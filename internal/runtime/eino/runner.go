package eino

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/adk"
	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

type Options struct {
	Tools           []einotool.InvokableTool
	Agent           adk.Agent
	Executor        QueryExecutor
	EnableStreaming bool
	CheckPointStore adk.CheckPointStore
}

type Runner struct {
	tools           []einotool.InvokableTool
	agent           adk.Agent
	executor        QueryExecutor
	enableStreaming bool
	checkPointStore adk.CheckPointStore
}

type QueryExecutor interface {
	Run(ctx context.Context, messages []*schema.Message) ([]*adk.AgentEvent, error)
}

var _ runtime.EinoRunner = (*Runner)(nil)

func NewRunner(opts Options) *Runner {
	return &Runner{
		tools:           append([]einotool.InvokableTool(nil), opts.Tools...),
		agent:           opts.Agent,
		executor:        opts.Executor,
		enableStreaming: opts.EnableStreaming,
		checkPointStore: opts.CheckPointStore,
	}
}

func (r *Runner) Ready(context.Context) error {
	if r.executor != nil || r.agent != nil {
		return nil
	}
	return fmt.Errorf("eino runner mode requires a configured ADK agent or executor")
}

func (r *Runner) ToolInventory(ctx context.Context) ([]runtime.RunnerToolInfo, error) {
	out := make([]runtime.RunnerToolInfo, 0, len(r.tools))
	for _, candidate := range r.tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(ctx)
		if err != nil {
			return nil, fmt.Errorf("load Eino tool info: %w", err)
		}
		out = append(out, runtime.RunnerToolInfo{
			Name:        info.Name,
			Description: info.Desc,
		})
	}
	return out, nil
}

func (r *Runner) Run(ctx context.Context, input runtime.EinoRunInput) ([]protocol.Event, error) {
	text := strings.TrimSpace(input.Message)
	if text == "" {
		return nil, nil
	}
	executor := r.executor
	if executor == nil {
		if r.agent == nil {
			return nil, fmt.Errorf("eino runner is not configured with an ADK agent")
		}
		executor = adkQueryExecutor{runner: r.NewADKRunner(ctx, r.agent)}
	}
	messages := transcriptMessages(input.History)
	messages = append(messages, schema.UserMessage(text))
	events := []protocol.Event{protocol.NewEvent(protocol.EventAssistantStart, input.SessionID, "eino runner started", nil)}
	agentEvents, err := executor.Run(ctx, messages)
	_, permissionedContext := protocol.AuthorizationContextFrom(ctx)
	if err != nil && permissionedContext {
		if errors.Is(err, runtime.ErrSideEffectPending) {
			return events, runtime.ErrSideEffectPending
		}
		return events, fmt.Errorf("%s", protectedContentUnavailableMessage)
	}
	binding, permissioned, bindingErr := protectedBindingFromAgentEvents(ctx, agentEvents)
	if bindingErr != nil {
		generic := fmt.Errorf("%s", protectedContentUnavailableMessage)
		events = append(events, protocol.NewEvent(protocol.EventError, input.SessionID, generic.Error(), nil))
		return events, generic
	}
	if permissionedContext && !permissioned {
		projectedEvents := make([]protocol.Event, 0, len(agentEvents))
		for _, event := range agentEvents {
			projectedEvents = append(projectedEvents, projectEvent(input.SessionID, event)...)
		}
		sanitizePermissionedErrors(projectedEvents)
		if hasAssistantOutput(projectedEvents) {
			generic := fmt.Errorf("%s", protectedContentUnavailableMessage)
			events = append(events, protocol.NewEvent(protocol.EventError, input.SessionID, generic.Error(), nil))
			return events, generic
		}
		events = append(events, projectedEvents...)
	} else {
		for _, event := range agentEvents {
			projected := projectEvent(input.SessionID, event)
			if permissioned {
				bindProjectedEvents(projected, binding)
			}
			events = append(events, projected...)
		}
	}
	if err != nil {
		if permissionedContext {
			return events, fmt.Errorf("%s", protectedContentUnavailableMessage)
		}
		return events, err
	}
	if len(events) == 1 {
		events = append(events, protocol.NewEvent(protocol.EventStatusUpdate, input.SessionID, "Eino runner completed without response.", nil))
	}
	return events, nil
}

func protectedBindingFromAgentEvents(
	ctx context.Context,
	events []*adk.AgentEvent,
) (*protocol.ProtectedContentBinding, bool, error) {
	authorization, authorized := protocol.AuthorizationContextFrom(ctx)
	var packages []protocol.EvidencePackage
	permissionedToolAttempted := false
	for _, event := range events {
		if authorized {
			attempted, err := permissionedAgentToolAttempt(event)
			if err != nil {
				return nil, true, err
			}
			permissionedToolAttempted = permissionedToolAttempted || attempted
		}
		toolName, content, ok, err := permissionedAgentToolOutput(event)
		if err != nil {
			return nil, true, err
		}
		if !ok {
			continue
		}
		if authorized && toolName == "" {
			return nil, true, errors.New("permissioned run received unnamed tool output")
		}
		if !permissionedToolName(toolName) {
			if authorized {
				return nil, false, fmt.Errorf("permissioned run received untrusted tool output %q", toolName)
			}
			continue
		}
		if !authorized {
			return nil, true, errors.New("permissioned tool output requires authorization")
		}
		evidencePackage, err := decodeEvidencePackage(content)
		if err != nil {
			return nil, true, err
		}
		packages = append(packages, evidencePackage)
	}
	if len(packages) == 0 {
		if permissionedToolAttempted {
			return nil, true, errors.New("permissioned tool call produced no protected output")
		}
		return nil, false, nil
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, packages...)
	if err != nil {
		return nil, true, err
	}
	return &binding, true, nil
}

func permissionedAgentToolAttempt(event *adk.AgentEvent) (bool, error) {
	if event == nil || event.Output == nil || event.Output.MessageOutput == nil || event.Output.MessageOutput.Role != schema.Assistant {
		return false, nil
	}
	message, _, err := adk.GetMessage(event)
	if err != nil {
		return false, err
	}
	if message == nil {
		return false, nil
	}
	attempted := false
	for _, call := range message.ToolCalls {
		toolName := strings.TrimSpace(call.Function.Name)
		if toolName == "" {
			return false, errors.New("permissioned run received unnamed tool call")
		}
		if !permissionedToolName(toolName) {
			return false, fmt.Errorf("permissioned run received untrusted tool call %q", toolName)
		}
		attempted = true
	}
	return attempted, nil
}

func permissionedAgentToolOutput(event *adk.AgentEvent) (string, string, bool, error) {
	if event == nil || event.Output == nil || event.Output.MessageOutput == nil || event.Output.MessageOutput.Role != schema.Tool {
		return "", "", false, nil
	}
	toolName := strings.TrimSpace(event.Output.MessageOutput.ToolName)
	if toolName != "" && !permissionedToolName(toolName) {
		return toolName, "", true, nil
	}
	message, _, err := adk.GetMessage(event)
	if err != nil {
		return "", "", false, err
	}
	if toolName == "" && message != nil {
		toolName = strings.TrimSpace(message.ToolName)
	}
	return toolName, messageContent(message), true, nil
}

func sanitizePermissionedErrors(events []protocol.Event) {
	for index := range events {
		if events[index].Type != protocol.EventError {
			continue
		}
		events[index].Message = protectedContentUnavailableMessage
		events[index].Payload = nil
	}
}

func hasAssistantOutput(events []protocol.Event) bool {
	for _, event := range events {
		if event.Type == protocol.EventAssistantDelta || event.Type == protocol.EventAssistantDone {
			return true
		}
	}
	return false
}

func bindProjectedEvents(events []protocol.Event, binding *protocol.ProtectedContentBinding) {
	if binding == nil {
		return
	}
	for index := range events {
		event := &events[index]
		sanitizePermissionedErrors(events[index : index+1])
		redactPermissionedToolEvent(event)
		if event.Type == protocol.EventAssistantDone ||
			event.Type == protocol.EventError ||
			event.Type == protocol.EventApprovalRequest ||
			event.Type == protocol.EventStatusUpdate ||
			((event.Type == protocol.EventToolComplete || event.Type == protocol.EventToolError) && permissionedToolName(eventToolName(event.Payload))) {
			copy := *binding
			event.ProtectedContent = &copy
		}
	}
}

func redactPermissionedToolEvent(event *protocol.Event) {
	if event == nil || (event.Type != protocol.EventToolComplete && event.Type != protocol.EventToolError) {
		return
	}
	toolName := eventToolName(event.Payload)
	if !permissionedToolName(toolName) {
		return
	}
	event.Payload = map[string]string{"tool": toolName}
	if event.Type == protocol.EventToolError {
		event.Message = protectedContentUnavailableMessage
		return
	}
	event.Message = toolName + " complete"
}

func (r *Runner) RunnerConfig(agent adk.Agent) adk.RunnerConfig {
	return adk.RunnerConfig{
		Agent:           agent,
		EnableStreaming: r.enableStreaming,
		CheckPointStore: r.checkPointStore,
	}
}

func (r *Runner) NewADKRunner(ctx context.Context, agent adk.Agent) *adk.Runner {
	return adk.NewRunner(ctx, r.RunnerConfig(agent))
}

type adkQueryExecutor struct {
	runner *adk.Runner
}

func (e adkQueryExecutor) Run(ctx context.Context, messages []*schema.Message) ([]*adk.AgentEvent, error) {
	if e.runner == nil {
		return nil, fmt.Errorf("eino ADK runner is not configured")
	}
	iter := e.runner.Run(ctx, messages)
	var events []*adk.AgentEvent
	for {
		event, ok := iter.Next()
		if !ok {
			break
		}
		if event == nil {
			continue
		}
		if event.Err != nil {
			return events, event.Err
		}
		events = append(events, event)
	}
	return events, nil
}

func projectEvent(sessionID string, event *adk.AgentEvent) []protocol.Event {
	if event == nil {
		return nil
	}
	if event.Err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, event.Err.Error(), nil)}
	}
	if event.Action != nil && event.Action.Interrupted != nil {
		return []protocol.Event{projectInterrupt(sessionID, event)}
	}
	if event.Output == nil || event.Output.MessageOutput == nil {
		return nil
	}
	output := event.Output.MessageOutput
	message, _, err := adk.GetMessage(event)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "read Eino message: "+err.Error(), nil)}
	}
	content := strings.TrimSpace(messageContent(message))
	switch output.Role {
	case schema.Tool:
		toolName := strings.TrimSpace(output.ToolName)
		if toolName == "" && message != nil {
			toolName = strings.TrimSpace(message.ToolName)
		}
		if toolName == "" {
			toolName = "eino_tool"
		}
		return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, sessionID, firstNonEmpty(content, toolName+" complete"), map[string]string{"tool": toolName})}
	case schema.Assistant:
		if content == "" {
			return nil
		}
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, content, map[string]string{"agent": event.AgentName})}
	default:
		if message != nil && message.Role == schema.Assistant && content != "" {
			return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, content, map[string]string{"agent": event.AgentName})}
		}
		if content != "" {
			return []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, sessionID, content, map[string]string{"agent": event.AgentName})}
		}
	}
	return nil
}

func projectInterrupt(sessionID string, event *adk.AgentEvent) protocol.Event {
	payload := map[string]any{
		"agent":     event.AgentName,
		"resumable": false,
	}
	var contexts []map[string]any
	for _, interruptContext := range event.Action.Interrupted.InterruptContexts {
		if interruptContext == nil {
			continue
		}
		contexts = append(contexts, map[string]any{
			"id":            interruptContext.ID,
			"info":          interruptContext.Info,
			"is_root_cause": interruptContext.IsRootCause,
			"address":       interruptContext.Address.String(),
		})
	}
	if len(contexts) > 0 {
		payload["contexts"] = contexts
	}
	message := "Eino runner interrupted; resume bridge is not enabled yet."
	for _, interruptContext := range contexts {
		if info := strings.TrimSpace(fmt.Sprint(interruptContext["info"])); info != "" {
			message = info
			break
		}
	}
	return protocol.NewEvent(protocol.EventApprovalRequest, sessionID, message, payload)
}

func transcriptMessages(history []protocol.Event) []*schema.Message {
	var messages []*schema.Message
	for _, event := range history {
		text := strings.TrimSpace(event.Message)
		if text == "" {
			continue
		}
		switch event.Type {
		case protocol.EventUserMessage:
			if strings.HasPrefix(text, "/") {
				continue
			}
			messages = append(messages, schema.UserMessage(text))
		case protocol.EventAssistantDone:
			if eventSource(event.Payload) == "slash" {
				continue
			}
			messages = append(messages, schema.AssistantMessage(text, nil))
		}
	}
	return messages
}

func eventSource(payload any) string {
	switch value := payload.(type) {
	case map[string]string:
		return strings.TrimSpace(value["source"])
	case map[string]any:
		source, _ := value["source"].(string)
		return strings.TrimSpace(source)
	default:
		return ""
	}
}

func messageContent(message *schema.Message) string {
	if message == nil {
		return ""
	}
	return message.Content
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
