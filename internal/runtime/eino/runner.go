package eino

import (
	"context"
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
	agentEvents, err := executor.Run(ctx, messages)
	if err != nil {
		return nil, err
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventAssistantStart, input.SessionID, "eino runner started", nil)}
	for _, event := range agentEvents {
		events = append(events, projectEvent(input.SessionID, event)...)
	}
	if len(events) == 1 {
		events = append(events, protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, "Eino runner completed without response.", nil))
	}
	return events, nil
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
			messages = append(messages, schema.UserMessage(text))
		case protocol.EventAssistantDone:
			messages = append(messages, schema.AssistantMessage(text, nil))
		}
	}
	return messages
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
