package eino

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

const (
	protectedContentUnavailableMessage   = "protected content is unavailable"
	permissionedSideEffectFailureMessage = "side effect failed"
)

type ToolExecutor struct {
	tools map[string]einotool.InvokableTool
}

func NewToolExecutor(tools []einotool.InvokableTool) ToolExecutor {
	out := map[string]einotool.InvokableTool{}
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(context.Background())
		if err != nil || info == nil {
			continue
		}
		out[info.Name] = candidate
	}
	return ToolExecutor{tools: out}
}

func NewSideEffectExecutor(approvedTools map[string]einotool.InvokableTool) runtime.SideEffectExecutor {
	return func(ctx context.Context, req runtime.SideEffectRequest) ([]protocol.Event, error) {
		return invokeTool(ctx, approvedTools, req.SessionID, req.ToolName, req.ArgumentsInJSON)
	}
}

func (e ToolExecutor) Invoke(ctx context.Context, sessionID string, toolName string, argumentsInJSON string) ([]protocol.Event, error) {
	return invokeTool(ctx, e.tools, sessionID, toolName, argumentsInJSON)
}

func invokeTool(ctx context.Context, tools map[string]einotool.InvokableTool, sessionID string, toolName string, argumentsInJSON string) ([]protocol.Event, error) {
	sessionID = strings.TrimSpace(sessionID)
	toolName = strings.TrimSpace(toolName)
	_, authorized := protocol.AuthorizationContextFrom(ctx)
	permissionedSideEffect := authorized && sideEffectToolName(toolName)
	tool, ok := tools[toolName]
	if !ok || tool == nil {
		if permissionedSideEffect {
			return permissionedSideEffectFailure(sessionID, toolName, nil)
		}
		err := fmt.Errorf("Eino tool %q is not registered", toolName)
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, err.Error(), map[string]string{"tool": toolName})}, err
	}
	args := strings.TrimSpace(argumentsInJSON)
	if args == "" {
		args = "{}"
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventToolStart, sessionID, toolName, map[string]string{"tool": toolName})}
	out, err := tool.InvokableRun(ctx, args)
	if errors.Is(err, runtime.ErrSideEffectPending) {
		return nil, err
	}
	if err != nil {
		if permissionedSideEffect {
			return permissionedSideEffectFailure(sessionID, toolName, events)
		}
		if isPermissionedToolCall(toolName) {
			generic := errors.New(protectedContentUnavailableMessage)
			events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, generic.Error(), map[string]string{"tool": toolName}))
			return events, generic
		}
		events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, err.Error(), map[string]string{"tool": toolName}))
		return events, err
	}
	binding, permissioned, err := protectedBindingFromToolOutput(ctx, toolName, out)
	if err != nil {
		generic := errors.New(protectedContentUnavailableMessage)
		events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, generic.Error(), map[string]string{"tool": toolName}))
		return events, generic
	}
	if permissioned {
		events[0].ProtectedContent = binding
	}
	decoded := decodeToolResult(out)
	payload := map[string]any{"tool": toolName, "result": decoded}
	if failure := adapterFailureMessage(toolName, decoded); failure != "" {
		if permissionedSideEffect {
			return permissionedSideEffectFailure(sessionID, toolName, events)
		}
		if permissioned {
			generic := errors.New(protectedContentUnavailableMessage)
			errorPayload := map[string]string{"tool": toolName}
			toolError := protocol.NewEvent(protocol.EventToolError, sessionID, generic.Error(), errorPayload)
			toolError.ProtectedContent = binding
			genericError := protocol.NewEvent(protocol.EventError, sessionID, generic.Error(), errorPayload)
			genericError.ProtectedContent = binding
			events = append(events, toolError, genericError)
			return events, generic
		}
		events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, failure, payload))
		events = append(events, protocol.NewEvent(protocol.EventError, sessionID, failure, payload))
		return events, fmt.Errorf("%s", failure)
	}
	if permissionedSideEffect {
		events = append(events, permissionedSideEffectSuccess(sessionID, toolName)...)
		return events, nil
	}
	complete := protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", payload)
	if permissioned {
		complete.ProtectedContent = binding
	}
	events = append(events, complete)
	events = append(events, versionEventsForTool(sessionID, toolName, decoded)...)
	if toolName == einotools.NameBuild {
		if manifest, ok := decodedMap(decoded)["manifest"]; ok {
			buildPayload := make(map[string]any)
			for key, value := range decodedMap(manifest) {
				buildPayload[key] = value
			}
			if bundle, exists := decodedMap(decoded)["bundle_manifest"]; exists {
				buildPayload["bundle_manifest"] = bundle
				if bundleMap := decodedMap(bundle); len(bundleMap) != 0 {
					buildPayload["projection_version"] = bundleMap["projection_version"]
					buildPayload["namespace"] = bundleMap["namespace"]
					buildPayload["authz_object"] = bundleMap["authz_object"]
					buildPayload["authz_version"] = bundleMap["authz_version"]
				}
			}
			events = append(events, protocol.NewEvent(protocol.EventBuildComplete, sessionID, "Build complete", buildPayload))
		}
	}
	if toolName == einotools.NameEval {
		return events, nil
	}
	answer := protocol.NewEvent(protocol.EventAssistantDone, sessionID, "Eino tool result\n"+prettyToolResult(decoded), map[string]string{"tool": toolName})
	if permissioned {
		answer.ProtectedContent = binding
	}
	events = append(events, answer)
	return events, nil
}

func protectedBindingFromToolOutput(
	ctx context.Context,
	toolName string,
	out string,
) (*protocol.ProtectedContentBinding, bool, error) {
	if !permissionedToolName(toolName) {
		return nil, false, nil
	}
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok {
		return nil, true, errors.New("permissioned tool output requires authorization")
	}
	evidencePackage, err := decodeEvidencePackage(out)
	if err != nil {
		return nil, true, err
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, evidencePackage)
	if err != nil {
		return nil, true, err
	}
	return &binding, true, nil
}

func decodeEvidencePackage(out string) (protocol.EvidencePackage, error) {
	var envelope struct {
		EvidencePackage json.RawMessage `json:"evidence_package"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &envelope); err != nil {
		return protocol.EvidencePackage{}, err
	}
	if len(envelope.EvidencePackage) == 0 || string(envelope.EvidencePackage) == "null" {
		return protocol.EvidencePackage{}, errors.New("permissioned tool result has no evidence package")
	}
	var evidencePackage protocol.EvidencePackage
	if err := json.Unmarshal(envelope.EvidencePackage, &evidencePackage); err != nil {
		return protocol.EvidencePackage{}, err
	}
	return evidencePackage, nil
}

func isPermissionedToolCall(toolName string) bool {
	return permissionedToolName(toolName)
}

func permissionedToolName(toolName string) bool {
	return toolName == einotools.NameQuery || toolName == einotools.NameExplain
}

func sideEffectToolName(toolName string) bool {
	switch toolName {
	case einotools.NameBuild, einotools.NameEval, einotools.NameCommit,
		einotools.NameRelease, einotools.NameCheckout:
		return true
	default:
		return false
	}
}

func permissionedSideEffectFailure(sessionID string, toolName string, events []protocol.Event) ([]protocol.Event, error) {
	payload := map[string]string{"tool": toolName}
	if len(events) == 0 {
		events = append(events, protocol.NewEvent(protocol.EventToolStart, sessionID, toolName, payload))
	}
	events = append(events,
		protocol.NewEvent(protocol.EventToolError, sessionID, permissionedSideEffectFailureMessage, payload),
		protocol.NewEvent(protocol.EventError, sessionID, permissionedSideEffectFailureMessage, payload),
	)
	return events, errors.New(permissionedSideEffectFailureMessage)
}

func permissionedSideEffectSuccess(sessionID string, toolName string) []protocol.Event {
	payload := map[string]string{"tool": toolName}
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventToolComplete, sessionID, "side effect complete", payload),
	}
	switch toolName {
	case einotools.NameBuild:
		events = append(events, protocol.NewEvent(protocol.EventBuildComplete, sessionID, "Build complete", payload))
	case einotools.NameCommit:
		events = append(events, protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Commit complete", payload))
	case einotools.NameRelease:
		events = append(events, protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Release complete", payload))
	case einotools.NameCheckout:
		events = append(events, protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Checkout complete", payload))
	}
	return events
}

func eventToolName(payload any) string {
	switch value := payload.(type) {
	case map[string]string:
		return strings.TrimSpace(value["tool"])
	case map[string]any:
		name, _ := value["tool"].(string)
		return strings.TrimSpace(name)
	default:
		return ""
	}
}

func decodeToolResult(out string) any {
	text := strings.TrimSpace(out)
	if text == "" {
		return map[string]any{}
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return text
	}
	return decoded
}

func prettyToolResult(decoded any) string {
	data, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return strings.TrimSpace(fmt.Sprint(decoded))
	}
	return string(data)
}

func decodedMap(decoded any) map[string]any {
	value, _ := decoded.(map[string]any)
	return value
}

func adapterFailureMessage(toolName string, decoded any) string {
	fields := decodedMap(decoded)
	if len(fields) == 0 {
		return ""
	}
	if message := strings.TrimSpace(stringField(fields, "adapter_error")); message != "" {
		return message
	}
	if toolName == einotools.NameEval {
		return ""
	}
	if count := intField(fields, "adapter_errors"); count > 0 {
		return fmt.Sprintf("%s completed with %d adapter error(s)", toolName, count)
	}
	return ""
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func intField(fields map[string]any, key string) int {
	switch value := fields[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func versionEventsForTool(sessionID string, toolName string, decoded any) []protocol.Event {
	switch toolName {
	case einotools.NameDiff:
		if diff, ok := decodedMap(decoded)["diff"].(string); ok {
			if strings.TrimSpace(diff) == "" {
				diff = "No diff."
			}
			return []protocol.Event{protocol.NewEvent(protocol.EventVersionDiff, sessionID, diff, decoded)}
		}
	case einotools.NameVersions:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, formatVersions(decoded), decoded)}
	case einotools.NameEval:
		events := []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, formatEvalReport(decoded), decoded)}
		if count := intField(decodedMap(decoded), "adapter_errors"); count > 0 {
			events = append(events, protocol.NewEvent(protocol.EventError, sessionID, fmt.Sprintf("eval completed with %d adapter error(s)", count), decoded))
		}
		return events
	case einotools.NameCommit:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Commit complete", decoded)}
	case einotools.NameRelease:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Release tag created", decoded)}
	case einotools.NameCheckout:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Checkout complete", decoded)}
	default:
		return nil
	}
	return nil
}

func formatVersions(decoded any) string {
	fields := decodedMap(decoded)
	items, _ := fields["versions"].([]any)
	if len(items) == 0 {
		return "No versions yet."
	}
	var b strings.Builder
	b.WriteString("Versions\n")
	for _, item := range items {
		version, _ := item.(map[string]any)
		if len(version) == 0 {
			continue
		}
		marker := " "
		if boolField(version, "current") {
			marker = "*"
		}
		tagText := ""
		if tags := stringSliceField(version, "tags"); len(tags) > 0 {
			tagText = " tags=" + strings.Join(tags, ",")
		}
		fmt.Fprintf(&b, "%s %s  %s  %s%s\n",
			marker,
			firstNonEmpty(stringField(version, "short_hash"), stringField(version, "hash")),
			stringField(version, "relative_time"),
			stringField(version, "subject"),
			tagText,
		)
	}
	text := strings.TrimSpace(b.String())
	if text == "Versions" || text == "" {
		return "No versions yet."
	}
	return text
}

func formatEvalReport(decoded any) string {
	fields := decodedMap(decoded)
	if report := strings.TrimSpace(stringField(fields, "report_markdown")); report != "" {
		return report
	}
	data, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return strings.TrimSpace(fmt.Sprint(decoded))
	}
	return string(data)
}

func boolField(fields map[string]any, key string) bool {
	value, _ := fields[key].(bool)
	return value
}

func stringSliceField(fields map[string]any, key string) []string {
	values, _ := fields[key].([]any)
	out := make([]string, 0, len(values))
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" {
			out = append(out, text)
		}
	}
	return out
}
