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
	tool, ok := tools[toolName]
	if !ok || tool == nil {
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
		events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, err.Error(), map[string]string{"tool": toolName}))
		return events, err
	}
	decoded := decodeToolResult(out)
	payload := map[string]any{"tool": toolName, "result": decoded}
	if failure := adapterFailureMessage(toolName, decoded); failure != "" {
		events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, failure, payload))
		events = append(events, protocol.NewEvent(protocol.EventError, sessionID, failure, payload))
		return events, fmt.Errorf("%s", failure)
	}
	events = append(events, protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", payload))
	events = append(events, versionEventsForTool(sessionID, toolName, decoded)...)
	if toolName == einotools.NameBuild {
		if manifest, ok := decodedMap(decoded)["manifest"]; ok {
			events = append(events, protocol.NewEvent(protocol.EventBuildComplete, sessionID, "Build complete", manifest))
		}
	}
	if toolName == einotools.NameEval {
		return events, nil
	}
	events = append(events, protocol.NewEvent(protocol.EventAssistantDone, sessionID, "Eino tool result\n"+prettyToolResult(decoded), map[string]string{"tool": toolName}))
	return events, nil
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
