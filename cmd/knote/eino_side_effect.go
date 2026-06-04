package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

func newEinoSideEffectGate(bridge *runtime.SideEffectBridge, approvedTools map[string]einotool.InvokableTool) einotools.SideEffectGate {
	execute := executeEinoToolOnce(approvedTools)
	return func(ctx context.Context, req einotools.SideEffectRequest) error {
		if bridge == nil {
			return fmt.Errorf("%s requires runtime confirmation; Eino side-effect bridge is not configured", req.ToolName)
		}
		return bridge.Request(ctx, runtime.SideEffectRequest{
			ToolName:        req.ToolName,
			Action:          req.Action,
			ArgumentsInJSON: req.ArgumentsInJSON,
			Summary:         req.Summary,
			Execute:         execute,
		})
	}
}

func executeEinoToolOnce(approvedTools map[string]einotool.InvokableTool) runtime.SideEffectExecutor {
	return func(ctx context.Context, req runtime.SideEffectRequest) ([]protocol.Event, error) {
		sessionID := strings.TrimSpace(req.SessionID)
		toolName := strings.TrimSpace(req.ToolName)
		tool, ok := approvedTools[toolName]
		if !ok || tool == nil {
			err := fmt.Errorf("approved Eino tool %q is not registered", toolName)
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, err.Error(), map[string]string{"tool": toolName})}, err
		}
		args := strings.TrimSpace(req.ArgumentsInJSON)
		if args == "" {
			args = "{}"
		}
		events := []protocol.Event{protocol.NewEvent(protocol.EventToolStart, sessionID, toolName, map[string]string{"tool": toolName})}
		out, err := tool.InvokableRun(ctx, args)
		if err != nil {
			events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, err.Error(), map[string]string{"tool": toolName}))
			return events, err
		}
		decoded := decodeEinoToolResult(out)
		payload := map[string]any{"tool": toolName, "result": decoded}
		if failure := adapterFailureMessage(toolName, decoded); failure != "" {
			events = append(events, protocol.NewEvent(protocol.EventToolError, sessionID, failure, payload))
			events = append(events, protocol.NewEvent(protocol.EventError, sessionID, failure, payload))
			return events, fmt.Errorf("%s", failure)
		}
		events = append(events, protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", payload))
		events = append(events, versionEventsForEinoTool(sessionID, toolName, decoded)...)
		if toolName == einotools.NameBuild {
			if manifest, ok := decodedMap(decoded)["manifest"]; ok {
				events = append(events, protocol.NewEvent(protocol.EventBuildComplete, sessionID, "Build complete", manifest))
			}
		}
		events = append(events, protocol.NewEvent(protocol.EventAssistantDone, sessionID, "Eino tool result\n"+prettyEinoToolResult(decoded), map[string]string{"tool": toolName}))
		return events, nil
	}
}

func decodeEinoToolResult(out string) any {
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

func prettyEinoToolResult(decoded any) string {
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

func versionEventsForEinoTool(sessionID string, toolName string, decoded any) []protocol.Event {
	switch toolName {
	case einotools.NameCommit:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Commit complete", decoded)}
	case einotools.NameRelease:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Release tag created", decoded)}
	case einotools.NameCheckout:
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, sessionID, "Checkout complete", decoded)}
	default:
		return nil
	}
}
