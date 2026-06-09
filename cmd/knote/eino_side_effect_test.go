package main

import (
	"context"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestExecuteEinoToolOnceSurfacesAdapterFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		toolName   string
		resultJSON string
		want       string
	}{
		{
			name:       "build adapter error",
			toolName:   einotools.NameBuild,
			resultJSON: `{"adapter_error":"KAG build failed","manifest":{"version":1}}`,
			want:       "KAG build failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec := executeEinoToolOnce(map[string]einotool.InvokableTool{
				tc.toolName: staticTool{name: tc.toolName, out: tc.resultJSON},
			})
			events, err := exec(context.Background(), runtime.SideEffectRequest{
				SessionID:       "sess_eino",
				ToolName:        tc.toolName,
				ArgumentsInJSON: "{}",
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected adapter failure %q, got err=%v events=%+v", tc.want, err, events)
			}
			if !hasCmdEvent(events, protocol.EventToolError) || !hasCmdEvent(events, protocol.EventError) {
				t.Fatalf("adapter failure should emit tool.error and error: %+v", events)
			}
			if hasCmdEvent(events, protocol.EventToolComplete) || hasCmdEvent(events, protocol.EventBuildComplete) {
				t.Fatalf("adapter failure must not report completion: %+v", events)
			}
		})
	}
}

func TestExecuteEinoToolOncePreservesEvalReportWithAdapterErrors(t *testing.T) {
	exec := executeEinoToolOnce(map[string]einotool.InvokableTool{
		einotools.NameEval: staticTool{name: einotools.NameEval, out: `{"total":2,"adapter_errors":1,"report_markdown":"# Eval\n\npartial results"}`},
	})
	events, err := exec(context.Background(), runtime.SideEffectRequest{
		SessionID:       "sess_eino",
		ToolName:        einotools.NameEval,
		ArgumentsInJSON: "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCmdMessage(events, protocol.EventAssistantDone, "# Eval\n\npartial results") {
		t.Fatalf("eval report should be shown before adapter error: %+v", events)
	}
	if !hasCmdEvent(events, protocol.EventToolComplete) || !hasCmdEvent(events, protocol.EventError) {
		t.Fatalf("eval with adapter errors should complete and append error: %+v", events)
	}
}

func TestExecuteEinoToolOnceReportsSuccessfulBuildCompletion(t *testing.T) {
	exec := executeEinoToolOnce(map[string]einotool.InvokableTool{
		einotools.NameBuild: staticTool{name: einotools.NameBuild, out: `{"manifest":{"version":1}}`},
	})
	events, err := exec(context.Background(), runtime.SideEffectRequest{
		SessionID:       "sess_eino",
		ToolName:        einotools.NameBuild,
		ArgumentsInJSON: "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCmdEvent(events, protocol.EventToolComplete) || !hasCmdEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("successful build should report completion: %+v", events)
	}
}

func TestExecuteEinoToolOnceRendersVersionsMessage(t *testing.T) {
	exec := executeEinoToolOnce(map[string]einotool.InvokableTool{
		einotools.NameVersions: staticTool{name: einotools.NameVersions, out: `{"versions":[{"short_hash":"abc1234","relative_time":"now","subject":"initial","tags":["v0"],"current":true}]}`},
	})
	events, err := exec(context.Background(), runtime.SideEffectRequest{
		SessionID:       "sess_eino",
		ToolName:        einotools.NameVersions,
		ArgumentsInJSON: "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCmdMessageContaining(events, protocol.EventVersionChanged, "* abc1234  now  initial tags=v0") {
		t.Fatalf("versions event should include rendered entries: %+v", events)
	}
}

type staticTool struct {
	name string
	out  string
}

func (t staticTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name}, nil
}

func (t staticTool) InvokableRun(context.Context, string, ...einotool.Option) (string, error) {
	return t.out, nil
}

func hasCmdEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func hasCmdMessage(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			return true
		}
	}
	return false
}

func hasCmdMessageContaining(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && strings.Contains(event.Message, message) {
			return true
		}
	}
	return false
}
