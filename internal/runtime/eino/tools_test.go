package eino

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestSideEffectExecutorSurfacesBuildAdapterFailure(t *testing.T) {
	exec := NewSideEffectExecutor(map[string]einotool.InvokableTool{
		einotools.NameBuild: staticTool{name: einotools.NameBuild, out: `{"adapter_error":"KAG build failed","manifest":{"version":1}}`},
	})
	events, err := exec(context.Background(), runtime.SideEffectRequest{
		SessionID:       "sess_eino",
		ToolName:        einotools.NameBuild,
		ArgumentsInJSON: "{}",
	})
	if err == nil || !strings.Contains(err.Error(), "KAG build failed") {
		t.Fatalf("expected adapter failure, got err=%v events=%+v", err, events)
	}
	if !hasToolEvent(events, protocol.EventToolError) || !hasToolEvent(events, protocol.EventError) {
		t.Fatalf("adapter failure should emit tool.error and error: %+v", events)
	}
	if hasToolEvent(events, protocol.EventToolComplete) || hasToolEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("adapter failure must not report completion: %+v", events)
	}
}

func TestSideEffectExecutorPreservesEvalReportWithAdapterErrors(t *testing.T) {
	exec := NewSideEffectExecutor(map[string]einotool.InvokableTool{
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
	if !hasToolMessage(events, protocol.EventAssistantDone, "# Eval\n\npartial results") {
		t.Fatalf("eval report should be shown before adapter error: %+v", events)
	}
	if !hasToolEvent(events, protocol.EventToolComplete) || !hasToolEvent(events, protocol.EventError) {
		t.Fatalf("eval with adapter errors should complete and append error: %+v", events)
	}
}

func TestToolExecutorReportsSuccessfulBuildCompletion(t *testing.T) {
	executor := NewToolExecutor([]einotool.InvokableTool{
		staticTool{name: einotools.NameBuild, out: `{"manifest":{"version":1},"bundle_manifest":{"version":2,"projection_version":"prj_test","namespace":"ns","authz_object":"kb:test","authz_version":"acl-v1"}}`},
	})
	events, err := executor.Invoke(context.Background(), "sess_eino", einotools.NameBuild, "{}")
	if err != nil {
		t.Fatal(err)
	}
	if !hasToolEvent(events, protocol.EventToolComplete) || !hasToolEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("successful build should report completion: %+v", events)
	}
	for _, event := range events {
		if event.Type != protocol.EventBuildComplete {
			continue
		}
		data, ok := event.Payload.(map[string]any)
		if !ok || data["version"] != float64(1) || data["projection_version"] != "prj_test" || data["namespace"] != "ns" {
			t.Fatalf("build.complete did not preserve v1 fields and add projection metadata: %+v", event.Payload)
		}
	}
}

func TestToolExecutorRendersVersionsMessage(t *testing.T) {
	executor := NewToolExecutor([]einotool.InvokableTool{
		staticTool{name: einotools.NameVersions, out: `{"versions":[{"short_hash":"abc1234","relative_time":"now","subject":"initial","tags":["v0"],"current":true}]}`},
	})
	events, err := executor.Invoke(context.Background(), "sess_eino", einotools.NameVersions, "{}")
	if err != nil {
		t.Fatal(err)
	}
	if !hasToolMessageContaining(events, protocol.EventVersionChanged, "* abc1234  now  initial tags=v0") {
		t.Fatalf("versions event should include rendered entries: %+v", events)
	}
}

func TestToolExecutorRendersEmptyVersionsMessage(t *testing.T) {
	executor := NewToolExecutor([]einotool.InvokableTool{
		staticTool{name: einotools.NameVersions, out: `{"versions":[]}`},
	})
	events, err := executor.Invoke(context.Background(), "sess_eino", einotools.NameVersions, "{}")
	if err != nil {
		t.Fatal(err)
	}
	if !hasToolMessageContaining(events, protocol.EventVersionChanged, "No versions yet.") {
		t.Fatalf("empty versions should render a friendly message: %+v", events)
	}
}

func TestToolExecutorBindsPermissionedEvidenceAndAnswerToOneBlock(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/allowed.md", "AUTHORIZED_CONTENT_CANARY")
	executor := NewToolExecutor([]einotool.InvokableTool{
		staticTool{name: einotools.NameQuery, out: testPermissionedToolOutput(t, evidencePackage, "AUTHORIZED_ANSWER_CANARY")},
	})
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	events, err := executor.Invoke(ctx, authorization.SessionID, einotools.NameQuery, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	var blockID string
	bound := 0
	for _, event := range events {
		if event.Type != protocol.EventToolStart && event.Type != protocol.EventToolComplete && event.Type != protocol.EventAssistantDone {
			continue
		}
		if event.ProtectedContent == nil {
			t.Fatalf("permissioned event has no protected binding: %+v", event)
		}
		if blockID == "" {
			blockID = event.ProtectedContent.BlockID
		} else if event.ProtectedContent.BlockID != blockID {
			t.Fatalf("permissioned events used different blocks: %+v", events)
		}
		bound++
	}
	if bound != 3 || len(events[1].ProtectedContent.Resources) != 1 {
		t.Fatalf("permissioned bound events = %d in %+v", bound, events)
	}
}

func TestToolExecutorFailsPermissionedCallsClosedWithoutLeakingBackendDetails(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		tool staticTool
	}{
		{name: "missing evidence", tool: staticTool{name: einotools.NameQuery, out: `{"answer":"MALFORMED_OUTPUT_CANARY"}`}},
		{name: "backend error", tool: staticTool{name: einotools.NameExplain, err: errors.New("BACKEND_ERROR_CANARY")}},
		{
			name: "adapter error with evidence",
			tool: staticTool{
				name: einotools.NameQuery,
				out:  testPermissionedToolFailureOutput(t, testEinoEvidencePackage(t, authorization, "sources/adapter-error.md", "ADAPTER_CONTENT_CANARY"), "ADAPTER_ERROR_CANARY"),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := NewToolExecutor([]einotool.InvokableTool{test.tool})
			events, err := executor.Invoke(ctx, authorization.SessionID, test.tool.name, `{}`)
			if err == nil || err.Error() != protectedContentUnavailableMessage {
				t.Fatalf("permissioned tool error = %v, events=%+v", err, events)
			}
			if strings.Contains(fmt.Sprint(events), "CANARY") {
				t.Fatalf("permissioned tool error leaked backend details: %+v", events)
			}
			if !hasToolMessage(events, protocol.EventToolError, protectedContentUnavailableMessage) {
				t.Fatalf("permissioned tool error was not generic: %+v", events)
			}
		})
	}
}

func TestToolExecutorRejectsPermissionedOutputWithoutAuthorizationContext(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/no-context.md", "NO_CONTEXT_CONTENT_CANARY")
	executor := NewToolExecutor([]einotool.InvokableTool{
		staticTool{name: einotools.NameQuery, out: testPermissionedToolOutput(t, evidencePackage, "NO_CONTEXT_ANSWER_CANARY")},
	})
	events, err := executor.Invoke(context.Background(), authorization.SessionID, einotools.NameQuery, `{}`)
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("missing authorization error = %v, events=%+v", err, events)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "CANARY") {
			t.Fatalf("missing authorization leaked permissioned output: %+v", events)
		}
	}
}

type staticTool struct {
	name string
	out  string
	err  error
}

func (t staticTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name}, nil
}

func (t staticTool) InvokableRun(context.Context, string, ...einotool.Option) (string, error) {
	return t.out, t.err
}

func hasToolEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func hasToolMessage(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			return true
		}
	}
	return false
}

func hasToolMessageContaining(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && strings.Contains(event.Message, message) {
			return true
		}
	}
	return false
}
