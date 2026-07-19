package eino

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
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
		testAuthorizedStaticTool(t, authorization, staticTool{
			name: einotools.NameQuery,
			out:  testPermissionedToolOutput(t, evidencePackage, "AUTHORIZED_ANSWER_CANARY"),
		}, evidencePackage),
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
	encodedEvents, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedEvents), `"tool_authorization"`) {
		t.Fatalf("permissioned events leaked the full tool authorization envelope: %s", encodedEvents)
	}
}

func TestToolExecutorFailsPermissionedCallsClosedWithoutLeakingBackendDetails(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/authorization.md", "AUTHORIZATION_CONTENT_CANARY")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		tool     einotool.InvokableTool
		toolName string
	}{
		{
			name:     "missing evidence",
			toolName: einotools.NameQuery,
			tool: testAuthorizedStaticTool(t, authorization, staticTool{
				name: einotools.NameQuery, out: `{"answer":"MALFORMED_OUTPUT_CANARY"}`,
			}, evidencePackage),
		},
		{
			name:     "backend error",
			toolName: einotools.NameExplain,
			tool: authorizedStaticTool{
				staticTool:     staticTool{name: einotools.NameExplain, err: errors.New("BACKEND_ERROR_CANARY")},
				manifestDigest: testToolManifestDigest,
			},
		},
		{
			name:     "adapter error with evidence",
			toolName: einotools.NameQuery,
			tool: testAuthorizedStaticTool(t, authorization, staticTool{
				name: einotools.NameQuery,
				out:  testPermissionedToolFailureOutput(t, testEinoEvidencePackage(t, authorization, "sources/adapter-error.md", "ADAPTER_CONTENT_CANARY"), "ADAPTER_ERROR_CANARY"),
			}, testEinoEvidencePackage(t, authorization, "sources/adapter-error.md", "ADAPTER_CONTENT_CANARY")),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := NewToolExecutor([]einotool.InvokableTool{test.tool})
			events, err := executor.Invoke(ctx, authorization.SessionID, test.toolName, `{}`)
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

func TestToolExecutorRejectsUnwrappedAndUnknownToolsBeforeInvocation(t *testing.T) {
	authorization := testEinoAuthorization("sess_tool_registration")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	executor := NewToolExecutor([]einotool.InvokableTool{
		staticTool{
			name: einotools.NameQuery,
			out:  `{"answer":"UNWRAPPED_RESULT_CANARY"}`,
			runs: &runs,
		},
	})

	for _, toolName := range []string{einotools.NameQuery, "knote_unknown"} {
		events, err := executor.Invoke(ctx, authorization.SessionID, toolName, `{}`)
		if err == nil || err.Error() != protectedContentUnavailableMessage {
			t.Fatalf("%s authorization error = %v, events=%+v", toolName, err, events)
		}
		if strings.Contains(fmt.Sprint(events), "CANARY") {
			t.Fatalf("%s leaked unwrapped tool output: %+v", toolName, events)
		}
	}
	if runs != 0 {
		t.Fatalf("unwrapped protected tool ran %d times", runs)
	}
}

func TestToolExecutorSuppressesStaleAuthorizationEnvelope(t *testing.T) {
	stale := testEinoAuthorization("sess_stale_tool_authorization")
	evidencePackage := testEinoEvidencePackage(t, stale, "sources/stale.md", "STALE_CONTENT_CANARY")
	tool := testAuthorizedStaticTool(t, stale, staticTool{
		name: einotools.NameQuery,
		out:  testPermissionedToolOutput(t, evidencePackage, "STALE_ANSWER_CANARY"),
	}, evidencePackage)
	current := stale
	current.RequestID = "request-2"
	ctx, err := protocol.WithAuthorizationContext(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}

	events, err := NewToolExecutor([]einotool.InvokableTool{tool}).Invoke(
		ctx, current.SessionID, einotools.NameQuery, `{}`,
	)
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("stale authorization error = %v, events=%+v", err, events)
	}
	if strings.Contains(fmt.Sprint(events), "CANARY") {
		t.Fatalf("stale authorization leaked protected output: %+v", events)
	}
}

func TestPermissionedSideEffectOutputsHaveFixedShapes(t *testing.T) {
	authorization := testEinoAuthorization("sess_side_effect_shapes")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	const resultCanary = "MANIFEST_BUNDLE_COUNT_PATH_HASH_NAMESPACE_AUTHZ_KAG_CANARY"
	successes := []struct {
		tool      string
		output    string
		eventType protocol.EventType
	}{
		{
			tool: einotools.NameBuild,
			output: `{"manifest":{"path":"` + resultCanary + `","document_count":97},` +
				`"bundle_manifest":{"hash":"` + resultCanary + `","namespace":"` + resultCanary + `","authz_object":"` + resultCanary + `","authz_version":"` + resultCanary + `"},` +
				`"kag_data":{"mode":"` + resultCanary + `"}}`,
			eventType: protocol.EventBuildComplete,
		},
		{tool: einotools.NameCommit, output: `{"hash":"` + resultCanary + `","path":"` + resultCanary + `"}`, eventType: protocol.EventVersionChanged},
		{tool: einotools.NameRelease, output: `{"tag":"` + resultCanary + `"}`, eventType: protocol.EventVersionChanged},
		{tool: einotools.NameCheckout, output: `{"ref":"` + resultCanary + `","allow_dirty":true}`, eventType: protocol.EventVersionChanged},
	}
	for _, test := range successes {
		t.Run(test.tool, func(t *testing.T) {
			executor := NewToolExecutor([]einotool.InvokableTool{testAuthorizedStaticTool(t, authorization, staticTool{name: test.tool, out: test.output})})
			events, err := executor.Invoke(ctx, authorization.SessionID, test.tool, `{}`)
			if err != nil {
				t.Fatal(err)
			}
			assertFixedPermissionedSideEffectEvents(t, events, test.tool, []protocol.EventType{
				protocol.EventToolStart, protocol.EventToolComplete, test.eventType,
			})
			if strings.Contains(fmt.Sprint(events), resultCanary) {
				t.Fatalf("permissioned side-effect success leaked backend result: %+v", events)
			}
		})
	}

	for _, test := range []struct {
		name string
		tool staticTool
	}{
		{name: "backend error", tool: staticTool{name: einotools.NameBuild, err: errors.New("BACKEND_PATH_HASH_CANARY")}},
		{name: "adapter error", tool: staticTool{name: einotools.NameBuild, out: `{"adapter_error":"ADAPTER_KAG_CANARY","manifest":{"path":"PRIVATE_PATH_CANARY"}}`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tool := testAuthorizedStaticTool(t, authorization, test.tool)
			executor := NewToolExecutor([]einotool.InvokableTool{tool})
			events, err := executor.Invoke(ctx, authorization.SessionID, test.tool.name, `{}`)
			if err == nil || err.Error() != permissionedSideEffectFailureMessage {
				t.Fatalf("permissioned side-effect failure = %v, events=%+v", err, events)
			}
			assertFixedPermissionedSideEffectEvents(t, events, test.tool.name, []protocol.EventType{
				protocol.EventToolStart, protocol.EventToolError, protocol.EventError,
			})
			if strings.Contains(fmt.Sprint(events), "CANARY") {
				t.Fatalf("permissioned side-effect failure leaked backend result: %+v", events)
			}
		})
	}
}

func TestPermissionedSlashBuildConfirmationKeepsSideEffectResultsFixed(t *testing.T) {
	for _, test := range []struct {
		name      string
		tool      staticTool
		wantError bool
	}{
		{
			name: "success",
			tool: staticTool{name: einotools.NameBuild, out: `{
				"manifest":{"path":"SUCCESS_PRIVATE_PATH_CANARY","count":97},
				"bundle_manifest":{"hash":"SUCCESS_HASH_CANARY","namespace":"SUCCESS_NAMESPACE_CANARY","authz_object":"SUCCESS_AUTHZ_CANARY"},
				"kag_data":{"mode":"SUCCESS_KAG_CANARY"}
			}`},
		},
		{
			name:      "failure",
			tool:      staticTool{name: einotools.NameBuild, err: errors.New("FAILURE_ADAPTER_PATH_HASH_KAG_CANARY")},
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			store := local.New(workspace)
			bridge := runtime.NewSideEffectBridge()
			tool := testAuthorizedStaticTool(t, testEinoAuthorization("sess_permissioned_slash_build"), test.tool)
			executor := NewToolExecutor([]einotool.InvokableTool{tool})
			providerCalls := 0
			manager := runtime.New(runtime.Dependencies{
				Workspace:    workspace,
				Capabilities: runtime.PermissionedSessionCapabilityProfile(),
				Sessions:     store,
				EinoRunner:   NewRunner(Options{Executor: &fakeExecutor{}}),
				SideEffects:  bridge,
				ToolExecutor: gatedToolExecutor{bridge: bridge, executor: executor},
				AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
					providerCalls++
					return testEinoAuthorization(sessionID), nil
				},
				NewSessionID: func() string { return "sess_permissioned_slash_build" },
			})
			if _, err := manager.Start(context.Background(), runtime.StartOptions{}); err != nil {
				t.Fatal(err)
			}
			pending := manager.SendMessage(context.Background(), "/build")
			confirm := firstToolConfirm(t, pending)
			for _, event := range pending {
				if event.Type == protocol.EventToolComplete || event.Type == protocol.EventBuildComplete {
					t.Fatalf("permissioned /build executed before confirmation: %+v", pending)
				}
			}
			events := manager.Confirm(context.Background(), confirm, true)
			if providerCalls < 2 {
				t.Fatalf("permissioned /build authorization provider calls = %d, want send and confirm revalidation", providerCalls)
			}
			if strings.Contains(fmt.Sprint(events), "CANARY") {
				t.Fatalf("permissioned /build leaked backend details after confirmation: %+v", events)
			}
			if !hasToolEvent(events, protocol.EventToolComplete) && !test.wantError {
				t.Fatalf("permissioned /build success omitted fixed completion: %+v", events)
			}
			if got := hasToolEvent(events, protocol.EventError); got != test.wantError {
				t.Fatalf("permissioned /build error=%t, want %t: %+v", got, test.wantError, events)
			}
		})
	}
}

type gatedToolExecutor struct {
	bridge   *runtime.SideEffectBridge
	executor ToolExecutor
}

func (e gatedToolExecutor) Invoke(ctx context.Context, sessionID string, toolName string, argumentsInJSON string) ([]protocol.Event, error) {
	err := e.bridge.Request(ctx, runtime.SideEffectRequest{
		SessionID:       sessionID,
		ToolName:        toolName,
		Action:          "build",
		ArgumentsInJSON: argumentsInJSON,
		Summary:         "Build knowledge artifacts.",
		Execute: func(execCtx context.Context, _ runtime.SideEffectRequest) ([]protocol.Event, error) {
			return e.executor.Invoke(execCtx, sessionID, toolName, argumentsInJSON)
		},
	})
	return nil, err
}

func assertFixedPermissionedSideEffectEvents(t *testing.T, events []protocol.Event, toolName string, eventTypes []protocol.EventType) {
	t.Helper()
	if len(events) != len(eventTypes) {
		t.Fatalf("permissioned side-effect event count = %d, want %d: %+v", len(events), len(eventTypes), events)
	}
	wantReferences := len(eventTypes) > 0 && eventTypes[len(eventTypes)-1] != protocol.EventError
	for index, eventType := range eventTypes {
		event := events[index]
		if event.Type != eventType {
			t.Fatalf("permissioned side-effect event[%d] = %s, want %s: %+v", index, event.Type, eventType, events)
		}
		payload, ok := event.Payload.(map[string]string)
		if !ok || payload["tool"] != toolName {
			t.Fatalf("permissioned side-effect payload[%d] = %#v", index, event.Payload)
		}
		if wantReferences && (len(payload) != 3 || payload["authorization_correlation_id"] == "" ||
			payload["authorization_manifest_digest"] != testToolManifestDigest) {
			t.Fatalf("permissioned side-effect reference payload[%d] = %#v", index, event.Payload)
		}
		if !wantReferences && len(payload) != 1 {
			t.Fatalf("permissioned side-effect failure payload[%d] = %#v", index, event.Payload)
		}
	}
}

func firstToolConfirm(t *testing.T, events []protocol.Event) protocol.ConfirmRequest {
	t.Helper()
	for _, event := range events {
		if event.Type != protocol.EventConfirmRequest {
			continue
		}
		confirm, ok := event.Payload.(protocol.ConfirmRequest)
		if !ok {
			t.Fatalf("confirm payload type = %T", event.Payload)
		}
		return confirm
	}
	t.Fatalf("no confirmation request in %+v", events)
	return protocol.ConfirmRequest{}
}

type staticTool struct {
	name string
	out  string
	err  error
	runs *int
}

func (t staticTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name}, nil
}

func (t staticTool) InvokableRun(context.Context, string, ...einotool.Option) (string, error) {
	if t.runs != nil {
		*t.runs++
	}
	return t.out, t.err
}

type authorizedStaticTool struct {
	staticTool
	manifestDigest string
}

func (t authorizedStaticTool) ToolAuthorizationManifestDigest() string {
	return t.manifestDigest
}

const testToolManifestDigest = "tool_manifest_00000000000000000000000000000001"

func testAuthorizedStaticTool(
	t *testing.T,
	authorization protocol.AuthorizationContext,
	tool staticTool,
	authorizationEvidence ...protocol.EvidencePackage,
) authorizedStaticTool {
	t.Helper()
	if tool.err == nil {
		tool.out = testToolOutputWithAuthorization(t, authorization, tool.name, tool.out, authorizationEvidence...)
	}
	return authorizedStaticTool{staticTool: tool, manifestDigest: testToolManifestDigest}
}

func testToolOutputWithAuthorization(
	t *testing.T,
	authorization protocol.AuthorizationContext,
	toolName string,
	output string,
	authorizationEvidence ...protocol.EvidencePackage,
) string {
	t.Helper()
	manifest := testToolAuthorizationManifest(t, toolName)
	checkedAt := time.Unix(1, 0).UTC()
	correlationID := "tool-authorization-" + strings.TrimPrefix(toolName, "knote_")
	invocation := protocol.ToolInvocationAuthorization{
		Version: protocol.EnterpriseContractVersion, CorrelationID: correlationID,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID: authorization.PrincipalID, AgentID: authorization.AgentID, TaskID: authorization.TaskID,
		SessionID: authorization.SessionID, RequestID: authorization.RequestID,
		ToolName: manifest.ToolName, Action: manifest.Action, Relation: manifest.Relation,
		AuthorizationModelID: authorization.AuthorizationModelID,
		IdentityWatermark:    authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		DelegationWatermark:       authorization.DelegationWatermark,
		AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
		SideEffect:                manifest.SideEffect, ReturnObligation: manifest.ReturnObligation,
		Outcome: protocol.DecisionAllow, Consistency: authorization.Consistency, CheckedAt: checkedAt,
	}
	result := protocol.ToolResultAuthorization{
		Version: protocol.EnterpriseContractVersion, CorrelationID: correlationID,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID: authorization.PrincipalID, AgentID: authorization.AgentID, TaskID: authorization.TaskID,
		SessionID: authorization.SessionID, RequestID: authorization.RequestID,
		ToolName: manifest.ToolName, Action: manifest.Action, Relation: manifest.Relation,
		SideEffect: manifest.SideEffect, ReturnObligation: manifest.ReturnObligation,
		AuthorizationModelID: authorization.AuthorizationModelID,
		IdentityWatermark:    authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		DelegationWatermark:       authorization.DelegationWatermark,
		AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
	}
	for _, evidencePackage := range authorizationEvidence {
		for _, decision := range evidencePackage.Decisions {
			result.Resources = append(result.Resources, decision.Resource)
			result.Decisions = append(result.Decisions, decision)
		}
	}
	envelope := protocol.ToolAuthorizationEnvelope{
		Version: protocol.EnterpriseContractVersion, ManifestDigest: testToolManifestDigest,
		Invocation: invocation, Result: result,
	}
	if err := envelope.ValidateFor(authorization, manifest); err != nil {
		t.Fatalf("test tool authorization envelope is invalid: %v", err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal([]byte(output), &fields); err != nil {
		t.Fatalf("decode test tool output: %v", err)
	}
	fields["tool_authorization"] = envelope
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func testToolAuthorizationManifest(t *testing.T, toolName string) protocol.ToolAuthorizationManifest {
	t.Helper()
	manifest := protocol.ToolAuthorizationManifest{
		Version:          protocol.EnterpriseContractVersion,
		ToolName:         toolName,
		Action:           strings.TrimPrefix(toolName, "knote_"),
		Relation:         "can_view",
		ReturnObligation: protocol.ToolReturnEvidence,
	}
	if sideEffectToolName(toolName) {
		manifest.Relation = "can_edit"
		manifest.SideEffect = true
		manifest.ReturnObligation = protocol.ToolReturnNone
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("test tool authorization manifest is invalid: %v", err)
	}
	return manifest
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
