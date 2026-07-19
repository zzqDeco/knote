package eino

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestRunnerInventoryAndSkeletonRun(t *testing.T) {
	runner := NewRunner(Options{
		Tools: []einotool.InvokableTool{
			fakeTool{name: "knote_query", desc: "Query knowledge."},
			fakeTool{name: "knote_diff", desc: "Diff knowledge."},
		},
		EnableStreaming: true,
	})
	tools, err := runner.ToolInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 || tools[0].Name != "knote_query" || tools[1].Name != "knote_diff" {
		t.Fatalf("unexpected tool inventory: %+v", tools)
	}
	if err := runner.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "requires a configured") {
		t.Fatalf("expected skeleton runner to be not ready, got %v", err)
	}
	if _, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "hello"}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected skeleton run error, got %v", err)
	}
}

func TestRunnerProjectsExecutorEvents(t *testing.T) {
	executor := &fakeExecutor{
		events: []*adk.AgentEvent{
			adk.EventFromMessage(schema.ToolMessage("tool output", "call_1", schema.WithToolName("knote_diff")), nil, schema.Tool, "knote_diff"),
			adk.EventFromMessage(schema.AssistantMessage("assistant answer", nil), nil, schema.Assistant, ""),
		},
	}
	runner := NewRunner(Options{
		Executor: executor,
	})
	if err := runner.Ready(context.Background()); err != nil {
		t.Fatalf("runner should be ready: %v", err)
	}
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{
		SessionID: "s1",
		Message:   "question",
		History: []protocol.Event{
			protocol.NewEvent(protocol.EventUserMessage, "s1", "earlier question", nil),
			protocol.NewEvent(protocol.EventAssistantDone, "s1", "earlier answer", nil),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := messageContents(executor.messages); strings.Join(got, "|") != "earlier question|earlier answer|question" {
		t.Fatalf("runner did not preserve transcript history: %+v", got)
	}
	if !hasEvent(events, protocol.EventAssistantStart) {
		t.Fatalf("missing assistant start: %+v", events)
	}
	if !hasEvent(events, protocol.EventToolComplete) {
		t.Fatalf("missing tool complete: %+v", events)
	}
	if got := lastMessage(events, protocol.EventAssistantDone); got != "assistant answer" {
		t.Fatalf("unexpected assistant answer %q in %+v", got, events)
	}
}

func TestRunnerPreservesUnnamedToolOutputWithoutAuthorization(t *testing.T) {
	runner := NewRunner(Options{Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.ToolMessage("NON_PERMISSIONED_TOOL_CANARY", "call_1"), nil, schema.Tool, ""),
	}}})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type != protocol.EventToolComplete {
			continue
		}
		if event.Message != "NON_PERMISSIONED_TOOL_CANARY" || eventToolName(event.Payload) != "eino_tool" {
			t.Fatalf("unnamed non-permissioned tool output changed: %+v", event)
		}
		if event.ProtectedContent != nil {
			t.Fatalf("non-permissioned tool output was protected: %+v", event)
		}
		return
	}
	t.Fatalf("unnamed non-permissioned tool output was not projected: %+v", events)
}

func TestRunnerProjectsStreamingAndInterruptEvents(t *testing.T) {
	stream := schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("streamed answer", nil)})
	runner := NewRunner(Options{
		Executor: &fakeExecutor{
			events: []*adk.AgentEvent{
				adk.EventFromMessage(nil, stream, schema.Assistant, ""),
				{
					Action: &adk.AgentAction{
						Interrupted: &adk.InterruptInfo{
							InterruptContexts: []*adk.InterruptCtx{
								{ID: "agent:test", Info: "approval needed", IsRootCause: true},
							},
						},
					},
				},
			},
		},
	})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastMessage(events, protocol.EventAssistantDone); got != "streamed answer" {
		t.Fatalf("streaming assistant output was not projected: %q in %+v", got, events)
	}
	if got := lastMessage(events, protocol.EventApprovalRequest); got != "approval needed" {
		t.Fatalf("interrupt was not surfaced: %q in %+v", got, events)
	}
}

func TestRunnerKeepsPartialEventsOnExecutorError(t *testing.T) {
	runner := NewRunner(Options{
		Executor: &fakeExecutor{
			events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.AssistantMessage("partial answer", nil), nil, schema.Assistant, ""),
			},
			err: errors.New("runner failed"),
		},
	})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err == nil || !strings.Contains(err.Error(), "runner failed") {
		t.Fatalf("expected executor error, got %v", err)
	}
	if got := lastMessage(events, protocol.EventAssistantDone); got != "partial answer" {
		t.Fatalf("partial assistant output was not preserved: %q in %+v", got, events)
	}
}

func TestRunnerDiscardsPartialPermissionedEventsOnExecutorError(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/partial.md", "PARTIAL_EVIDENCE_CANARY")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(Options{Executor: &fakeExecutor{
		events: []*adk.AgentEvent{
			adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, evidencePackage, "PARTIAL_TOOL_CANARY"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
			adk.EventFromMessage(schema.AssistantMessage("PARTIAL_ASSISTANT_CANARY", nil), nil, schema.Assistant, ""),
		},
		err: errors.New("EXECUTOR_FAILURE_CANARY"),
	}})

	events, err := runner.Run(ctx, runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "question"})
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("permissioned executor error = %v, events=%+v", err, events)
	}
	for _, event := range events {
		if event.Type == protocol.EventToolComplete || event.Type == protocol.EventAssistantDone {
			t.Fatalf("failed permissioned turn retained partial output: %+v", events)
		}
		if event.ProtectedContent != nil {
			t.Fatalf("failed permissioned turn retained protected output: %+v", events)
		}
		for _, canary := range []string{"PARTIAL_TOOL_CANARY", "PARTIAL_ASSISTANT_CANARY", "PARTIAL_EVIDENCE_CANARY", "EXECUTOR_FAILURE_CANARY"} {
			if strings.Contains(event.Message, canary) {
				t.Fatalf("failed permissioned turn leaked %q: %+v", canary, events)
			}
		}
	}
}

func TestRunnerPreservesPendingSideEffectSentinelInPermissionedContext(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(Options{Executor: &fakeExecutor{
		events: []*adk.AgentEvent{
			adk.EventFromMessage(schema.ToolMessage("PARTIAL_TOOL_CANARY", "call_1", schema.WithToolName("knote_diff")), nil, schema.Tool, "knote_diff"),
			adk.EventFromMessage(schema.AssistantMessage("PARTIAL_ASSISTANT_CANARY", nil), nil, schema.Assistant, ""),
		},
		err: fmt.Errorf("PENDING_EXECUTOR_CANARY: %w", runtime.ErrSideEffectPending),
	}})

	events, err := runner.Run(ctx, runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "build knowledge"})
	if !errors.Is(err, runtime.ErrSideEffectPending) {
		t.Fatalf("pending side-effect error lost sentinel identity: %v", err)
	}
	if strings.Contains(err.Error(), "PENDING_EXECUTOR_CANARY") {
		t.Fatalf("pending side-effect error exposed executor details: %v", err)
	}
	for _, event := range events {
		if event.Type == protocol.EventToolComplete || event.Type == protocol.EventAssistantDone || event.Type == protocol.EventError {
			t.Fatalf("pending permissioned turn retained partial or error output: %+v", events)
		}
		if strings.Contains(event.Message, "PARTIAL_") || strings.Contains(event.Message, "PENDING_EXECUTOR_CANARY") {
			t.Fatalf("pending permissioned turn leaked executor output: %+v", events)
		}
	}
}

func TestRunnerPendingSideEffectWaitsForManagerConfirmationWithoutError(t *testing.T) {
	workspace := t.TempDir()
	authorization := testEinoAuthorization("sess_eino")
	bridge := runtime.NewSideEffectBridge()
	runner := NewRunner(Options{Executor: pendingSideEffectExecutor{
		bridge:    bridge,
		sessionID: authorization.SessionID,
	}})
	manager := runtime.New(runtime.Dependencies{
		Workspace:   workspace,
		Sessions:    local.New(workspace),
		EinoRunner:  runner,
		SideEffects: bridge,
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			current := authorization
			current.SessionID = sessionID
			return current, nil
		},
		NewSessionID: func() string { return authorization.SessionID },
	})
	if _, err := manager.Start(context.Background(), runtime.StartOptions{}); err != nil {
		t.Fatal(err)
	}

	events := manager.SendMessage(context.Background(), "build knowledge")
	if !hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("pending side effect did not reach confirmation state: %+v", events)
	}
	for _, event := range events {
		if event.Type == protocol.EventError || event.Type == protocol.EventToolComplete || event.Type == protocol.EventAssistantDone {
			t.Fatalf("manager exposed an error or partial output while confirmation waits: %+v", events)
		}
		if strings.Contains(event.Message, "PENDING_MANAGER_CANARY") {
			t.Fatalf("manager leaked pending executor output: %+v", events)
		}
	}
}

func TestRunnerRejectsVersionsToolInAuthorizationContext(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(Options{Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.AssistantMessage("", []schema.ToolCall{{
			ID: "call_versions", Function: schema.FunctionCall{Name: "knote_versions", Arguments: `{}`},
		}}), nil, schema.Assistant, ""),
		adk.EventFromMessage(schema.ToolMessage("SAFE_VERSIONS_CANARY", "call_versions", schema.WithToolName("knote_versions")), nil, schema.Tool, "knote_versions"),
		adk.EventFromMessage(schema.AssistantMessage("SAFE_ASSISTANT_CANARY", nil), nil, schema.Assistant, ""),
	}}})

	events, err := runner.Run(ctx, runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "compare versions"})
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("permissioned versions error = %v, events=%+v", err, events)
	}
	projected := fmt.Sprint(events)
	for _, canary := range []string{"SAFE_VERSIONS_CANARY", "SAFE_ASSISTANT_CANARY", "safe-tool-assistant/v1"} {
		if strings.Contains(projected, canary) {
			t.Fatalf("permissioned versions turn leaked %q: %s", canary, projected)
		}
	}
	if hasEvent(events, protocol.EventToolComplete) || hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("permissioned versions output was projected: %+v", events)
	}
}

func TestRunnerRejectsSafeToolAssistantAnswerDerivedFromProtectedHistory(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/protected.md", "PROTECTED_HISTORY_EVIDENCE_CANARY")
	binding, err := protocol.NewProtectedContentBinding(authorization, evidencePackage)
	if err != nil {
		t.Fatal(err)
	}
	protectedAnswer := protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "PROTECTED_HISTORY_ANSWER_CANARY", nil)
	protectedAnswer.ProtectedContent = &binding
	runner := NewRunner(Options{Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.AssistantMessage("", []schema.ToolCall{{
			ID: "call_versions", Function: schema.FunctionCall{Name: "knote_versions", Arguments: `{}`},
		}}), nil, schema.Assistant, ""),
		adk.EventFromMessage(schema.ToolMessage("SAFE_HISTORY_TOOL_CANARY", "call_versions", schema.WithToolName("knote_versions")), nil, schema.Tool, "knote_versions"),
		adk.EventFromMessage(schema.AssistantMessage("SAFE_HISTORY_SUMMARY_CANARY", nil), nil, schema.Assistant, ""),
	}}})

	events, err := runner.Run(ctx, runtime.EinoRunInput{
		SessionID: authorization.SessionID,
		Message:   "compare versions",
		History: []protocol.Event{
			protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "protected question", nil),
			protectedAnswer,
		},
	})
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("protected-history safe-tool error = %v, want %q: %+v", err, protectedContentUnavailableMessage, events)
	}
	encoded := fmt.Sprintf("%+v", events)
	for _, canary := range []string{"SAFE_HISTORY_TOOL_CANARY", "SAFE_HISTORY_SUMMARY_CANARY", "safe-tool-assistant/v1"} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("protected-history safe-tool turn leaked %q: %s", canary, encoded)
		}
	}
	if hasEvent(events, protocol.EventToolComplete) || hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("protected-history safe-tool turn projected content: %+v", events)
	}
}

func TestRunnerRejectsContentBearingNonPermissionedToolInAuthorizationContext(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(Options{Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.AssistantMessage("", []schema.ToolCall{{
			ID: "call_diff", Function: schema.FunctionCall{Name: "knote_diff", Arguments: `{}`},
		}}), nil, schema.Assistant, ""),
		adk.EventFromMessage(schema.ToolMessage("UNTRUSTED_DIFF_CANARY", "call_diff", schema.WithToolName("knote_diff")), nil, schema.Tool, "knote_diff"),
		adk.EventFromMessage(schema.AssistantMessage("UNTRUSTED_ASSISTANT_CANARY", nil), nil, schema.Assistant, ""),
	}}})

	events, err := runner.Run(ctx, runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "show diff"})
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("content-bearing tool error = %v, want %q: %+v", err, protectedContentUnavailableMessage, events)
	}
	projected := fmt.Sprintf("%+v", events)
	if strings.Contains(projected, "UNTRUSTED_DIFF_CANARY") || strings.Contains(projected, "UNTRUSTED_ASSISTANT_CANARY") {
		t.Fatalf("content-bearing tool leaked into permissioned events: %s", projected)
	}
	if got := countEvents(events, protocol.EventToolComplete); got != 0 {
		t.Fatalf("content-bearing tool completion count = %d, want 0: %+v", got, events)
	}
}

func TestRunnerPersistsLoadsAndResumesVersionsOutputWithoutAuthorization(t *testing.T) {
	workspace := t.TempDir()
	authorization := testEinoAuthorization("sess_safe_replay")
	store := local.New(workspace)
	newExecutor := func() *fakeExecutor {
		return &fakeExecutor{events: []*adk.AgentEvent{
			adk.EventFromMessage(schema.AssistantMessage("", []schema.ToolCall{{
				ID: "call_versions", Function: schema.FunctionCall{Name: "knote_versions", Arguments: `{}`},
			}}), nil, schema.Assistant, ""),
			adk.EventFromMessage(schema.ToolMessage("SAFE_PERSISTED_TOOL_CANARY", "call_versions", schema.WithToolName("knote_versions")), nil, schema.Tool, "knote_versions"),
			adk.EventFromMessage(schema.AssistantMessage("SAFE_PERSISTED_ANSWER_CANARY", nil), nil, schema.Assistant, ""),
		}}
	}

	firstExecutor := newExecutor()
	manager := runtime.New(runtime.Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		EinoRunner:   NewRunner(Options{Executor: firstExecutor}),
		NewSessionID: func() string { return authorization.SessionID },
	})
	if _, err := manager.Start(context.Background(), runtime.StartOptions{}); err != nil {
		t.Fatal(err)
	}
	produced := manager.SendMessage(context.Background(), "compare versions")
	if !hasEventMessage(produced, protocol.EventAssistantDone, "SAFE_PERSISTED_ANSWER_CANARY") {
		t.Fatalf("safe answer was not produced: %+v", produced)
	}
	raw, err := store.Load(context.Background(), authorization.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	persisted := false
	for _, event := range raw {
		if event.Message == "SAFE_PERSISTED_ANSWER_CANARY" {
			persisted = true
			if eventPayloadString(event.Payload, "replay_class") != "" {
				t.Fatalf("non-permissioned answer unexpectedly received a replay class: %+v", event)
			}
		}
	}
	if !persisted {
		t.Fatalf("safe answer was not persisted: %+v", raw)
	}

	resumeExecutor := newExecutor()
	resumed := runtime.New(runtime.Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		EinoRunner:   NewRunner(Options{Executor: resumeExecutor}),
		NewSessionID: func() string { return "sess_other" },
	})
	replayed, err := resumed.Start(context.Background(), runtime.StartOptions{ResumeID: authorization.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if !hasEventMessage(replayed, protocol.EventAssistantDone, "SAFE_PERSISTED_ANSWER_CANARY") {
		t.Fatalf("safe answer was dropped during resume: %+v", replayed)
	}
	resumed.SendMessage(context.Background(), "follow up")
	if got := messageContents(resumeExecutor.messages); strings.Join(got, "|") != "compare versions|SAFE_PERSISTED_ANSWER_CANARY|follow up" {
		t.Fatalf("loadHistory dropped or changed the safe answer: %+v", got)
	}
}

func TestRunnerBindsAllPermissionedToolOutputsAndAnswerToOneBlock(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	first := testEinoEvidencePackage(t, authorization, "sources/first.md", "FIRST_CONTENT_CANARY")
	second := testEinoEvidencePackage(t, authorization, "sources/second.md", "SECOND_CONTENT_CANARY")
	runner := NewRunner(Options{ToolAuthorizationValidator: testEinoToolAuthorizationValidator(t), Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, second, "second", "knote_explain"), "call_2", schema.WithToolName("knote_explain")), nil, schema.Tool, "knote_explain"),
		adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, first, "first"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
		adk.EventFromMessage(schema.AssistantMessage("AUTHORIZED_ANSWER_CANARY", nil), nil, schema.Assistant, ""),
	}}})
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	events, err := runner.Run(ctx, runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "question"})
	if err != nil {
		t.Fatal(err)
	}
	var blockID string
	bound := 0
	for _, event := range events {
		if event.Type != protocol.EventToolComplete && event.Type != protocol.EventAssistantDone {
			continue
		}
		if event.ProtectedContent == nil {
			t.Fatalf("permissioned ADK event has no protected binding: %+v", event)
		}
		if eventPayloadString(event.Payload, "replay_class") != "" {
			t.Fatalf("permissioned ADK event received a safe replay class: %+v", event)
		}
		if blockID == "" {
			blockID = event.ProtectedContent.BlockID
		} else if event.ProtectedContent.BlockID != blockID {
			t.Fatalf("permissioned ADK events used different blocks: %+v", events)
		}
		if len(event.ProtectedContent.Resources) != 2 {
			t.Fatalf("permissioned ADK block resources = %d", len(event.ProtectedContent.Resources))
		}
		bound++
	}
	if bound != 3 {
		t.Fatalf("permissioned ADK bound events = %d in %+v", bound, events)
	}
}

func TestRunnerRedactsPermissionedToolOutputBeforeSessionPersistence(t *testing.T) {
	workspace := t.TempDir()
	authorization := testEinoAuthorization("sess_redacted_tool_output")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/private.md", "PRIVATE_EVIDENCE_CONTENT_CANARY")
	runner := NewRunner(Options{ToolAuthorizationValidator: testEinoToolAuthorizationValidator(t), Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, evidencePackage, "PRIVATE_TOOL_ANSWER_CANARY"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
		adk.EventFromMessage(schema.AssistantMessage("AUTHORIZED_FINAL_ANSWER_CANARY", nil), nil, schema.Assistant, ""),
	}}})
	store := local.New(workspace)
	manager := runtime.New(runtime.Dependencies{
		Workspace:  workspace,
		Sessions:   store,
		EinoRunner: runner,
		AuthorizationContextProvider: func(context.Context, string) (protocol.AuthorizationContext, error) {
			return authorization, nil
		},
		NewSessionID: func() string { return authorization.SessionID },
	})
	if _, err := manager.Start(context.Background(), runtime.StartOptions{}); err != nil {
		t.Fatal(err)
	}
	produced := manager.SendMessage(context.Background(), "private question")
	if !hasEventMessage(produced, protocol.EventAssistantDone, "AUTHORIZED_FINAL_ANSWER_CANARY") {
		t.Fatalf("authorized answer was not produced: %+v", produced)
	}
	var redactedToolEvent *protocol.Event
	for index := range produced {
		if produced[index].Type == protocol.EventToolComplete {
			redactedToolEvent = &produced[index]
			break
		}
	}
	if redactedToolEvent == nil || redactedToolEvent.Message != "knote_query complete" ||
		eventPayloadString(redactedToolEvent.Payload, "tool") != "knote_query" ||
		redactedToolEvent.ProtectedContent == nil {
		t.Fatalf("permissioned tool completion was not reduced to protected metadata: %+v", produced)
	}

	raw, err := os.ReadFile(filepath.Join(workspace, ".knote", "sessions", authorization.SessionID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	persisted := string(raw)
	for _, secret := range []string{"PRIVATE_EVIDENCE_CONTENT_CANARY", "PRIVATE_TOOL_ANSWER_CANARY"} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("permissioned tool output persisted %q: %s", secret, persisted)
		}
	}
	for _, retained := range []string{"AUTHORIZED_FINAL_ANSWER_CANARY", string(evidencePackage.Items[0].Resource.ResourceID), `"block_id"`} {
		if !strings.Contains(persisted, retained) {
			t.Fatalf("permissioned session omitted protected metadata %q: %s", retained, persisted)
		}
	}
}

func TestRunnerBindsPermissionedInterruptForRevocationReplay(t *testing.T) {
	workspace := t.TempDir()
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/approval.md", "APPROVAL_CONTENT_CANARY")
	runner := NewRunner(Options{ToolAuthorizationValidator: testEinoToolAuthorizationValidator(t), Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, evidencePackage, "answer"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
		{
			Action: &adk.AgentAction{Interrupted: &adk.InterruptInfo{InterruptContexts: []*adk.InterruptCtx{
				{ID: "agent:test", Info: "PERMISSIONED_APPROVAL_CANARY", IsRootCause: true},
			}}},
		},
	}}})
	store := local.New(workspace)
	provider := func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		current := authorization
		current.SessionID = sessionID
		return current, nil
	}
	manager := runtime.New(runtime.Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: provider,
		NewSessionID:                 func() string { return authorization.SessionID },
	})
	if _, err := manager.Start(context.Background(), runtime.StartOptions{}); err != nil {
		t.Fatal(err)
	}
	produced := manager.SendMessage(context.Background(), "question")
	var blockID string
	boundTypes := map[protocol.EventType]bool{}
	for _, event := range produced {
		if event.Type != protocol.EventToolComplete && event.Type != protocol.EventApprovalRequest {
			continue
		}
		if event.ProtectedContent == nil {
			t.Fatalf("permissioned tool or approval event has no replay binding: %+v", event)
		}
		if blockID == "" {
			blockID = event.ProtectedContent.BlockID
		} else if event.ProtectedContent.BlockID != blockID {
			t.Fatalf("permissioned approval used a different replay block: %+v", produced)
		}
		boundTypes[event.Type] = true
	}
	if blockID == "" || !boundTypes[protocol.EventToolComplete] || !boundTypes[protocol.EventApprovalRequest] {
		t.Fatalf("permissioned tool and approval were not both replay-bound: %+v", produced)
	}

	authorizationCalls := 0
	replayManager := runtime.New(runtime.Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: provider,
		ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			authorizationCalls++
			return errors.New("revoked")
		},
		NewSessionID: func() string { return "sess_other" },
	})
	replayed, err := replayManager.Start(context.Background(), runtime.StartOptions{ResumeID: authorization.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if authorizationCalls != 1 {
		t.Fatalf("protected replay authorization calls = %d, want 1", authorizationCalls)
	}
	for _, event := range replayed {
		if strings.Contains(event.Message, "PERMISSIONED_APPROVAL_CANARY") || strings.Contains(event.Message, "APPROVAL_CONTENT_CANARY") {
			t.Fatalf("revoked permissioned interrupt replay leaked protected content: %+v", replayed)
		}
	}
}

func TestRunnerBindsPermissionedStatusForRevocationReplay(t *testing.T) {
	workspace := t.TempDir()
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/status.md", "STATUS_EVIDENCE_CANARY")
	runner := NewRunner(Options{ToolAuthorizationValidator: testEinoToolAuthorizationValidator(t), Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, evidencePackage, "answer"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
		adk.EventFromMessage(schema.SystemMessage("PERMISSIONED_STATUS_CANARY"), nil, schema.System, ""),
	}}})
	store := local.New(workspace)
	provider := func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		current := authorization
		current.SessionID = sessionID
		return current, nil
	}
	manager := runtime.New(runtime.Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: provider,
		NewSessionID:                 func() string { return authorization.SessionID },
	})
	if _, err := manager.Start(context.Background(), runtime.StartOptions{}); err != nil {
		t.Fatal(err)
	}
	produced := manager.SendMessage(context.Background(), "question")
	var blockID string
	boundTypes := map[protocol.EventType]bool{}
	for _, event := range produced {
		if event.Type != protocol.EventToolComplete && event.Type != protocol.EventStatusUpdate {
			continue
		}
		if event.ProtectedContent == nil {
			t.Fatalf("permissioned tool or status event has no replay binding: %+v", event)
		}
		if blockID == "" {
			blockID = event.ProtectedContent.BlockID
		} else if event.ProtectedContent.BlockID != blockID {
			t.Fatalf("permissioned status used a different replay block: %+v", produced)
		}
		boundTypes[event.Type] = true
	}
	if blockID == "" || !boundTypes[protocol.EventToolComplete] || !boundTypes[protocol.EventStatusUpdate] {
		t.Fatalf("permissioned tool and status were not both replay-bound: %+v", produced)
	}

	authorizationCalls := 0
	replayManager := runtime.New(runtime.Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: provider,
		ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			authorizationCalls++
			return errors.New("revoked")
		},
		NewSessionID: func() string { return "sess_other" },
	})
	replayed, err := replayManager.Start(context.Background(), runtime.StartOptions{ResumeID: authorization.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if authorizationCalls != 1 {
		t.Fatalf("protected replay authorization calls = %d, want 1", authorizationCalls)
	}
	for _, event := range replayed {
		if strings.Contains(event.Message, "PERMISSIONED_STATUS_CANARY") || strings.Contains(event.Message, "STATUS_EVIDENCE_CANARY") {
			t.Fatalf("revoked permissioned status replay leaked protected content: %+v", replayed)
		}
	}
}

func TestRunnerPreservesContextFreeStatus(t *testing.T) {
	runner := NewRunner(Options{Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.SystemMessage("CONTEXT_FREE_STATUS_CANARY"), nil, schema.System, ""),
	}}})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type != protocol.EventStatusUpdate {
			continue
		}
		if event.Message != "CONTEXT_FREE_STATUS_CANARY" || event.ProtectedContent != nil {
			t.Fatalf("context-free status behavior changed: %+v", event)
		}
		return
	}
	t.Fatalf("context-free status was not projected: %+v", events)
}

func TestRunnerFailsPermissionedOutputClosedAndSanitizesErrors(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	missingEnvelopeEvidence := testEinoEvidencePackage(
		t, authorization, "sources/missing-envelope.md", "MISSING_ENVELOPE_CONTENT_CANARY",
	)
	envelopeEvidence := testEinoEvidencePackage(
		t, authorization, "sources/envelope.md", "ENVELOPE_RESOURCE_CONTENT_CANARY",
	)
	mismatchedEvidence := testEinoEvidencePackage(
		t, authorization, "sources/mismatch.md", "MISMATCHED_RESOURCE_CONTENT_CANARY",
	)
	for _, test := range []struct {
		name     string
		executor *fakeExecutor
	}{
		{
			name: "missing evidence",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.ToolMessage(`{"answer":"MALFORMED_OUTPUT_CANARY"}`, "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
			}},
		},
		{
			name: "missing authorization envelope",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.ToolMessage(
					testPermissionedToolOutputWithoutAuthorization(t, missingEnvelopeEvidence, "MISSING_ENVELOPE_ANSWER_CANARY"),
					"call_1", schema.WithToolName("knote_query"),
				), nil, schema.Tool, "knote_query"),
			}},
		},
		{
			name: "authorization resources do not match evidence",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.ToolMessage(
					testPermissionedToolOutputWithAuthorizationEvidence(
						t, mismatchedEvidence, envelopeEvidence, "MISMATCHED_ENVELOPE_ANSWER_CANARY",
					),
					"call_1", schema.WithToolName("knote_query"),
				), nil, schema.Tool, "knote_query"),
			}},
		},
		{
			name: "safe tool cannot mask malformed permissioned evidence",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.ToolMessage("SAFE_TOOL_BEFORE_MALFORMED_CANARY", "call_1", schema.WithToolName("knote_versions")), nil, schema.Tool, "knote_versions"),
				adk.EventFromMessage(schema.ToolMessage(`{"answer":"MIXED_MALFORMED_OUTPUT_CANARY"}`, "call_2", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
				adk.EventFromMessage(schema.AssistantMessage("MIXED_UNBOUND_ANSWER_CANARY", nil), nil, schema.Assistant, ""),
			}},
		},
		{
			name: "safe tool cannot mask permissioned tool attempt",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.AssistantMessage("", []schema.ToolCall{{
					ID: "call_query", Function: schema.FunctionCall{Name: "knote_query", Arguments: `{}`},
				}}), nil, schema.Assistant, ""),
				adk.EventFromMessage(schema.ToolMessage("SAFE_TOOL_AFTER_QUERY_CANARY", "call_versions", schema.WithToolName("knote_versions")), nil, schema.Tool, "knote_versions"),
				adk.EventFromMessage(schema.AssistantMessage("ATTEMPTED_QUERY_UNBOUND_ANSWER_CANARY", nil), nil, schema.Assistant, ""),
			}},
		},
		{
			name: "executor error after evidence",
			executor: &fakeExecutor{
				events: []*adk.AgentEvent{
					adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, testEinoEvidencePackage(t, authorization, "sources/error.md", "ERROR_CONTENT_CANARY"), "answer"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
				},
				err: errors.New("EXECUTOR_ERROR_CANARY"),
			},
		},
		{
			name: "unnamed tool output",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, testEinoEvidencePackage(t, authorization, "sources/unnamed.md", "UNNAMED_CONTENT_CANARY"), "UNNAMED_OUTPUT_CANARY"), "call_1"), nil, schema.Tool, ""),
			}},
		},
		{
			name:     "executor error without evidence",
			executor: &fakeExecutor{err: errors.New("CONTEXT_ERROR_CANARY")},
		},
		{
			name: "assistant answer without evidence",
			executor: &fakeExecutor{events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.AssistantMessage("UNBOUND_ANSWER_CANARY", nil), nil, schema.Assistant, ""),
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := NewRunner(Options{
				Executor:                   test.executor,
				ToolAuthorizationValidator: testEinoToolAuthorizationValidator(t),
			})
			events, err := runner.Run(ctx, runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "question"})
			if err == nil || err.Error() != protectedContentUnavailableMessage {
				t.Fatalf("permissioned ADK error = %v, events=%+v", err, events)
			}
			for _, event := range events {
				if eventPayloadString(event.Payload, "replay_class") != "" {
					t.Fatalf("failed permissioned flow received a safe replay class: %+v", events)
				}
				if strings.Contains(event.Message, "MALFORMED_OUTPUT_CANARY") ||
					strings.Contains(event.Message, "MISSING_ENVELOPE_CONTENT_CANARY") ||
					strings.Contains(event.Message, "MISSING_ENVELOPE_ANSWER_CANARY") ||
					strings.Contains(event.Message, "MISMATCHED_RESOURCE_CONTENT_CANARY") ||
					strings.Contains(event.Message, "MISMATCHED_ENVELOPE_ANSWER_CANARY") ||
					strings.Contains(event.Message, "SAFE_TOOL_BEFORE_MALFORMED_CANARY") ||
					strings.Contains(event.Message, "MIXED_UNBOUND_ANSWER_CANARY") ||
					strings.Contains(event.Message, "ATTEMPTED_QUERY_UNBOUND_ANSWER_CANARY") ||
					strings.Contains(event.Message, "UNNAMED_CONTENT_CANARY") ||
					strings.Contains(event.Message, "UNNAMED_OUTPUT_CANARY") ||
					strings.Contains(event.Message, "EXECUTOR_ERROR_CANARY") ||
					strings.Contains(event.Message, "CONTEXT_ERROR_CANARY") ||
					strings.Contains(event.Message, "UNBOUND_ANSWER_CANARY") {
					t.Fatalf("permissioned ADK error leaked backend details: %+v", events)
				}
				if event.Type == protocol.EventAssistantDone {
					t.Fatalf("permissioned ADK persisted an unbound assistant answer: %+v", events)
				}
			}
		})
	}
}

func TestRunnerRejectsPermissionedOutputWithoutAuthorizationContext(t *testing.T) {
	authorization := testEinoAuthorization("sess_eino")
	evidencePackage := testEinoEvidencePackage(t, authorization, "sources/no-context.md", "NO_CONTEXT_CONTENT_CANARY")
	runner := NewRunner(Options{Executor: &fakeExecutor{events: []*adk.AgentEvent{
		adk.EventFromMessage(schema.ToolMessage(testPermissionedToolOutput(t, evidencePackage, "NO_CONTEXT_ANSWER_CANARY"), "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
	}}})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: authorization.SessionID, Message: "question"})
	if err == nil || err.Error() != protectedContentUnavailableMessage {
		t.Fatalf("missing authorization error = %v, events=%+v", err, events)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "CANARY") {
			t.Fatalf("missing authorization leaked permissioned output: %+v", events)
		}
	}
}

func TestRunnerUsesStatusForNoResponseAndFiltersSlashHistory(t *testing.T) {
	executor := &fakeExecutor{}
	runner := NewRunner(Options{Executor: executor})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{
		SessionID: "s1",
		Message:   "question",
		History: []protocol.Event{
			protocol.NewEvent(protocol.EventUserMessage, "s1", "/build", nil),
			protocol.NewEvent(protocol.EventAssistantDone, "s1", "slash output", map[string]string{"source": "slash"}),
			protocol.NewEvent(protocol.EventStatusUpdate, "s1", "Eino runner completed without response.", nil),
			protocol.NewEvent(protocol.EventAssistantDone, "s1", "real assistant answer", nil),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("no-response fallback must not be persisted as assistant output: %+v", events)
	}
	if got := lastMessage(events, protocol.EventStatusUpdate); got != "Eino runner completed without response." {
		t.Fatalf("missing no-response status event: %q in %+v", got, events)
	}
	if got := messageContents(executor.messages); strings.Join(got, "|") != "real assistant answer|question" {
		t.Fatalf("slash or status history leaked into ADK messages: %+v", got)
	}
}

func TestRunnerConfigCarriesADKSettings(t *testing.T) {
	runner := NewRunner(Options{EnableStreaming: true})
	cfg := runner.RunnerConfig(nil)
	if !cfg.EnableStreaming {
		t.Fatal("expected ADK runner config to preserve streaming option")
	}
	if cfg.Agent != nil {
		t.Fatalf("expected nil agent in skeleton config, got %T", cfg.Agent)
	}
	if created := runner.NewADKRunner(context.Background(), nil); created == nil {
		t.Fatal("expected ADK runner to be constructible from skeleton config")
	}
}

type fakeTool struct {
	name string
	desc string
}

func (t fakeTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name, Desc: t.desc}, nil
}

func (fakeTool) InvokableRun(context.Context, string, ...einotool.Option) (string, error) {
	return "{}", nil
}

type fakeExecutor struct {
	events   []*adk.AgentEvent
	messages []*schema.Message
	err      error
}

type pendingSideEffectExecutor struct {
	bridge    *runtime.SideEffectBridge
	sessionID string
}

func (e pendingSideEffectExecutor) Run(ctx context.Context, _ []*schema.Message) ([]*adk.AgentEvent, error) {
	err := e.bridge.Request(ctx, runtime.SideEffectRequest{
		SessionID:       e.sessionID,
		ToolName:        "knote_build",
		Action:          "build",
		ArgumentsInJSON: "{}",
		Execute: func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
			return nil, nil
		},
	})
	return []*adk.AgentEvent{
		adk.EventFromMessage(schema.AssistantMessage("PENDING_MANAGER_CANARY", nil), nil, schema.Assistant, ""),
	}, err
}

func (e *fakeExecutor) Run(_ context.Context, messages []*schema.Message) ([]*adk.AgentEvent, error) {
	e.messages = append([]*schema.Message(nil), messages...)
	return append([]*adk.AgentEvent(nil), e.events...), e.err
}

func hasEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func hasEventMessage(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			return true
		}
	}
	return false
}

func countEvents(events []protocol.Event, eventType protocol.EventType) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func lastMessage(events []protocol.Event, eventType protocol.EventType) string {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == eventType {
			return events[i].Message
		}
	}
	return ""
}

func messageContents(messages []*schema.Message) []string {
	var out []string
	for _, message := range messages {
		if message != nil {
			out = append(out, message.Content)
		}
	}
	return out
}

func eventPayloadString(payload any, key string) string {
	switch value := payload.(type) {
	case map[string]string:
		return strings.TrimSpace(value[key])
	case map[string]any:
		item, _ := value[key].(string)
		return strings.TrimSpace(item)
	default:
		return ""
	}
}
