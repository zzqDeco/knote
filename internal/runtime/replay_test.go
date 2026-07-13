package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestFilterPersistedEventsAuthorizesOncePerBlockAndHidesDeniedContent(t *testing.T) {
	authorization := testAuthorizationContext("sess_replay")
	allowed := testProtectedBinding(t, authorization, "allowed")
	denied := testProtectedBinding(t, authorization, "denied")
	allowedTool := protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "ALLOWED_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}, allowed)
	allowedAnswer := protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "ALLOWED_ANSWER_CANARY", nil, allowed)
	deniedTool := protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "DENIED_TOOL_CANARY", map[string]string{"tool": einotools.NameExplain}, denied)
	deniedAnswer := protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "DENIED_ANSWER_CANARY", nil, denied)

	calls := map[string]int{}
	manager := New(Dependencies{
		AuthorizationContextProvider: testAuthorizationContextProvider,
		ProtectedContentAuthorizer: func(_ context.Context, current protocol.AuthorizationContext, binding protocol.ProtectedContentBinding) error {
			if current.SessionID != authorization.SessionID {
				t.Fatal("authorizer received the wrong session")
			}
			calls[binding.BlockID]++
			if binding.BlockID == denied.BlockID {
				return errors.New("AUTHORIZER_DETAIL_CANARY")
			}
			return nil
		},
	})
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "safe status", nil),
		allowedTool,
		allowedAnswer,
		deniedTool,
		deniedAnswer,
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "LEGACY_ANSWER_CANARY", nil),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "LEGACY_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "LEGACY_ERROR_CANARY", nil),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "safe user message", nil),
	}

	filtered := manager.filterPersistedEvents(context.Background(), authorization, events)
	if calls[allowed.BlockID] != 1 || calls[denied.BlockID] != 1 || len(calls) != 2 {
		t.Fatalf("protected block authorization calls = %#v", calls)
	}
	if !hasMessage(filtered, protocol.EventToolComplete, "ALLOWED_TOOL_CANARY") ||
		!hasMessage(filtered, protocol.EventAssistantDone, "ALLOWED_ANSWER_CANARY") {
		t.Fatalf("allowed block was not preserved: %+v", filtered)
	}
	encoded := eventsText(filtered)
	for _, canary := range []string{"DENIED_TOOL_CANARY", "DENIED_ANSWER_CANARY", "LEGACY_ANSWER_CANARY", "LEGACY_TOOL_CANARY", "LEGACY_ERROR_CANARY", "AUTHORIZER_DETAIL_CANARY"} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("filtered replay leaked %q: %s", canary, encoded)
		}
	}
	if !strings.Contains(encoded, "safe status") || !strings.Contains(encoded, "safe user message") {
		t.Fatalf("safe replay events were removed: %s", encoded)
	}
}

func TestFilterPersistedEventsRejectsMalformedBlocksWithoutAuthorization(t *testing.T) {
	authorization := testAuthorizationContext("sess_replay")
	binding := testProtectedBinding(t, authorization, "malformed")
	binding.BlockID = "block_00000000000000000000000000000000"
	calls := 0
	manager := New(Dependencies{
		AuthorizationContextProvider: testAuthorizationContextProvider,
		ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			calls++
			return nil
		},
	})
	filtered := manager.filterPersistedEvents(context.Background(), authorization, []protocol.Event{
		protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "MALFORMED_CONTENT_CANARY", nil, binding),
	})
	if calls != 0 || len(filtered) != 0 {
		t.Fatalf("malformed block reached authorization or replay: calls=%d events=%+v", calls, filtered)
	}
}

func TestFilterPersistedEventsKeepsLegacyBehaviorWithoutPermissionedSessions(t *testing.T) {
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventAssistantDone, "sess_legacy", "legacy answer", nil),
		protocol.NewEvent(protocol.EventError, "sess_legacy", "legacy error", nil),
	}
	filtered := New(Dependencies{}).filterPersistedEvents(context.Background(), protocol.AuthorizationContext{}, events)
	if len(filtered) != len(events) || !hasMessage(filtered, protocol.EventAssistantDone, "legacy answer") {
		t.Fatalf("non-permissioned replay changed: %+v", filtered)
	}
}

func TestFilterPersistedEventsPreservesUnprotectedSlashResponsesAndToolSummaries(t *testing.T) {
	authorization := testAuthorizationContext("sess_replay")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "help response", map[string]string{"source": "slash", "overlay": "help"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/details", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "details response", map[string]any{"source": "slash", "overlay": "details"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/settings", nil),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "settings error", nil),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/diff", nil),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "diff summary", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "direct tool summary", map[string]string{"source": "slash"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "protected legacy prompt", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "LEGACY_ANSWER_CANARY", nil),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "LEGACY_ERROR_CANARY", nil),
	}
	manager := New(Dependencies{
		AuthorizationContextProvider: testAuthorizationContextProvider,
		ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			return nil
		},
	})

	filtered := manager.filterPersistedEvents(context.Background(), authorization, events)
	want := []string{
		"/help", "help response",
		"/details", "details response",
		"/settings", "settings error",
		"/diff", "diff summary", "direct tool summary",
		"protected legacy prompt",
	}
	assertEventMessages(t, filtered, want)
}

func TestFilterPersistedEventsDropsProtectedContentWhenAuthorizationUnavailable(t *testing.T) {
	authorization := testAuthorizationContext("sess_replay")
	binding := testProtectedBinding(t, authorization, "unavailable")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "before", nil),
		protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "PROTECTED_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}, binding),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "safe slash response", map[string]string{"source": "slash"}),
		protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "PROTECTED_ANSWER_CANARY", nil, binding),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "safe tool summary", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "after", nil),
	}

	for _, test := range []struct {
		name string
		deps Dependencies
	}{
		{name: "provider missing", deps: Dependencies{}},
		{
			name: "provider missing with authorizer configured",
			deps: Dependencies{ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
				t.Fatal("authorizer called without an authorization context provider")
				return nil
			}},
		},
		{name: "authorizer missing", deps: Dependencies{AuthorizationContextProvider: testAuthorizationContextProvider}},
	} {
		t.Run(test.name, func(t *testing.T) {
			filtered := New(test.deps).filterPersistedEvents(context.Background(), authorization, events)
			assertEventMessages(t, filtered, []string{"before", "/help", "safe slash response", "safe tool summary", "after"})
			if encoded := eventsText(filtered); strings.Contains(encoded, "PROTECTED_") {
				t.Fatalf("protected content replayed without complete authorization dependencies: %s", encoded)
			}
		})
	}
}

func TestFilterPersistedEventsPreservesMixedHistoryOrder(t *testing.T) {
	authorization := testAuthorizationContext("sess_replay")
	allowed := testProtectedBinding(t, authorization, "mixed-allowed")
	denied := testProtectedBinding(t, authorization, "mixed-denied")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "first", nil),
		protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "allowed answer", nil, allowed),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "slash answer", map[string]string{"source": "slash"}),
		protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "denied tool", map[string]string{"tool": einotools.NameExplain}, denied),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "local tool", map[string]string{"tool": einotools.NameDiff}),
		protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "allowed tool", map[string]string{"tool": einotools.NameQuery}, allowed),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "last", nil),
	}
	manager := New(Dependencies{
		AuthorizationContextProvider: testAuthorizationContextProvider,
		ProtectedContentAuthorizer: func(_ context.Context, _ protocol.AuthorizationContext, binding protocol.ProtectedContentBinding) error {
			if binding.BlockID == denied.BlockID {
				return errors.New("denied")
			}
			return nil
		},
	})

	filtered := manager.filterPersistedEvents(context.Background(), authorization, events)
	assertEventMessages(t, filtered, []string{"first", "allowed answer", "/help", "slash answer", "local tool", "allowed tool", "last"})
}

func TestRuntimeStartAndSlashResumeReplayAuthorizedProtectedBlocks(t *testing.T) {
	for _, test := range []struct {
		name   string
		resume func(*Manager) ([]protocol.Event, error)
	}{
		{
			name: "startup",
			resume: func(manager *Manager) ([]protocol.Event, error) {
				return manager.Start(context.Background(), StartOptions{ResumeID: "sess_authorized"})
			},
		},
		{
			name: "slash",
			resume: func(manager *Manager) ([]protocol.Event, error) {
				if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
					return nil, err
				}
				return manager.SendMessage(context.Background(), "/resume sess_authorized"), nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			stored := local.New(workspace)
			authorization := testAuthorizationContext("sess_authorized")
			bindTestSessionAuthorization(t, stored, authorization)
			binding := testProtectedBinding(t, authorization, "resume")
			must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil)))
			must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "UNPROTECTED_SLASH_CANARY", map[string]string{"source": "slash"})))
			must(t, stored.Append(context.Background(), protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "BOUND_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}, binding)))
			must(t, stored.Append(context.Background(), protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "BOUND_ANSWER_CANARY", nil, binding)))
			calls := 0
			manager := New(Dependencies{
				Workspace: workspace,
				Sessions:  stored,
				EinoRunner: &fakeEinoRunner{events: []protocol.Event{
					protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil),
				}},
				AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
					current := testAuthorizationContext(sessionID)
					current.RequestID = "request-replay"
					return current, nil
				},
				ProtectedContentAuthorizer: func(_ context.Context, _ protocol.AuthorizationContext, got protocol.ProtectedContentBinding) error {
					calls++
					if got.BlockID != binding.BlockID {
						t.Fatalf("authorized block %q, want %q", got.BlockID, binding.BlockID)
					}
					return nil
				},
				NewSessionID: func() string { return "sess_current" },
			})
			events, err := test.resume(manager)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !hasMessage(events, protocol.EventAssistantDone, "UNPROTECTED_SLASH_CANARY") || !hasMessage(events, protocol.EventToolComplete, "BOUND_TOOL_CANARY") || !hasMessage(events, protocol.EventAssistantDone, "BOUND_ANSWER_CANARY") {
				t.Fatalf("protected resume = calls:%d events:%+v", calls, events)
			}
		})
	}
}

func TestRuntimeStartAndSlashResumeDropProtectedContentWhenAuthorizationUnavailable(t *testing.T) {
	for _, dependencyCase := range []struct {
		name     string
		provider bool
	}{
		{name: "provider nil"},
		{name: "authorizer nil", provider: true},
	} {
		for _, resumeCase := range []struct {
			name   string
			resume func(*Manager, string) ([]protocol.Event, error)
		}{
			{
				name: "startup",
				resume: func(manager *Manager, sessionID string) ([]protocol.Event, error) {
					return manager.Start(context.Background(), StartOptions{ResumeID: sessionID})
				},
			},
			{
				name: "slash",
				resume: func(manager *Manager, sessionID string) ([]protocol.Event, error) {
					if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
						return nil, err
					}
					return manager.SendMessage(context.Background(), "/resume "+sessionID), nil
				},
			},
		} {
			t.Run(dependencyCase.name+"/"+resumeCase.name, func(t *testing.T) {
				workspace := t.TempDir()
				stored := local.New(workspace)
				authorization := testAuthorizationContext("sess_unavailable")
				appendMixedReplayHistory(t, stored, authorization)
				deps := Dependencies{
					Workspace: workspace,
					Sessions:  stored,
					EinoRunner: &fakeEinoRunner{events: []protocol.Event{
						protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil),
					}},
					NewSessionID: func() string { return "sess_current" },
				}
				if dependencyCase.provider {
					bindTestSessionAuthorization(t, stored, authorization)
					deps.AuthorizationContextProvider = func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
						current := testAuthorizationContext(sessionID)
						current.RequestID = "request-replay"
						return current, nil
					}
				}

				events, err := resumeCase.resume(New(deps), authorization.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				assertMixedReplayHistory(t, events)
			})
		}
	}
}

func TestLoadHistoryDropsProtectedContentWhenAuthorizationUnavailable(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider bool
	}{
		{name: "provider nil"},
		{name: "authorizer nil", provider: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stored := local.New(t.TempDir())
			authorization := testAuthorizationContext("sess_history")
			appendMixedReplayHistory(t, stored, authorization)
			deps := Dependencies{Sessions: stored}
			ctx := context.Background()
			if test.provider {
				deps.AuthorizationContextProvider = testAuthorizationContextProvider
				var err error
				ctx, err = protocol.WithAuthorizationContext(ctx, authorization)
				if err != nil {
					t.Fatal(err)
				}
			}

			events := New(deps).loadHistory(ctx, authorization.SessionID)
			assertMixedReplayHistory(t, events)
		})
	}
}

func appendMixedReplayHistory(t *testing.T, stored local.Store, authorization protocol.AuthorizationContext) {
	t.Helper()
	binding := testProtectedBinding(t, authorization, "unavailable-integration")
	for _, event := range []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_STATUS_BEFORE", nil),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "SAFE_SLASH_RESPONSE", map[string]string{"source": "slash", "overlay": "help"}),
		protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "PROTECTED_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}, binding),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "SAFE_TOOL_SUMMARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "SAFE_USER_AFTER", nil),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_STATUS_AFTER", nil),
		protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "PROTECTED_ANSWER_CANARY", nil, binding),
	} {
		must(t, stored.Append(context.Background(), event))
	}
}

func assertMixedReplayHistory(t *testing.T, events []protocol.Event) {
	t.Helper()
	want := []string{"SAFE_STATUS_BEFORE", "/help", "SAFE_SLASH_RESPONSE", "SAFE_TOOL_SUMMARY", "SAFE_USER_AFTER", "SAFE_STATUS_AFTER"}
	next := 0
	for _, event := range events {
		if strings.HasPrefix(event.Message, "PROTECTED_") {
			t.Fatalf("protected history replayed without complete authorization dependencies: %+v", events)
		}
		if event.Message == "SAFE_SLASH_RESPONSE" {
			if event.ProtectedContent != nil || eventPayloadValue(event.Payload, "source") != "slash" {
				t.Fatalf("slash replay metadata changed: %+v", event)
			}
		}
		if next < len(want) && event.Message == want[next] {
			next++
		}
	}
	if next != len(want) {
		t.Fatalf("mixed replay order preserved %d/%d events, want %v: %+v", next, len(want), want, events)
	}
}

func testProtectedBinding(t *testing.T, authorization protocol.AuthorizationContext, source string) protocol.ProtectedContentBinding {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(authorization.TenantID, authorization.KnowledgeBaseID, protocol.ResourceDocument, "replay/"+source)
	if err != nil {
		t.Fatal(err)
	}
	resource := protocol.ResourceHandle{
		ResourceID: resourceID, Type: protocol.ResourceDocument,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		AuthorizationID: "document:" + string(resourceID), AuthorizationResourceID: resourceID,
		ContentDigest: protocol.NewContentDigest(source),
		Versions: protocol.ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
			Index: "index-v1", Graph: "graph-v1", Projection: "projection-v1",
		},
		ServingState: protocol.ServingActive,
	}
	binding, err := protocol.NewProtectedContentBindingFromResources(authorization.SessionID, authorization.RequestID, []protocol.ProtectedResourceBinding{{
		Resource: resource, AuthorizationResource: resource,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func protectedTestEvent(eventType protocol.EventType, sessionID, message string, payload any, binding protocol.ProtectedContentBinding) protocol.Event {
	event := protocol.NewEvent(eventType, sessionID, message, payload)
	event.CreatedAt = time.Unix(1, 0).UTC()
	event.ProtectedContent = &binding
	return event
}

func eventsText(events []protocol.Event) string {
	var builder strings.Builder
	for _, event := range events {
		builder.WriteString(event.Message)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func assertEventMessages(t *testing.T, events []protocol.Event, want []string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("event count = %d, want %d: %+v", len(events), len(want), events)
	}
	for i, message := range want {
		if events[i].Message != message {
			t.Fatalf("event %d message = %q, want %q: %+v", i, events[i].Message, message, events)
		}
	}
}
