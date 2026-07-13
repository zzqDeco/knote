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
			if calls != 1 || !hasMessage(events, protocol.EventToolComplete, "BOUND_TOOL_CANARY") || !hasMessage(events, protocol.EventAssistantDone, "BOUND_ANSWER_CANARY") {
				t.Fatalf("protected resume = calls:%d events:%+v", calls, events)
			}
		})
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
