package runtime

import (
	"context"
	"errors"
	"reflect"
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
		protocol.NewEvent(protocol.EventUserMessage, "sess_legacy", "/diff UNPERMISSIONED_DIFF_USER_CANARY", nil),
		protocol.NewEvent(protocol.EventToolStart, "sess_legacy", "UNPERMISSIONED_DIFF_START_CANARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventToolComplete, "sess_legacy", "UNPERMISSIONED_DIFF_COMPLETE_CANARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventVersionDiff, "sess_legacy", "UNPERMISSIONED_VERSION_DIFF_CANARY", map[string]string{"diff": "UNPERMISSIONED_VERSION_DIFF_CANARY"}),
		protocol.NewEvent(protocol.EventAssistantDone, "sess_legacy", "UNPERMISSIONED_DIFF_ANSWER_CANARY", map[string]string{"source": "slash", "tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventError, "sess_legacy", "legacy error", nil),
	}
	filtered := New(Dependencies{}).filterPersistedEvents(context.Background(), protocol.AuthorizationContext{}, events)
	if !reflect.DeepEqual(filtered, events) {
		t.Fatalf("non-permissioned replay changed: %+v", filtered)
	}
}

func TestFilterPersistedEventsPreservesOnlyPermissionedSafeSlashResponses(t *testing.T) {
	authorization := testAuthorizationContext("sess_replay")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "help response", map[string]string{"source": "slash", "overlay": "help"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/details", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "details response", map[string]any{"source": "slash", "overlay": "details"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/settings", nil),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "settings error", nil),
		protocol.NewEvent(protocol.EventSessionInfo, authorization.SessionID, "STALE_SESSION_INFO_CANARY", protocol.SessionInfo{Workspace: "STALE_WORKSPACE_CANARY"}),
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
		"protected legacy prompt",
	}
	assertEventMessages(t, filtered, want)
	if encoded := eventsText(filtered); strings.Contains(encoded, "STALE_") {
		t.Fatalf("permissioned replay retained stale session metadata: %s", encoded)
	}
}

func TestFilterPersistedEventsDropsCompleteHistoricalDiffTurnsInPermissionedReplay(t *testing.T) {
	authorization := testAuthorizationContext("sess_diff_turn")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_BEFORE_DIFF_CANARY", nil),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/diff FULL_DIFF_USER_CANARY", nil),
		protocol.NewEvent(protocol.EventToolStart, authorization.SessionID, "FULL_DIFF_TOOL_START_CANARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventToolProgress, authorization.SessionID, "FULL_DIFF_TOOL_PROGRESS_CANARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "FULL_DIFF_TOOL_COMPLETE_CANARY", map[string]any{"tool": einotools.NameDiff, "result": "FULL_DIFF_RESULT_CANARY"}),
		protocol.NewEvent(protocol.EventVersionDiff, authorization.SessionID, "FULL_VERSION_DIFF_CANARY", map[string]string{"diff": "FULL_VERSION_DIFF_PAYLOAD_CANARY"}),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "FULL_DIFF_SLASH_COMPLETION_CANARY", map[string]string{"source": "slash", "tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/diff FULL_DIFF_ERROR_USER_CANARY", nil),
		protocol.NewEvent(protocol.EventToolStart, authorization.SessionID, "FULL_DIFF_ERROR_START_CANARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventToolError, authorization.SessionID, "FULL_DIFF_TOOL_ERROR_CANARY", map[string]string{"tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "FULL_DIFF_SLASH_ERROR_CANARY", map[string]string{"source": "slash"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/different", nil),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "SAFE_NEAR_MATCH_SLASH_CANARY", nil),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "SAFE_HELP_AFTER_DIFF_CANARY", map[string]string{"source": "slash"}),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_AFTER_DIFF_CANARY", nil),
	}
	manager := New(Dependencies{AuthorizationContextProvider: testAuthorizationContextProvider})

	filtered := manager.filterPersistedEvents(context.Background(), authorization, events)
	assertEventMessages(t, filtered, []string{
		"SAFE_BEFORE_DIFF_CANARY",
		"/help", "SAFE_HELP_AFTER_DIFF_CANARY",
		"SAFE_AFTER_DIFF_CANARY",
	})
	encoded := eventsText(filtered)
	for _, canary := range []string{
		"FULL_DIFF_USER_CANARY",
		"FULL_DIFF_TOOL_START_CANARY",
		"FULL_DIFF_TOOL_PROGRESS_CANARY",
		"FULL_DIFF_TOOL_COMPLETE_CANARY",
		"FULL_DIFF_RESULT_CANARY",
		"FULL_VERSION_DIFF_CANARY",
		"FULL_VERSION_DIFF_PAYLOAD_CANARY",
		"FULL_DIFF_SLASH_COMPLETION_CANARY",
		"FULL_DIFF_ERROR_USER_CANARY",
		"FULL_DIFF_ERROR_START_CANARY",
		"FULL_DIFF_TOOL_ERROR_CANARY",
		"FULL_DIFF_SLASH_ERROR_CANARY",
	} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("permissioned replay retained complete /diff canary %q: %s", canary, encoded)
		}
	}
}

func TestFilterPersistedEventsDropsOrphanedHistoricalDiffArtifactsBeforeSlashPreservation(t *testing.T) {
	authorization := testAuthorizationContext("sess_orphaned_diff")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_BEFORE_ORPHANS_CANARY", nil),
		protocol.NewEvent(protocol.EventToolStart, authorization.SessionID, "ORPHAN_DIFF_START_CANARY", map[string]string{"source": "slash", "tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventToolProgress, authorization.SessionID, "ORPHAN_DIFF_PROGRESS_CANARY", map[string]string{"source": "slash", "tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "ORPHAN_DIFF_COMPLETE_CANARY", map[string]string{
			"source":       "slash",
			"tool":         einotools.NameDiff,
			"replay_class": SafeToolAssistantReplayClassV1,
		}),
		protocol.NewEvent(protocol.EventVersionDiff, authorization.SessionID, "ORPHAN_VERSION_DIFF_CANARY", map[string]string{"source": "slash", "diff": "ORPHAN_VERSION_PAYLOAD_CANARY"}),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "ORPHAN_DIFF_COMPLETION_CANARY", map[string]string{
			"source":       "slash",
			"tool":         einotools.NameDiff,
			"replay_class": SafeToolAssistantReplayClassV1,
		}),
		protocol.NewEvent(protocol.EventToolError, authorization.SessionID, "ORPHAN_DIFF_TOOL_ERROR_CANARY", map[string]string{"source": "slash", "tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventError, authorization.SessionID, "ORPHAN_DIFF_SLASH_ERROR_CANARY", map[string]string{"source": "slash", "tool": einotools.NameDiff}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "/help", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "SAFE_HELP_AFTER_ORPHANS_CANARY", map[string]string{"source": "slash"}),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_AFTER_ORPHANS_CANARY", nil),
	}
	manager := New(Dependencies{AuthorizationContextProvider: testAuthorizationContextProvider})

	filtered := manager.filterPersistedEvents(context.Background(), authorization, events)
	assertEventMessages(t, filtered, []string{
		"SAFE_BEFORE_ORPHANS_CANARY",
		"/help", "SAFE_HELP_AFTER_ORPHANS_CANARY",
		"SAFE_AFTER_ORPHANS_CANARY",
	})
	encoded := eventsText(filtered)
	for _, canary := range []string{
		"ORPHAN_DIFF_START_CANARY",
		"ORPHAN_DIFF_PROGRESS_CANARY",
		"ORPHAN_DIFF_COMPLETE_CANARY",
		"ORPHAN_VERSION_DIFF_CANARY",
		"ORPHAN_VERSION_PAYLOAD_CANARY",
		"ORPHAN_DIFF_COMPLETION_CANARY",
		"ORPHAN_DIFF_TOOL_ERROR_CANARY",
		"ORPHAN_DIFF_SLASH_ERROR_CANARY",
	} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("permissioned replay retained orphaned /diff canary %q: %s", canary, encoded)
		}
	}
}

func TestFilterPersistedEventsRejectsHistoricalSafeToolAssistantClass(t *testing.T) {
	authorization := testAuthorizationContext("sess_safe_class")
	binding := testProtectedBinding(t, authorization, "mixed-forgery")
	classified := func(event protocol.Event) protocol.Event {
		payload, _ := event.Payload.(map[string]string)
		if payload == nil {
			payload = map[string]string{}
		}
		payload["replay_class"] = "safe-tool-assistant/v1"
		event.Payload = payload
		return event
	}
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "safe prompt", nil),
		classified(protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "safe tool", map[string]string{"tool": einotools.NameVersions})),
		classified(protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "safe answer", nil)),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "naked forgery", nil),
		classified(protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "FORGED_NAKED_ANSWER_CANARY", nil)),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "terminal forgery", nil),
		classified(protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "terminal safe tool", map[string]string{"tool": einotools.NameVersions})),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "UNCLASSIFIED_TERMINAL_CANARY", nil),
		classified(protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "FORGED_AFTER_TERMINAL_CANARY", nil)),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "permissioned forgery", nil),
		classified(protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "FORGED_QUERY_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery})),
		classified(protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "FORGED_QUERY_ANSWER_CANARY", nil)),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "mixed forgery", nil),
		classified(protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "mixed safe tool", map[string]string{"tool": einotools.NameVersions})),
		protectedTestEvent(protocol.EventToolComplete, authorization.SessionID, "allowed protected tool", map[string]string{"tool": einotools.NameQuery}, binding),
		classified(protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "FORGED_MIXED_ANSWER_CANARY", nil)),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "malformed class", nil),
		classified(protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "malformed safe tool", map[string]string{"tool": einotools.NameVersions})),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "MALFORMED_CLASS_ANSWER_CANARY", map[string]string{"replay_class": "safe-tool-assistant/v2"}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "legacy permissioned prompt", nil),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "LEGACY_QUERY_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "LEGACY_QUERY_ANSWER_CANARY", nil),
	}
	manager := New(Dependencies{
		AuthorizationContextProvider: testAuthorizationContextProvider,
		ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			return nil
		},
	})

	filtered := manager.filterPersistedEvents(context.Background(), authorization, events)
	if !hasMessage(filtered, protocol.EventToolComplete, "allowed protected tool") {
		t.Fatalf("authorized protected content was dropped: %+v", filtered)
	}
	encoded := eventsText(filtered)
	for _, canary := range []string{
		"safe tool",
		"safe answer",
		"FORGED_NAKED_ANSWER_CANARY",
		"UNCLASSIFIED_TERMINAL_CANARY",
		"FORGED_AFTER_TERMINAL_CANARY",
		"FORGED_QUERY_TOOL_CANARY",
		"FORGED_QUERY_ANSWER_CANARY",
		"FORGED_MIXED_ANSWER_CANARY",
		"MALFORMED_CLASS_ANSWER_CANARY",
		"LEGACY_QUERY_TOOL_CANARY",
		"LEGACY_QUERY_ANSWER_CANARY",
	} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("replay accepted %q: %s", canary, encoded)
		}
	}
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
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "safe tool summary", map[string]string{"tool": einotools.NameVersions}),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "after", nil),
	}

	for _, test := range []struct {
		name string
		deps Dependencies
		want []string
	}{
		{name: "provider missing", deps: Dependencies{}, want: []string{"before", "/help", "safe slash response", "safe tool summary", "after"}},
		{
			name: "provider missing with authorizer configured",
			deps: Dependencies{ProtectedContentAuthorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
				t.Fatal("authorizer called without an authorization context provider")
				return nil
			}},
			want: []string{"before", "/help", "safe slash response", "safe tool summary", "after"},
		},
		{
			name: "authorizer missing", deps: Dependencies{AuthorizationContextProvider: testAuthorizationContextProvider},
			want: []string{"before", "/help", "safe slash response", "after"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			filtered := New(test.deps).filterPersistedEvents(context.Background(), authorization, events)
			assertEventMessages(t, filtered, test.want)
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
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "local tool", map[string]string{"tool": einotools.NameVersions}),
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
	assertEventMessages(t, filtered, []string{"first", "allowed answer", "/help", "slash answer", "allowed tool", "last"})
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
				assertMixedReplayHistory(t, events, dependencyCase.provider)
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
			assertMixedReplayHistory(t, events, test.provider)
		})
	}
}

func TestHistoricalSafeToolAssistantIsDroppedFromPermissionedReplay(t *testing.T) {
	for _, test := range []struct {
		name   string
		replay func(*Manager, context.Context, string) ([]protocol.Event, error)
	}{
		{
			name: "load history",
			replay: func(manager *Manager, ctx context.Context, sessionID string) ([]protocol.Event, error) {
				return manager.loadHistory(ctx, sessionID), nil
			},
		},
		{
			name: "startup resume",
			replay: func(manager *Manager, _ context.Context, sessionID string) ([]protocol.Event, error) {
				return manager.Start(context.Background(), StartOptions{ResumeID: sessionID})
			},
		},
		{
			name: "slash resume",
			replay: func(manager *Manager, _ context.Context, sessionID string) ([]protocol.Event, error) {
				if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
					return nil, err
				}
				return manager.SendMessage(context.Background(), "/resume "+sessionID), nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			stored := local.New(workspace)
			authorization := testAuthorizationContext("sess_safe_integration")
			bindTestSessionAuthorization(t, stored, authorization)
			appendSafeToolAndLegacyHistory(t, stored, authorization)
			ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
			if err != nil {
				t.Fatal(err)
			}
			manager := New(Dependencies{
				Workspace: workspace,
				Sessions:  stored,
				EinoRunner: &fakeEinoRunner{events: []protocol.Event{
					protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "ready", nil),
				}},
				AuthorizationContextProvider: testAuthorizationContextProvider,
				NewSessionID:                 func() string { return "sess_current" },
			})

			events, err := test.replay(manager, ctx, authorization.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			encoded := eventsText(events)
			for _, canary := range []string{
				"SAFE_CLASSIFIED_TOOL_CANARY", "SAFE_CLASSIFIED_ANSWER_CANARY",
				"LEGACY_PERMISSIONED_TOOL_CANARY", "LEGACY_PERMISSIONED_ANSWER_CANARY", "FORGED_STANDALONE_ANSWER_CANARY",
			} {
				if strings.Contains(encoded, canary) {
					t.Fatalf("persisted replay leaked %q: %s", canary, encoded)
				}
			}
		})
	}
}

func appendSafeToolAndLegacyHistory(t *testing.T, stored local.Store, authorization protocol.AuthorizationContext) {
	t.Helper()
	for _, event := range []protocol.Event{
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "safe prompt", nil),
		protocol.NewEvent(protocol.EventAssistantStart, authorization.SessionID, "eino runner started", nil),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "SAFE_CLASSIFIED_TOOL_CANARY", map[string]string{
			"tool":         einotools.NameVersions,
			"replay_class": "safe-tool-assistant/v1",
		}),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "SAFE_CLASSIFIED_ANSWER_CANARY", map[string]string{
			"replay_class": "safe-tool-assistant/v1",
		}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "legacy permissioned prompt", nil),
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "LEGACY_PERMISSIONED_TOOL_CANARY", map[string]string{"tool": einotools.NameQuery}),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "LEGACY_PERMISSIONED_ANSWER_CANARY", nil),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "forged standalone prompt", nil),
		protocol.NewEvent(protocol.EventAssistantDone, authorization.SessionID, "FORGED_STANDALONE_ANSWER_CANARY", map[string]string{
			"replay_class": "safe-tool-assistant/v1",
		}),
	} {
		must(t, stored.Append(context.Background(), event))
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
		protocol.NewEvent(protocol.EventToolComplete, authorization.SessionID, "SAFE_TOOL_SUMMARY", map[string]string{"tool": einotools.NameVersions}),
		protocol.NewEvent(protocol.EventUserMessage, authorization.SessionID, "SAFE_USER_AFTER", nil),
		protocol.NewEvent(protocol.EventStatusUpdate, authorization.SessionID, "SAFE_STATUS_AFTER", nil),
		protectedTestEvent(protocol.EventAssistantDone, authorization.SessionID, "PROTECTED_ANSWER_CANARY", nil, binding),
	} {
		must(t, stored.Append(context.Background(), event))
	}
}

func assertMixedReplayHistory(t *testing.T, events []protocol.Event, permissioned bool) {
	t.Helper()
	want := []string{"SAFE_STATUS_BEFORE", "/help", "SAFE_SLASH_RESPONSE"}
	if !permissioned {
		want = append(want, "SAFE_TOOL_SUMMARY")
	}
	want = append(want, "SAFE_USER_AFTER", "SAFE_STATUS_AFTER")
	next := 0
	for _, event := range events {
		if strings.HasPrefix(event.Message, "PROTECTED_") || permissioned && event.Message == "SAFE_TOOL_SUMMARY" {
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
