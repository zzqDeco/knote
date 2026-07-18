package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestRuntimeStartSendConfirmAndSubscribe(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	rt, err := newTestRuntime(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	var emitted []protocol.Event
	unsubscribe := rt.Subscribe(func(events []protocol.Event) {
		emitted = append(emitted, events...)
	})
	initial, err := rt.Start(context.Background(), StartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(initial, protocol.EventSessionInfo) || rt.SessionID() == "" {
		t.Fatalf("runtime did not start session: events=%+v session=%q", initial, rt.SessionID())
	}

	buildEvents := rt.SendMessage(context.Background(), "/build")
	confirm := firstConfirm(t, buildEvents)
	buildEvents = rt.Confirm(context.Background(), confirm, true)
	if !hasEvent(buildEvents, protocol.EventBuildComplete) {
		t.Fatalf("runtime build did not complete: %+v", buildEvents)
	}
	if len(emitted) == 0 {
		t.Fatal("runtime subscriber did not receive events")
	}
	unsubscribe()
	before := len(emitted)
	_ = rt.SendMessage(context.Background(), "/status")
	if len(emitted) != before {
		t.Fatal("runtime subscriber received events after unsubscribe")
	}
}

func TestRuntimeWorkspaceStatusAndEinoControls(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	rt, err := newTestRuntime(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	status, err := rt.WorkspaceStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Branch == "" {
		t.Fatalf("workspace status did not include branch: %+v", status)
	}
	if !hasEvent(rt.Interrupt(context.Background()), protocol.EventStatusUpdate) {
		t.Fatal("interrupt should emit a status event in Eino-only runtime")
	}
	if !hasEvent(rt.StopTask(context.Background(), "task_1"), protocol.EventStatusUpdate) {
		t.Fatal("stop task should emit a status event in Eino-only runtime")
	}
	if !hasEvent(rt.StopTask(context.Background(), ""), protocol.EventError) {
		t.Fatal("stop task without id should emit an error")
	}
}

func TestRuntimeRunnerInfoIncludesEinoInventory(t *testing.T) {
	rt := New(Dependencies{
		Workspace:    "/tmp/knote-test",
		EinoRunner:   &fakeEinoRunner{tools: []RunnerToolInfo{{Name: "knote_query", Description: "query knowledge"}}},
		NewSessionID: local.NewSessionID,
	})
	info, err := rt.RunnerInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ConfiguredMode != RunnerModeEino || info.ActiveMode != RunnerModeEino {
		t.Fatalf("unexpected runner modes: %+v", info)
	}
	if !info.EinoAvailable {
		t.Fatalf("expected Eino runner to be available: %+v", info)
	}
	if len(info.Tools) != 1 || info.Tools[0].Name != "knote_query" {
		t.Fatalf("unexpected tool inventory: %+v", info.Tools)
	}
}

func TestPermissionedRuntimeRedactsObservableSurfaces(t *testing.T) {
	const (
		workspaceCanary = "/private/workspaces/permissioned-canary"
		branchCanary    = "private-branch-canary"
		toolCanary      = "private-tool-canary"
	)
	store := local.New(t.TempDir())
	versions := &observableVersionsProbe{status: repository.Status{
		Branch: branchCanary,
		Dirty:  true,
		Raw:    workspaceCanary,
	}}
	runner := &fakeEinoRunner{
		tools:  []RunnerToolInfo{{Name: toolCanary, Description: workspaceCanary}},
		events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "unused", nil)},
	}
	rt := New(Dependencies{
		Workspace:    workspaceCanary,
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     store,
		Versions:     versions,
		EinoRunner:   runner,
		NewSessionID: func() string { return "sess_permissioned_observables" },
	})
	initial, err := rt.Start(context.Background(), StartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if versions.statusCalls != 0 {
		t.Fatalf("permissioned start queried workspace status %d time(s)", versions.statusCalls)
	}
	for _, event := range initial {
		if event.Type != protocol.EventSessionInfo {
			continue
		}
		info, ok := event.Payload.(protocol.SessionInfo)
		if !ok || info.Workspace != "" || info.Branch != "" || info.Dirty || info.KAGMode != "" {
			t.Fatalf("permissioned session event leaked observables: %+v", event.Payload)
		}
	}

	status, err := rt.WorkspaceStatus(context.Background())
	if err != nil || status != (repository.Status{}) || versions.statusCalls != 0 {
		t.Fatalf("permissioned workspace status = %+v, err=%v, calls=%d", status, err, versions.statusCalls)
	}
	info := rt.CurrentSessionInfo(context.Background())
	if info.ID != "sess_permissioned_observables" || info.Workspace != "" || info.Branch != "" || info.Dirty || info.KAGMode != "" {
		t.Fatalf("permissioned current session info = %+v", info)
	}
	if got := rt.Workspace(); got != "" {
		t.Fatalf("permissioned workspace accessor = %q", got)
	}
	runnerInfo, err := rt.RunnerInfo(context.Background())
	if err != nil || len(runnerInfo.Tools) != 0 || runner.inventoryCalls != 0 {
		t.Fatalf("permissioned runner info = %+v, err=%v, inventory calls=%d", runnerInfo, err, runner.inventoryCalls)
	}
	if !runnerInfo.EinoAvailable || runnerInfo.ConfiguredMode != RunnerModeEino || runnerInfo.ActiveMode != RunnerModeEino {
		t.Fatalf("permissioned runner info lost fixed availability shape: %+v", runnerInfo)
	}
	encoded := fmt.Sprint(initial, status, info, runnerInfo)
	for _, canary := range []string{workspaceCanary, branchCanary, toolCanary} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("permissioned observable surfaces leaked %q: %s", canary, encoded)
		}
	}
}

func TestPermissionedRuntimeHidesAuthorizationProviderFailures(t *testing.T) {
	const providerCanary = "PRIVATE_AUTH_PROVIDER_PATH_CANARY"
	runner := &fakeEinoRunner{events: []protocol.Event{
		protocol.NewEvent(protocol.EventAssistantDone, "", "unused", nil),
	}}
	rt := New(Dependencies{
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     local.New(t.TempDir()),
		EinoRunner:   runner,
		AuthorizationContextProvider: func(context.Context, string) (protocol.AuthorizationContext, error) {
			return protocol.AuthorizationContext{}, errors.New(providerCanary)
		},
		NewSessionID: func() string { return "sess_permissioned_provider_failure" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "protected request")
	if !hasMessage(events, protocol.EventError, sessionAuthorizationErrorMessage) {
		t.Fatalf("permissioned provider failure shape = %+v", events)
	}
	if strings.Contains(fmt.Sprint(events), providerCanary) {
		t.Fatalf("permissioned provider failure leaked backend details: %+v", events)
	}
	if runner.runCalls != 0 {
		t.Fatalf("permissioned provider failure reached runner %d time(s)", runner.runCalls)
	}
}

func TestRuntimeEinoModeStartsAndSendsThroughBridge(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	einoRunner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "hello from eino", nil)}}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		EinoRunner:   einoRunner,
		NewSessionID: func() string { return "sess_eino" },
	})
	initial, err := rt.Start(context.Background(), StartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(initial, protocol.EventSessionInfo) || rt.SessionID() != "sess_eino" {
		t.Fatalf("runtime did not start Eino session: events=%+v session=%q", initial, rt.SessionID())
	}
	events := rt.SendMessage(context.Background(), "hello")
	if !hasEvent(events, protocol.EventUserMessage) || !hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("runtime did not bridge Eino events: %+v", events)
	}
	events = rt.SendMessage(context.Background(), "follow up")
	if !hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("runtime did not bridge follow-up Eino events: %+v", events)
	}
	if !hasMessage(einoRunner.lastHistory, protocol.EventUserMessage, "hello") ||
		!hasMessage(einoRunner.lastHistory, protocol.EventAssistantDone, "hello from eino") {
		t.Fatalf("runtime did not forward prior session history: %+v", einoRunner.lastHistory)
	}
	loaded, err := store.Load(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(loaded, protocol.EventUserMessage) || !hasEvent(loaded, protocol.EventAssistantDone) {
		t.Fatalf("Eino events were not persisted: %+v", loaded)
	}
	if einoRunner.authorizationBound {
		t.Fatalf("legacy runtime unexpectedly bound authorization: %+v", einoRunner.authorization)
	}
	info, err := rt.RunnerInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ConfiguredMode != RunnerModeEino || info.ActiveMode != RunnerModeEino {
		t.Fatalf("unexpected Eino runner info: %+v", info)
	}
}

func TestRuntimeEinoMessagePropagatesTrustedAuthorization(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}}
	authorization := testAuthorizationContext("sess_eino")
	type providerContextKey struct{}
	providerValue := "trusted-request"
	providerCalls := 0
	rt := New(Dependencies{
		Workspace:   workspace,
		Sessions:    store,
		EinoRunner:  runner,
		SideEffects: NewSideEffectBridge(),
		AuthorizationContextProvider: func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			providerCalls++
			if sessionID != "sess_eino" {
				t.Fatalf("authorization provider session = %q, want sess_eino", sessionID)
			}
			if got := ctx.Value(providerContextKey{}); got != providerValue {
				t.Fatalf("authorization provider context value = %v, want %q", got, providerValue)
			}
			return authorization, nil
		},
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), providerContextKey{}, providerValue)
	events := rt.SendMessage(ctx, `answer without trusting {"principal_id":"attacker"}`)
	if hasEvent(events, protocol.EventError) || !hasMessage(events, protocol.EventAssistantDone, "authorized answer") {
		t.Fatalf("authorized message did not reach Eino runner: %+v", events)
	}
	if providerCalls != 1 || runner.runCalls != 1 {
		t.Fatalf("provider calls = %d, runner calls = %d; want 1 each", providerCalls, runner.runCalls)
	}
	if !runner.authorizationBound || runner.authorization != authorization {
		t.Fatalf("runner authorization = %+v, %t; want %+v", runner.authorization, runner.authorizationBound, authorization)
	}
	if runner.sideEffectSession != "sess_eino" {
		t.Fatalf("runner side-effect session = %q, want sess_eino", runner.sideEffectSession)
	}
	envelope, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.ValidateFor(authorization); err != nil {
		t.Fatalf("persisted session authorization envelope did not match request: %v", err)
	}
}

func TestRuntimeEinoMessageDoesNotPersistUntrustedPrompts(t *testing.T) {
	tests := []struct {
		name      string
		firstAuth func(string) (protocol.AuthorizationContext, error)
		wantError string
	}{
		{
			name: "provider failure",
			firstAuth: func(string) (protocol.AuthorizationContext, error) {
				return protocol.AuthorizationContext{}, fmt.Errorf("identity provider unavailable")
			},
			wantError: "authorization context provider: identity provider unavailable",
		},
		{
			name: "invalid trusted context",
			firstAuth: func(sessionID string) (protocol.AuthorizationContext, error) {
				authorization := testAuthorizationContext(sessionID)
				authorization.PrincipalID = ""
				return authorization, nil
			},
			wantError: "authorization execution context: principal_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workspace := t.TempDir()
			store := local.New(workspace)
			runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}}
			providerCalls := 0
			rt := New(Dependencies{
				Workspace:  workspace,
				Sessions:   store,
				EinoRunner: runner,
				AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
					providerCalls++
					if providerCalls == 1 {
						return tt.firstAuth(sessionID)
					}
					authorization := testAuthorizationContext(sessionID)
					authorization.RequestID = fmt.Sprintf("request-%d", providerCalls)
					return authorization, nil
				},
				NewSessionID: func() string { return "sess_eino" },
			})
			if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
				t.Fatal(err)
			}

			events := rt.SendMessage(context.Background(), "untrusted prompt")
			if runner.runCalls != 0 {
				t.Fatalf("Eino runner called %d times after authorization failure", runner.runCalls)
			}
			if !hasMessage(events, protocol.EventError, tt.wantError) {
				t.Fatalf("authorization failure was not surfaced: %+v", events)
			}
			persisted, err := store.Load(context.Background(), "sess_eino")
			if err != nil {
				t.Fatal(err)
			}
			if hasMessage(persisted, protocol.EventUserMessage, "untrusted prompt") {
				t.Fatalf("untrusted prompt was persisted: %+v", persisted)
			}

			events = rt.SendMessage(context.Background(), "authorized prompt")
			if hasEvent(events, protocol.EventError) || runner.runCalls != 1 {
				t.Fatalf("subsequent authorized request failed: %+v", events)
			}
			if hasMessage(runner.lastHistory, protocol.EventUserMessage, "untrusted prompt") {
				t.Fatalf("untrusted prompt reached later authorized history: %+v", runner.lastHistory)
			}
		})
	}
}

func TestRuntimeEinoMessageFailsClosedWithoutPermissionedSessionStorage(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     sessionsOnlyStore{Sessions: stored},
		EinoRunner:                   runner,
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "protected prompt")
	if !hasMessage(events, protocol.EventError, sessionAuthorizationErrorMessage) {
		t.Fatalf("missing permissioned session storage error = %+v", events)
	}
	if runner.runCalls != 0 {
		t.Fatalf("runner called %d times without durable session authorization", runner.runCalls)
	}
	persisted, err := stored.Load(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if hasMessage(persisted, protocol.EventUserMessage, "protected prompt") {
		t.Fatalf("protected prompt persisted without durable session authorization: %+v", persisted)
	}
}

func TestRuntimePermissionedSlashBindsAuthorizationBeforePersisting(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}},
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "/help")
	if hasEvent(events, protocol.EventError) || !hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("permissioned slash command failed: %+v", events)
	}
	envelope, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.ValidateFor(testAuthorizationContext("sess_eino")); err != nil {
		t.Fatalf("permissioned slash envelope mismatch: %v", err)
	}
	persisted, err := store.Load(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if !hasMessage(persisted, protocol.EventUserMessage, "/help") {
		t.Fatalf("slash command was not persisted after authorization bind: %+v", persisted)
	}
}

func TestRuntimeEinoSessionRejectsAuthorizationBindingChangesBeforeHistoryOrRunner(t *testing.T) {
	workspace := t.TempDir()
	store := &trackingSessionStore{Sessions: local.New(workspace)}
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}}
	sessionIDs := []string{"sess_first", "sess_second"}
	nextSession := 0
	firstSessionRequests := 0
	rt := New(Dependencies{
		Workspace:  workspace,
		Sessions:   store,
		EinoRunner: runner,
		NewSessionID: func() string {
			sessionID := sessionIDs[nextSession]
			nextSession++
			return sessionID
		},
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			authorization := testAuthorizationContext(sessionID)
			if sessionID == "sess_first" {
				firstSessionRequests++
				authorization.RequestID = fmt.Sprintf("request-%d", firstSessionRequests)
				if firstSessionRequests == 3 {
					authorization.PrincipalID = "other-user"
				}
			} else {
				authorization.RequestID = "request-new-session"
				authorization.PrincipalID = "other-user"
			}
			return authorization, nil
		},
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"first", "same binding, new request id"} {
		if events := rt.SendMessage(context.Background(), message); hasEvent(events, protocol.EventError) {
			t.Fatalf("authorized request %q failed: %+v", message, events)
		}
	}

	loadCalls := store.loadCalls
	runCalls := runner.runCalls
	events := rt.SendMessage(context.Background(), "cross-principal request")
	if !hasMessage(events, protocol.EventError, `authorization context changed for live session "sess_first"`) {
		t.Fatalf("authorization binding change was not rejected: %+v", events)
	}
	if store.loadCalls != loadCalls {
		t.Fatalf("history loads = %d after binding rejection, want %d", store.loadCalls, loadCalls)
	}
	if runner.runCalls != runCalls {
		t.Fatalf("runner calls = %d after binding rejection, want %d", runner.runCalls, runCalls)
	}
	persisted, err := store.Sessions.Load(context.Background(), "sess_first")
	if err != nil {
		t.Fatal(err)
	}
	if hasMessage(persisted, protocol.EventUserMessage, "cross-principal request") {
		t.Fatalf("rejected request was persisted into the bound session: %+v", persisted)
	}

	_ = rt.SendMessage(context.Background(), "/new")
	events = rt.SendMessage(context.Background(), "new principal, new session")
	if hasEvent(events, protocol.EventError) || !hasMessage(events, protocol.EventAssistantDone, "authorized answer") {
		t.Fatalf("/new did not reset the authorization binding: %+v", events)
	}
}

func TestRuntimeExplicitlyRebindsConfirmedArtifactScopeChanges(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}}
	current := testAuthorizationContext("sess_eino")
	rt := New(Dependencies{
		Workspace:    workspace,
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     store,
		EinoRunner:   runner,
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			authorization := current
			authorization.SessionID = sessionID
			return authorization, nil
		},
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	if events := rt.SendMessage(context.Background(), "before scope change"); hasEvent(events, protocol.EventError) {
		t.Fatalf("initial authorization failed: %+v", events)
	}

	expected := current
	expectedEnvelope, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	rebindCtx, err := protocol.WithAuthorizationContext(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	rebindCtx = withExpectedSessionAuthorizationEnvelope(rebindCtx, expectedEnvelope)
	current.TenantID = "tenant-v2"
	current.KnowledgeBaseID = "knowledge-v2"
	current.ACLWatermark = "acl-v2"
	current.RequestID = "request-2"
	if err := rt.RebindSessionAuthorization(rebindCtx, "sess_eino"); err != nil {
		t.Fatalf("explicit scope rebind failed: %v", err)
	}
	if events := rt.SendMessage(context.Background(), "after scope change"); hasEvent(events, protocol.EventError) {
		t.Fatalf("request after explicit scope rebind failed: %+v", events)
	}
	envelope, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.ValidateFor(current); err != nil {
		t.Fatalf("persisted scope rebind does not match provider: %v", err)
	}
	current.ACLWatermark = "acl-v3"
	current.RequestID = "request-3"
	if err := rt.RebindSessionAuthorization(rebindCtx, "sess_eino"); err == nil {
		t.Fatal("stale confirmed authorization rebound an already transitioned session")
	}
	current.ACLWatermark = "acl-v2"
	current.RequestID = "request-2"

	resumed := New(Dependencies{
		Workspace:                    workspace,
		Capabilities:                 PermissionedSessionCapabilityProfile(),
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: rt.deps.AuthorizationContextProvider,
		NewSessionID:                 func() string { return "unused" },
	})
	if _, err := resumed.Start(context.Background(), StartOptions{ResumeID: "sess_eino"}); err != nil {
		t.Fatalf("resume after scope rebind failed: %v", err)
	}
}

func TestRuntimeExplicitScopeRebindRejectsIdentityChanges(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	current := testAuthorizationContext("sess_eino")
	rt := New(Dependencies{
		Workspace:    workspace,
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     store,
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}},
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			authorization := current
			authorization.SessionID = sessionID
			return authorization, nil
		},
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	if events := rt.SendMessage(context.Background(), "bind session"); hasEvent(events, protocol.EventError) {
		t.Fatalf("initial authorization failed: %+v", events)
	}
	original, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	expected := current
	rebindCtx, err := protocol.WithAuthorizationContext(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	rebindCtx = withExpectedSessionAuthorizationEnvelope(rebindCtx, original)
	current.PrincipalID = "other-user"
	current.RequestID = "request-2"
	if err := rt.RebindSessionAuthorization(rebindCtx, "sess_eino"); err == nil {
		t.Fatal("explicit scope rebind accepted an identity change")
	}
	loaded, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != original {
		t.Fatalf("rejected identity change replaced envelope: got %+v want %+v", loaded, original)
	}
}

func TestRuntimeNoopScopeRebindStillRequiresDurableEnvelope(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	current := testAuthorizationContext("sess_eino")
	rt := New(Dependencies{
		Workspace:    workspace,
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     store,
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}},
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			authorization := current
			authorization.SessionID = sessionID
			return authorization, nil
		},
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	if events := rt.SendMessage(context.Background(), "bind session"); hasEvent(events, protocol.EventError) {
		t.Fatalf("initial authorization failed: %+v", events)
	}
	expectedEnvelope, err := store.LoadAuthorization(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	rebindCtx, err := protocol.WithAuthorizationContext(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}
	rebindCtx = withExpectedSessionAuthorizationEnvelope(rebindCtx, expectedEnvelope)
	if err := os.Remove(filepath.Join(workspace, ".knote", "sessions", "sess_eino.authorization.json")); err != nil {
		t.Fatal(err)
	}
	if err := rt.RebindSessionAuthorization(rebindCtx, "sess_eino"); err == nil {
		t.Fatal("no-op scope rebind succeeded without a durable envelope")
	}
}

func TestRuntimeNewSessionBypassesStaleLiveAuthorizationWithoutPersistingToOldSession(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "authorized answer", nil)}}
	sessionIDs := []string{"sess_first", "sess_second"}
	nextSession := 0
	providerCalls := map[string]int{}
	rt := New(Dependencies{
		Workspace:  workspace,
		Sessions:   store,
		EinoRunner: runner,
		NewSessionID: func() string {
			sessionID := sessionIDs[nextSession]
			nextSession++
			return sessionID
		},
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			providerCalls[sessionID]++
			authorization := testAuthorizationContext(sessionID)
			if sessionID == "sess_first" && providerCalls[sessionID] > 1 {
				authorization.ACLWatermark = "acl-v2"
			}
			if sessionID == "sess_second" {
				authorization.ACLWatermark = "acl-v2"
			}
			return authorization, nil
		},
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	if events := rt.SendMessage(context.Background(), "first message"); hasEvent(events, protocol.EventError) {
		t.Fatalf("first authorized message failed: %+v", events)
	}
	events := rt.SendMessage(context.Background(), "/new")
	if hasEvent(events, protocol.EventError) || rt.SessionID() != "sess_second" {
		t.Fatalf("/new did not escape stale session binding: session=%q events=%+v", rt.SessionID(), events)
	}
	if providerCalls["sess_first"] != 1 {
		t.Fatalf("/new consulted stale session authorization %d times", providerCalls["sess_first"])
	}
	persisted, err := store.Load(context.Background(), "sess_first")
	if err != nil {
		t.Fatal(err)
	}
	if hasMessage(persisted, protocol.EventUserMessage, "/new") {
		t.Fatalf("/new was persisted into stale session history: %+v", persisted)
	}
	events = rt.SendMessage(context.Background(), "new session message")
	if hasEvent(events, protocol.EventError) || !hasMessage(events, protocol.EventAssistantDone, "authorized answer") {
		t.Fatalf("new session did not accept rotated authorization: %+v", events)
	}
}

func TestRuntimeStartResumeFailsClosedWithoutAuthorizationEnvelope(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_legacy", "old answer", nil)))
	store := &trackingSessionStore{Sessions: stored}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_current" },
	})
	var emitted []protocol.Event
	rt.Subscribe(func(events []protocol.Event) { emitted = append(emitted, events...) })
	events, err := rt.Start(context.Background(), StartOptions{ResumeID: "sess_legacy"})
	if err == nil || err.Error() != permissionedResumeErrorMessage {
		t.Fatalf("permissioned start resume error = %v, want %q", err, permissionedResumeErrorMessage)
	}
	if len(events) != 0 || len(emitted) != 0 {
		t.Fatalf("permissioned start resume emitted events: returned=%+v emitted=%+v", events, emitted)
	}
	if store.loadCalls != 0 {
		t.Fatalf("permissioned start resume loaded history %d times", store.loadCalls)
	}
	if rt.SessionID() != "" {
		t.Fatalf("permissioned start resume changed live session to %q", rt.SessionID())
	}
}

func TestRuntimeStartResumeSuppressesLegacyHistoryForMatchingAuthorizationEnvelope(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	authorization := testAuthorizationContext("sess_authorized")
	bindTestSessionAuthorization(t, stored, authorization)
	must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_authorized", "old answer", nil)))
	store := &trackingSessionStore{Sessions: stored}
	rt := New(Dependencies{
		Workspace:  workspace,
		Sessions:   store,
		EinoRunner: &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			current := testAuthorizationContext(sessionID)
			current.RequestID = "request-resume"
			return current, nil
		},
		NewSessionID: func() string { return "sess_current" },
	})
	events, err := rt.Start(context.Background(), StartOptions{ResumeID: "sess_authorized"})
	if err != nil {
		t.Fatal(err)
	}
	if hasMessage(events, protocol.EventAssistantDone, "old answer") || rt.SessionID() != "sess_authorized" {
		t.Fatalf("permissioned start resume exposed legacy history: session=%q events=%+v", rt.SessionID(), events)
	}
	if store.loadCalls != 1 || store.authorizationLoadCalls != 1 {
		t.Fatalf("permissioned start resume loads = history:%d envelope:%d, want 1 each", store.loadCalls, store.authorizationLoadCalls)
	}
}

func TestRuntimeStartResumeRejectsChangedAuthorizationBeforeHistoryLoad(t *testing.T) {
	tests := []struct {
		name   string
		change func(*protocol.AuthorizationContext)
	}{
		{name: "principal", change: func(auth *protocol.AuthorizationContext) { auth.PrincipalID = "other-user" }},
		{name: "authorization model", change: func(auth *protocol.AuthorizationContext) { auth.AuthorizationModelID = "local-v2" }},
		{name: "identity watermark", change: func(auth *protocol.AuthorizationContext) { auth.IdentityWatermark = "identity-v2" }},
		{name: "acl watermark", change: func(auth *protocol.AuthorizationContext) { auth.ACLWatermark = "acl-v2" }},
		{name: "agent", change: func(auth *protocol.AuthorizationContext) { auth.AgentID = "agent-2" }},
		{name: "task", change: func(auth *protocol.AuthorizationContext) { auth.TaskID = "task-2" }},
		{name: "delegation watermark", change: func(auth *protocol.AuthorizationContext) {
			auth.DelegationWatermark = "delegation-v2"
		}},
		{name: "scope fingerprint", change: func(auth *protocol.AuthorizationContext) {
			auth.AgentTaskScopeFingerprint = "scope_00000000000000000000000000000002"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workspace := t.TempDir()
			stored := local.New(workspace)
			bindTestSessionAuthorization(t, stored, testAuthorizationContext("sess_authorized"))
			must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_authorized", "old answer", nil)))
			store := &trackingSessionStore{Sessions: stored}
			rt := New(Dependencies{
				Workspace:  workspace,
				Sessions:   store,
				EinoRunner: &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
				AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
					authorization := testAuthorizationContext(sessionID)
					tt.change(&authorization)
					return authorization, nil
				},
			})
			events, err := rt.Start(context.Background(), StartOptions{ResumeID: "sess_authorized"})
			if err == nil || err.Error() != permissionedResumeErrorMessage {
				t.Fatalf("changed authorization resume error = %v, want %q", err, permissionedResumeErrorMessage)
			}
			if len(events) != 0 || store.loadCalls != 0 || store.authorizationLoadCalls != 1 {
				t.Fatalf("changed authorization reached history: events=%+v history=%d envelope=%d", events, store.loadCalls, store.authorizationLoadCalls)
			}
			if rt.SessionID() != "" {
				t.Fatalf("changed authorization resume selected session %q", rt.SessionID())
			}
		})
	}
}

func TestRuntimeStartResumeFailsClosedWhenAuthorizedHistoryCannotLoad(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	bindTestSessionAuthorization(t, stored, testAuthorizationContext("sess_authorized"))
	store := &trackingSessionStore{Sessions: stored}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
		AuthorizationContextProvider: testAuthorizationContextProvider,
	})
	events, err := rt.Start(context.Background(), StartOptions{ResumeID: "sess_authorized"})
	if err == nil || err.Error() != permissionedResumeErrorMessage {
		t.Fatalf("missing authorized history error = %v, want %q", err, permissionedResumeErrorMessage)
	}
	if len(events) != 0 || store.loadCalls != 1 || store.authorizationLoadCalls != 1 {
		t.Fatalf("missing authorized history state: events=%+v history=%d envelope=%d", events, store.loadCalls, store.authorizationLoadCalls)
	}
	if rt.SessionID() != "" {
		t.Fatalf("missing authorized history selected session %q", rt.SessionID())
	}
}

func TestRuntimeSlashResumeFailsClosedWithoutAuthorizationEnvelope(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_legacy", "old answer", nil)))
	store := &trackingSessionStore{Sessions: stored}
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_current" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	var emitted []protocol.Event
	rt.Subscribe(func(events []protocol.Event) { emitted = append(emitted, events...) })
	events := rt.SendMessage(context.Background(), "/resume sess_legacy")
	if !hasMessage(events, protocol.EventError, permissionedResumeErrorMessage) {
		t.Fatalf("permissioned slash resume did not return fail-closed error: %+v", events)
	}
	if hasMessage(events, protocol.EventAssistantDone, "old answer") || hasMessage(emitted, protocol.EventAssistantDone, "old answer") {
		t.Fatalf("permissioned slash resume replayed old answer: returned=%+v emitted=%+v", events, emitted)
	}
	if store.loadCalls != 0 || runner.runCalls != 0 {
		t.Fatalf("permissioned slash resume reached history/runner: loads=%d runs=%d", store.loadCalls, runner.runCalls)
	}
	if rt.SessionID() != "sess_current" {
		t.Fatalf("permissioned slash resume changed live session to %q", rt.SessionID())
	}
}

func TestRuntimeSlashResumeSuppressesLegacyHistoryForMatchingAuthorizationEnvelope(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	bindTestSessionAuthorization(t, stored, testAuthorizationContext("sess_authorized"))
	must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_authorized", "old answer", nil)))
	store := &trackingSessionStore{Sessions: stored}
	runner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_current" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "/resume sess_authorized")
	if hasMessage(events, protocol.EventAssistantDone, "old answer") || hasEvent(events, protocol.EventError) {
		t.Fatalf("permissioned slash resume exposed legacy history: %+v", events)
	}
	if rt.SessionID() != "sess_authorized" || store.loadCalls != 1 || store.authorizationLoadCalls != 1 {
		t.Fatalf("permissioned slash resume state = session:%q history:%d envelope:%d", rt.SessionID(), store.loadCalls, store.authorizationLoadCalls)
	}
}

func TestRuntimePermissionedResumeListsOnlyMatchingSessionEnvelopes(t *testing.T) {
	workspace := t.TempDir()
	stored := local.New(workspace)
	for _, sessionID := range []string{"sess_allowed", "sess_denied", "sess_legacy"} {
		must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, sessionID, "stored answer", nil)))
	}
	allowed := testAuthorizationContext("sess_allowed")
	allowed.TaskID = "target-task"
	bindTestSessionAuthorization(t, stored, allowed)
	denied := testAuthorizationContext("sess_denied")
	denied.PrincipalID = "other-user"
	bindTestSessionAuthorization(t, stored, denied)
	must(t, os.WriteFile(filepath.Join(workspace, ".knote", "sessions", "sess_denied.jsonl"), []byte("{not-json\n"), 0o600))
	store := &trackingSessionStore{Sessions: stored}
	rt := New(Dependencies{
		Workspace:  workspace,
		Sessions:   store,
		EinoRunner: &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
		AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			authorization := testAuthorizationContext(sessionID)
			if sessionID == "sess_allowed" {
				authorization.TaskID = "target-task"
			}
			return authorization, nil
		},
		NewSessionID: func() string { return "sess_current" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "/resume")
	if hasEvent(events, protocol.EventError) {
		t.Fatalf("permissioned session list failed: %+v", events)
	}
	var list string
	for _, event := range events {
		if event.Type == protocol.EventAssistantDone {
			list = event.Message
		}
	}
	if !strings.Contains(list, "sess_allowed") {
		t.Fatalf("matching permissioned session missing from list: %q", list)
	}
	for _, forbidden := range []string{"sess_denied", "sess_legacy"} {
		if strings.Contains(list, forbidden) {
			t.Fatalf("non-matching session %q leaked into permissioned list: %q", forbidden, list)
		}
	}
	if store.authorizationListCalls != 1 {
		t.Fatalf("authorization envelope list calls = %d, want 1", store.authorizationListCalls)
	}
	for _, loadedSessionID := range store.loadedSessionIDs {
		if loadedSessionID == "sess_denied" || loadedSessionID == "sess_legacy" {
			t.Fatalf("permissioned list loaded unauthorized history %q: %+v", loadedSessionID, store.loadedSessionIDs)
		}
	}
}

func TestRuntimeResumeWithoutAuthorizationProviderPreservesLegacyReplay(t *testing.T) {
	t.Run("start option", func(t *testing.T) {
		workspace := t.TempDir()
		stored := local.New(workspace)
		must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_legacy", "old answer", nil)))
		store := &trackingSessionStore{Sessions: stored}
		rt := New(Dependencies{
			Workspace:    workspace,
			Sessions:     store,
			EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
			NewSessionID: func() string { return "sess_current" },
		})
		events, err := rt.Start(context.Background(), StartOptions{ResumeID: "sess_legacy"})
		if err != nil {
			t.Fatal(err)
		}
		if !hasMessage(events, protocol.EventAssistantDone, "old answer") || rt.SessionID() != "sess_legacy" {
			t.Fatalf("legacy start resume was not preserved: session=%q events=%+v", rt.SessionID(), events)
		}
		if store.loadCalls != 1 {
			t.Fatalf("legacy start resume history loads = %d, want 1", store.loadCalls)
		}
	})

	t.Run("slash command", func(t *testing.T) {
		workspace := t.TempDir()
		stored := local.New(workspace)
		must(t, stored.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_legacy", "old answer", nil)))
		store := &trackingSessionStore{Sessions: stored}
		rt := New(Dependencies{
			Workspace:    workspace,
			Sessions:     store,
			EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "new answer", nil)}},
			NewSessionID: func() string { return "sess_current" },
		})
		if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
			t.Fatal(err)
		}
		events := rt.SendMessage(context.Background(), "/resume sess_legacy")
		if !hasMessage(events, protocol.EventAssistantDone, "old answer") || rt.SessionID() != "sess_legacy" {
			t.Fatalf("legacy slash resume was not preserved: session=%q events=%+v", rt.SessionID(), events)
		}
		if store.loadCalls != 1 {
			t.Fatalf("legacy slash resume history loads = %d, want 1", store.loadCalls)
		}
	})
}

func TestRuntimeEinoCurrentSessionInfoRefreshesWorkspaceStatus(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	mustRun(t, workspace, "git", "config", "user.email", "knote@example.com")
	mustRun(t, workspace, "git", "config", "user.name", "knote")
	must(t, os.WriteFile(filepath.Join(workspace, ".gitignore"), []byte(".knote/sessions/\n"), 0o644))
	mustRun(t, workspace, "git", "add", ".gitignore")
	mustRun(t, workspace, "git", "commit", "-m", "initial")
	store := local.New(workspace)
	einoRunner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "hello from eino", nil)}}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		Versions:     store,
		EinoRunner:   einoRunner,
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	info := rt.CurrentSessionInfo(context.Background())
	if info.ID != "sess_eino" || info.Branch == "" || info.Dirty {
		t.Fatalf("unexpected initial Eino session info: %+v", info)
	}

	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("dirty\n"), 0o644))
	info = rt.CurrentSessionInfo(context.Background())
	if info.ID != "sess_eino" || info.Branch == "" || !info.Dirty {
		t.Fatalf("Eino session info did not refresh workspace status: %+v", info)
	}
}

func TestRuntimeEvalSlashFailsClosedBeforeToolExecution(t *testing.T) {
	workspace := t.TempDir()
	executor := &fakeToolExecutor{}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     local.New(workspace),
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}},
		ToolExecutor: executor,
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "/eval")
	if !hasMessage(events, protocol.EventError, "eval is unavailable until authorized explain is implemented") {
		t.Fatalf("disabled eval did not fail closed: %+v", events)
	}
	if executor.calls != 0 {
		t.Fatalf("disabled eval invoked the tool executor %d times", executor.calls)
	}
}

func TestRuntimeEinoModeConfirmsSideEffectTool(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	bridge := NewSideEffectBridge()
	einoRunner := &sideEffectEinoRunner{bridge: bridge}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   einoRunner,
		AuthorizationContextProvider: testAuthorizationContextProvider,
		SideEffects:                  bridge,
		NewSessionID:                 func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "build knowledge")
	if hasEvent(events, protocol.EventError) || !hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("side-effect request should surface as confirm without error: %+v", events)
	}
	confirm := firstConfirm(t, events)
	events = rt.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventStatusUpdate) || !hasEvent(events, protocol.EventToolComplete) {
		t.Fatalf("approved side-effect did not execute: %+v", events)
	}
	if einoRunner.executions != 1 {
		t.Fatalf("approved side-effect executions = %d, want 1", einoRunner.executions)
	}
	if !einoRunner.executionAuthorizationBound || einoRunner.executionAuthorization != testAuthorizationContext("sess_eino") {
		t.Fatalf("approved side-effect authorization = bound:%t context:%+v", einoRunner.executionAuthorizationBound, einoRunner.executionAuthorization)
	}
	if !einoRunner.executionExpectedEnvelopeBound || einoRunner.executionExpectedEnvelope.ValidateFor(einoRunner.executionAuthorization) != nil {
		t.Fatalf("approved side-effect expected envelope = bound:%t envelope:%+v", einoRunner.executionExpectedEnvelopeBound, einoRunner.executionExpectedEnvelope)
	}
	loaded, err := store.Load(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(loaded, protocol.EventConfirmRequest) || !hasEvent(loaded, protocol.EventToolComplete) {
		t.Fatalf("side-effect confirm/execution events were not persisted: %+v", loaded)
	}
}

func TestRuntimeEinoModeRevalidatesAuthorizationBeforeApprovedSideEffect(t *testing.T) {
	for _, test := range []struct {
		name       string
		invalidate func(*protocol.AuthorizationContext, *error)
		wantError  string
	}{
		{
			name: "provider failure",
			invalidate: func(_ *protocol.AuthorizationContext, providerErr *error) {
				*providerErr = fmt.Errorf("identity provider unavailable")
			},
			wantError: "authorization context provider: identity provider unavailable",
		},
		{
			name: "binding change",
			invalidate: func(authorization *protocol.AuthorizationContext, _ *error) {
				authorization.ACLWatermark = "acl-v2"
			},
			wantError: `authorization context changed for live session "sess_eino"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			bridge := NewSideEffectBridge()
			einoRunner := &sideEffectEinoRunner{bridge: bridge}
			original := testAuthorizationContext("sess_eino")
			current := original
			var providerErr error
			rt := New(Dependencies{
				Workspace:  workspace,
				Sessions:   local.New(workspace),
				EinoRunner: einoRunner,
				AuthorizationContextProvider: func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
					if providerErr != nil {
						return protocol.AuthorizationContext{}, providerErr
					}
					authorization := current
					authorization.SessionID = sessionID
					return authorization, nil
				},
				SideEffects:  bridge,
				NewSessionID: func() string { return "sess_eino" },
			})
			if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
				t.Fatal(err)
			}
			confirm := firstConfirm(t, rt.SendMessage(context.Background(), "build knowledge"))
			test.invalidate(&current, &providerErr)

			events := rt.Confirm(context.Background(), confirm, true)
			if !hasMessage(events, protocol.EventError, test.wantError) {
				t.Fatalf("authorization change was not rejected: %+v", events)
			}
			if len(events) != 2 || events[0].Type != protocol.EventError || events[1].Type != protocol.EventConfirmRequest {
				t.Fatalf("authorization rejection events = %+v, want error then confirm request", events)
			}
			retry := firstConfirm(t, events)
			if retry != confirm {
				t.Fatalf("retry confirmation = %+v, want canonical request %+v", retry, confirm)
			}
			if einoRunner.executions != 0 {
				t.Fatalf("stale side-effect executed %d times", einoRunner.executions)
			}

			current = original
			providerErr = nil
			events = rt.Confirm(context.Background(), retry, true)
			if hasEvent(events, protocol.EventError) || hasEvent(events, protocol.EventConfirmRequest) || !hasEvent(events, protocol.EventToolComplete) {
				t.Fatalf("pending confirmation was consumed by authorization rejection: %+v", events)
			}
			if einoRunner.executions != 1 || !einoRunner.executionAuthorizationBound || einoRunner.executionAuthorization != original {
				t.Fatalf("revalidated execution = count:%d bound:%t context:%+v", einoRunner.executions, einoRunner.executionAuthorizationBound, einoRunner.executionAuthorization)
			}

			providerErr = fmt.Errorf("identity provider unavailable again")
			events = rt.Confirm(context.Background(), retry, true)
			if len(events) != 1 || events[0].Type != protocol.EventError || hasEvent(events, protocol.EventConfirmRequest) {
				t.Fatalf("stale confirmation was re-emitted after consumption: %+v", events)
			}
			if einoRunner.executions != 1 {
				t.Fatalf("stale confirmation executed side-effect %d times, want 1", einoRunner.executions)
			}
		})
	}
}

func TestRuntimeEinoModeDoesNotRetryPostConsumptionExecutionFailure(t *testing.T) {
	workspace := t.TempDir()
	bridge := NewSideEffectBridge()
	einoRunner := &sideEffectEinoRunner{
		bridge:       bridge,
		executionErr: fmt.Errorf("workspace write failed"),
	}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     local.New(workspace),
		EinoRunner:   einoRunner,
		SideEffects:  bridge,
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	confirm := firstConfirm(t, rt.SendMessage(context.Background(), "build knowledge"))

	events := rt.Confirm(context.Background(), confirm, true)
	if !hasMessage(events, protocol.EventError, "workspace write failed") || hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("post-consumption execution failure became retryable: %+v", events)
	}
	if einoRunner.executions != 1 {
		t.Fatalf("failed side-effect executions = %d, want 1", einoRunner.executions)
	}

	events = rt.Confirm(context.Background(), confirm, true)
	if !hasMessage(events, protocol.EventError, "confirmation is not pending or has already been used") || hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("consumed confirmation was not cleared: %+v", events)
	}
	if einoRunner.executions != 1 {
		t.Fatalf("consumed confirmation executed side-effect %d times, want 1", einoRunner.executions)
	}
}

func TestRuntimeEinoSlashReadOnlyToolUsesExecutor(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	einoRunner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}}
	toolExecutor := &fakeToolExecutor{
		events: []protocol.Event{protocol.NewEvent(protocol.EventVersionDiff, "", "No diff.", nil)},
	}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		EinoRunner:   einoRunner,
		ToolExecutor: toolExecutor,
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "/diff HEAD")
	if !hasEvent(events, protocol.EventUserMessage) || !hasEvent(events, protocol.EventVersionDiff) {
		t.Fatalf("slash diff did not use tool executor: %+v", events)
	}
	if toolExecutor.calls != 1 || toolExecutor.lastTool != "knote_diff" || toolExecutor.lastArgs != `{"ref":"HEAD"}` {
		t.Fatalf("unexpected tool executor call: calls=%d tool=%q args=%q", toolExecutor.calls, toolExecutor.lastTool, toolExecutor.lastArgs)
	}
	if len(einoRunner.lastHistory) != 0 {
		t.Fatalf("slash command should not be sent to Eino runner history: %+v", einoRunner.lastHistory)
	}
}

func TestRuntimeEinoSlashMutatingToolRequiresConfirmation(t *testing.T) {
	workspace := t.TempDir()
	bridge := NewSideEffectBridge()
	toolExecutor := &fakeToolExecutor{}
	toolExecutor.onInvoke = func(ctx context.Context, sessionID string, toolName string, args string) ([]protocol.Event, error) {
		return nil, bridge.Request(ctx, SideEffectRequest{
			ToolName:        toolName,
			Action:          "build",
			ArgumentsInJSON: args,
			Summary:         "Build knowledge artifacts.",
			Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
				toolExecutor.executions++
				return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", nil)}, nil
			},
		})
	}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     local.New(workspace),
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}},
		SideEffects:  bridge,
		ToolExecutor: toolExecutor,
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "/build")
	if !hasEvent(events, protocol.EventConfirmRequest) || hasEvent(events, protocol.EventToolComplete) {
		t.Fatalf("slash build should request confirmation before execution: %+v", events)
	}
	if toolExecutor.executions != 0 {
		t.Fatalf("slash build executed before confirmation: %d", toolExecutor.executions)
	}
	events = rt.Confirm(context.Background(), firstConfirm(t, events), true)
	if !hasEvent(events, protocol.EventToolComplete) || toolExecutor.executions != 1 {
		t.Fatalf("approved slash build did not execute once: executions=%d events=%+v", toolExecutor.executions, events)
	}
}

func TestRuntimeEinoModeRejectsSideEffectTool(t *testing.T) {
	workspace := t.TempDir()
	bridge := NewSideEffectBridge()
	einoRunner := &sideEffectEinoRunner{bridge: bridge}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     local.New(workspace),
		EinoRunner:                   einoRunner,
		AuthorizationContextProvider: testAuthorizationContextProvider,
		SideEffects:                  bridge,
		NewSessionID:                 func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	confirm := firstConfirm(t, rt.SendMessage(context.Background(), "build knowledge"))
	events := rt.Confirm(context.Background(), confirm, false)
	if !hasMessage(events, protocol.EventAssistantDone, "Cancelled: build") {
		t.Fatalf("rejected side-effect should be cancelled: %+v", events)
	}
	if einoRunner.executions != 0 {
		t.Fatalf("rejected side-effect executed %d times", einoRunner.executions)
	}
}

func TestSideEffectBridgeQueuesOneConfirmationAtATime(t *testing.T) {
	bridge := NewSideEffectBridge()
	ctx := withSideEffectSession(context.Background(), "sess_eino")
	executed := make([]string, 0, 2)
	for _, action := range []string{"build", "eval"} {
		err := bridge.Request(ctx, SideEffectRequest{
			ToolName:        "knote_" + action,
			Action:          action,
			ArgumentsInJSON: "{}",
			Summary:         action,
			Execute: func(_ context.Context, req SideEffectRequest) ([]protocol.Event, error) {
				executed = append(executed, req.Action)
				return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, req.SessionID, req.ToolName+" complete", nil)}, nil
			},
		})
		if err != ErrSideEffectPending {
			t.Fatalf("request %s returned %v", action, err)
		}
	}
	firstBatch := bridge.PendingEvents("sess_eino")
	if got := countEvents(firstBatch, protocol.EventConfirmRequest); got != 1 {
		t.Fatalf("first pending batch confirm count = %d, want 1: %+v", got, firstBatch)
	}
	first := firstConfirm(t, firstBatch)
	secondBatch := bridge.PendingEvents("sess_eino")
	if countEvents(secondBatch, protocol.EventConfirmRequest) != 0 {
		t.Fatalf("bridge showed another confirmation while first is active: %+v", secondBatch)
	}
	events := bridge.Confirm(context.Background(), "sess_eino", first, true)
	if executed[0] != "build" {
		t.Fatalf("bridge did not execute FIFO first request: %+v", executed)
	}
	if got := countEvents(events, protocol.EventConfirmRequest); got != 1 {
		t.Fatalf("confirm should surface next queued request, got %d confirm events: %+v", got, events)
	}
	second := firstConfirm(t, events)
	if first.RequestID == second.RequestID {
		t.Fatalf("queued confirmations reused request id %q", first.RequestID)
	}
	events = bridge.Confirm(context.Background(), "sess_eino", second, false)
	if !hasMessage(events, protocol.EventAssistantDone, "Cancelled: eval") {
		t.Fatalf("rejecting second queued request did not cancel eval: %+v", events)
	}
	if len(executed) != 1 {
		t.Fatalf("rejected queued request executed unexpectedly: %+v", executed)
	}
}

func TestRuntimeEinoModePersistsPartialEventsOnRunnerError(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "partial answer", nil)}, err: fmt.Errorf("runner failed")},
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events := rt.SendMessage(context.Background(), "hello")
	if !hasMessage(events, protocol.EventAssistantDone, "partial answer") || !hasEvent(events, protocol.EventError) {
		t.Fatalf("runtime did not keep partial runner events before error: %+v", events)
	}
	loaded, err := store.Load(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if !hasMessage(loaded, protocol.EventAssistantDone, "partial answer") || !hasEvent(loaded, protocol.EventError) {
		t.Fatalf("partial runner events were not persisted: %+v", loaded)
	}
}

func TestRuntimeEinoModeRequiresReadyRunner(t *testing.T) {
	workspace := t.TempDir()
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     local.New(workspace),
		EinoRunner:   &fakeEinoRunner{},
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err == nil {
		t.Fatal("expected Eino mode startup to fail when runner is not ready")
	}
}

func TestRuntimeEinoModeRequiresSessionStorage(t *testing.T) {
	rt := New(Dependencies{
		Workspace:    t.TempDir(),
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "hello from eino", nil)}},
		NewSessionID: func() string { return "sess_eino" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err == nil {
		t.Fatal("expected Eino mode startup to fail without session storage")
	}
}

func newTestRuntime(t *testing.T, workspace string) (*Manager, error) {
	t.Helper()
	ctx := context.Background()
	repo := local.New(workspace)
	cfg, err := repo.Config(ctx)
	if err != nil {
		return nil, err
	}
	cfg.KAG.Fake = true
	cfg.Workspace = workspace
	if err := repo.SaveConfig(ctx, cfg); err != nil {
		return nil, err
	}
	bridge := NewSideEffectBridge()
	toolExecutor := &fakeToolExecutor{}
	toolExecutor.onInvoke = func(ctx context.Context, sessionID string, toolName string, args string) ([]protocol.Event, error) {
		return nil, bridge.Request(ctx, SideEffectRequest{
			ToolName:        toolName,
			Action:          "build",
			ArgumentsInJSON: args,
			Summary:         "Build knowledge artifacts.",
			Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
				toolExecutor.executions++
				return []protocol.Event{
					protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", nil),
					protocol.NewEvent(protocol.EventBuildComplete, sessionID, "Build complete", nil),
				}, nil
			},
		})
	}
	return New(Dependencies{
		Workspace:     workspace,
		Config:        cfg,
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		EinoRunner:    &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "hello from eino", nil)}},
		SideEffects:   bridge,
		ToolExecutor:  toolExecutor,
		NewSessionID:  local.NewSessionID,
	}), nil
}

func firstConfirm(t *testing.T, events []protocol.Event) protocol.ConfirmRequest {
	t.Helper()
	for _, event := range events {
		if event.Type != protocol.EventConfirmRequest {
			continue
		}
		req, ok := event.Payload.(protocol.ConfirmRequest)
		if !ok {
			t.Fatalf("unexpected confirm payload %T", event.Payload)
		}
		return req
	}
	t.Fatalf("no confirm request in %+v", events)
	return protocol.ConfirmRequest{}
}

func hasEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func countEvents(events []protocol.Event, eventType protocol.EventType) int {
	var count int
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func hasMessage(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			return true
		}
	}
	return false
}

type fakeEinoRunner struct {
	tools              []RunnerToolInfo
	inventoryCalls     int
	events             []protocol.Event
	lastHistory        []protocol.Event
	authorization      protocol.AuthorizationContext
	authorizationBound bool
	sideEffectSession  string
	runCalls           int
	err                error
}

type trackingSessionStore struct {
	repository.Sessions
	loadCalls              int
	loadedSessionIDs       []string
	authorizationLoadCalls int
	authorizationBindCalls int
	authorizationListCalls int
}

type sessionsOnlyStore struct {
	repository.Sessions
}

func (s *trackingSessionStore) Load(ctx context.Context, sessionID string) ([]protocol.Event, error) {
	s.loadCalls++
	s.loadedSessionIDs = append(s.loadedSessionIDs, sessionID)
	return s.Sessions.Load(ctx, sessionID)
}

func (s *trackingSessionStore) BindAuthorization(ctx context.Context, envelope protocol.SessionAuthorizationEnvelope) error {
	s.authorizationBindCalls++
	sessions, ok := s.Sessions.(repository.PermissionedSessions)
	if !ok {
		return repository.ErrSessionAuthorizationEnvelopeNotFound
	}
	return sessions.BindAuthorization(ctx, envelope)
}

func (s *trackingSessionStore) LoadAuthorization(ctx context.Context, sessionID string) (protocol.SessionAuthorizationEnvelope, error) {
	s.authorizationLoadCalls++
	sessions, ok := s.Sessions.(repository.PermissionedSessions)
	if !ok {
		return protocol.SessionAuthorizationEnvelope{}, repository.ErrSessionAuthorizationEnvelopeNotFound
	}
	return sessions.LoadAuthorization(ctx, sessionID)
}

func (s *trackingSessionStore) ListAuthorization(ctx context.Context) ([]protocol.SessionAuthorizationEnvelope, error) {
	s.authorizationListCalls++
	sessions, ok := s.Sessions.(repository.PermissionedSessions)
	if !ok {
		return nil, repository.ErrSessionAuthorizationEnvelopeNotFound
	}
	return sessions.ListAuthorization(ctx)
}

type fakeToolExecutor struct {
	events     []protocol.Event
	err        error
	onInvoke   func(context.Context, string, string, string) ([]protocol.Event, error)
	calls      int
	executions int
	lastTool   string
	lastArgs   string
}

func (e *fakeToolExecutor) Invoke(ctx context.Context, sessionID string, toolName string, argumentsInJSON string) ([]protocol.Event, error) {
	e.calls++
	e.lastTool = toolName
	e.lastArgs = argumentsInJSON
	if e.onInvoke != nil {
		return e.onInvoke(ctx, sessionID, toolName, argumentsInJSON)
	}
	events := make([]protocol.Event, 0, len(e.events))
	for _, event := range e.events {
		event.SessionID = sessionID
		events = append(events, event)
	}
	return events, e.err
}

type sideEffectEinoRunner struct {
	bridge                         *SideEffectBridge
	executions                     int
	executionErr                   error
	executionAuthorization         protocol.AuthorizationContext
	executionAuthorizationBound    bool
	executionExpectedEnvelope      protocol.SessionAuthorizationEnvelope
	executionExpectedEnvelopeBound bool
}

func (r *sideEffectEinoRunner) Ready(context.Context) error {
	return nil
}

func (r *sideEffectEinoRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return []RunnerToolInfo{{Name: "knote_build", Description: "build knowledge"}}, nil
}

func (r *sideEffectEinoRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	return nil, r.bridge.Request(ctx, SideEffectRequest{
		ToolName:        "knote_build",
		Action:          "build",
		ArgumentsInJSON: "{}",
		Summary:         "Build knowledge artifacts.",
		Execute: func(ctx context.Context, _ SideEffectRequest) ([]protocol.Event, error) {
			r.executions++
			r.executionAuthorization, r.executionAuthorizationBound = protocol.AuthorizationContextFrom(ctx)
			r.executionExpectedEnvelope, r.executionExpectedEnvelopeBound = expectedSessionAuthorizationEnvelopeFrom(ctx)
			if r.executionErr != nil {
				return nil, r.executionErr
			}
			return []protocol.Event{
				protocol.NewEvent(protocol.EventToolComplete, input.SessionID, "knote_build complete", map[string]string{"tool": "knote_build"}),
			}, nil
		},
	})
}

func (r *fakeEinoRunner) Ready(context.Context) error {
	if len(r.events) == 0 {
		return fmt.Errorf("fake Eino runner is not ready")
	}
	return nil
}

func (r *fakeEinoRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	r.inventoryCalls++
	return append([]RunnerToolInfo(nil), r.tools...), nil
}

type observableVersionsProbe struct {
	status      repository.Status
	statusCalls int
}

func (p *observableVersionsProbe) Status(context.Context) (repository.Status, error) {
	p.statusCalls++
	return p.status, nil
}

func (*observableVersionsProbe) Diff(context.Context, string) (string, error) {
	return "", fmt.Errorf("unexpected diff call")
}

func (*observableVersionsProbe) Versions(context.Context, int) ([]repository.Version, error) {
	return nil, fmt.Errorf("unexpected versions call")
}

func (*observableVersionsProbe) Commit(context.Context, string) (repository.CommitResult, error) {
	return repository.CommitResult{}, fmt.Errorf("unexpected commit call")
}

func (*observableVersionsProbe) Tag(context.Context, string) error {
	return fmt.Errorf("unexpected tag call")
}

func (*observableVersionsProbe) Checkout(context.Context, string, repository.CheckoutOptions) error {
	return fmt.Errorf("unexpected checkout call")
}

func (r *fakeEinoRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	r.runCalls++
	r.authorization, r.authorizationBound = protocol.AuthorizationContextFrom(ctx)
	r.sideEffectSession = sideEffectSessionID(ctx)
	if len(r.events) == 0 {
		return nil, fmt.Errorf("fake Eino runner does not execute")
	}
	r.lastHistory = append([]protocol.Event(nil), input.History...)
	events := make([]protocol.Event, 0, len(r.events))
	for _, event := range r.events {
		event.SessionID = input.SessionID
		events = append(events, event)
	}
	return events, r.err
}

func testAuthorizationContextProvider(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
	return testAuthorizationContext(sessionID), nil
}

func testAuthorizationContext(sessionID string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:                   protocol.SecurityContractVersion,
		TenantID:                  "local",
		KnowledgeBaseID:           "default",
		PrincipalID:               "local-user",
		SessionID:                 sessionID,
		RequestID:                 "request-1",
		AgentID:                   "agent-1",
		TaskID:                    "task-1",
		DelegationWatermark:       "delegation-v1",
		AgentTaskScopeFingerprint: "scope_00000000000000000000000000000001",
		AuthorizationModelID:      "local-v1",
		IdentityWatermark:         "identity-v1",
		ACLWatermark:              "acl-v1",
		Consistency:               protocol.ConsistencyHigherConsistency,
	}
}

func bindTestSessionAuthorization(t *testing.T, sessions repository.PermissionedSessions, authorization protocol.AuthorizationContext) {
	t.Helper()
	envelope, err := protocol.NewSessionAuthorizationEnvelope(authorization, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.BindAuthorization(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
