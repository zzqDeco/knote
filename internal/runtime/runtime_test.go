package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/session"
)

func TestRuntimeBuildAndQueryWithFakeKAG(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, _, err := New(context.Background(), Options{Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	buildEvents := rt.Handle(context.Background(), "/build")
	if !hasEvent(buildEvents, protocol.EventConfirmRequest) {
		t.Fatalf("missing build confirmation: %+v", buildEvents)
	}
	confirm := firstConfirm(t, buildEvents)
	buildEvents = rt.Confirm(context.Background(), confirm, true)
	if !hasEvent(buildEvents, protocol.EventBuildComplete) {
		t.Fatalf("missing build complete: %+v", buildEvents)
	}
	queryEvents := rt.Handle(context.Background(), "what is knote?")
	if !hasEvent(queryEvents, protocol.EventAssistantDone) {
		t.Fatalf("missing assistant answer: %+v", queryEvents)
	}
}

func TestRuntimeRejectsSideEffectConfirmation(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, _, err := New(context.Background(), Options{Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	events := rt.Handle(context.Background(), "/build")
	confirm := firstConfirm(t, events)
	events = rt.Confirm(context.Background(), confirm, false)
	if hasEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("rejected build should not run: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("rejected build wrote artifacts: %v", err)
	}
}

func TestRuntimeRejectsForgedAndReplayedConfirmation(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, _, err := New(context.Background(), Options{Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	forged := protocol.ConfirmRequest{
		RequestID: "forged",
		Action:    "build",
		Command:   "/build",
	}
	events := rt.Confirm(context.Background(), forged, true)
	if !hasEvent(events, protocol.EventError) {
		t.Fatalf("forged confirmation should fail: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("forged confirmation wrote artifacts: %v", err)
	}

	events = rt.Handle(context.Background(), "/build")
	confirm := firstConfirm(t, events)
	events = rt.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("valid confirmation should build: %+v", events)
	}
	events = rt.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventError) {
		t.Fatalf("replayed confirmation should fail: %+v", events)
	}
}

func TestRuntimeSessionCommands(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, _, err := New(context.Background(), Options{Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	oldID := rt.SessionID()

	clearEvents := rt.Handle(context.Background(), "/clear")
	if !hasEvent(clearEvents, protocol.EventViewClear) {
		t.Fatalf("missing view clear event: %+v", clearEvents)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".knote", "sessions", oldID+".jsonl")); err != nil {
		t.Fatalf("clear should keep session history file: %v", err)
	}

	newEvents := rt.Handle(context.Background(), "/new")
	newID := rt.SessionID()
	if newID == oldID {
		t.Fatal("/new did not create a new session id")
	}
	if !hasEvent(newEvents, protocol.EventSessionInfo) || !hasEvent(newEvents, protocol.EventViewClear) {
		t.Fatalf("/new did not emit session info and clear events: %+v", newEvents)
	}

	store := session.NewStore(workspace)
	beforeResume, err := store.Load(oldID)
	if err != nil {
		t.Fatal(err)
	}
	resumeEvents := rt.Handle(context.Background(), "/resume "+oldID)
	if rt.SessionID() != oldID {
		t.Fatalf("/resume did not switch runtime session, got %s", rt.SessionID())
	}
	if !hasEvent(resumeEvents, protocol.EventSessionInfo) || !hasEvent(resumeEvents, protocol.EventViewClear) {
		t.Fatalf("/resume did not emit replay boundary and session info: %+v", resumeEvents)
	}
	afterResume, err := store.Load(oldID)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterResume) != len(beforeResume)+1 {
		t.Fatalf("/resume should append only fresh session.info to resumed session, before=%d after=%d", len(beforeResume), len(afterResume))
	}
}

func TestRuntimeReadOnlyCommands(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, _, err := New(context.Background(), Options{Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		command string
		want    string
	}{
		{command: "/details", want: "Workspace details"},
		{command: "/settings", want: "Effective settings"},
		{command: "/model", want: "Model profiles"},
	} {
		events := rt.Handle(context.Background(), tc.command)
		got := lastAssistant(events)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("%s output missing %q:\n%s", tc.command, tc.want, got)
		}
		if strings.Contains(got, "stubbed") {
			t.Fatalf("%s still returned stub output: %s", tc.command, got)
		}
	}
}

func TestRuntimeResumeWithoutIDListsRecentSessions(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, _, err := New(context.Background(), Options{Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := rt.SessionID()

	events := rt.Handle(context.Background(), "/resume")
	got := lastAssistant(events)
	if !strings.Contains(got, "Recent sessions") || !strings.Contains(got, sessionID) {
		t.Fatalf("/resume without id did not list recent sessions:\n%s", got)
	}
}

func hasEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
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

func lastAssistant(events []protocol.Event) string {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == protocol.EventAssistantDone {
			return events[i].Message
		}
	}
	return ""
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
