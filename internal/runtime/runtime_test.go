package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
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
	if !hasEvent(buildEvents, protocol.EventBuildComplete) {
		t.Fatalf("missing build complete: %+v", buildEvents)
	}
	queryEvents := rt.Handle(context.Background(), "what is knote?")
	if !hasEvent(queryEvents, protocol.EventAssistantDone) {
		t.Fatalf("missing assistant answer: %+v", queryEvents)
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
