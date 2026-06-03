package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
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

func TestRuntimeWorkspaceStatusAndDirectModeControls(t *testing.T) {
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
		t.Fatal("interrupt should emit a status event in direct mode")
	}
	if !hasEvent(rt.StopTask(context.Background(), "task_1"), protocol.EventStatusUpdate) {
		t.Fatal("stop task should emit a status event in direct mode")
	}
	if !hasEvent(rt.StopTask(context.Background(), ""), protocol.EventError) {
		t.Fatal("stop task without id should emit an error")
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
	kagClient := kag.Client{
		AdapterPath: cfg.KAG.AdapterPath,
		Workspace:   workspace,
		Host:        cfg.KAG.Host,
		Fake:        cfg.KAG.Fake,
		ConfigPath:  cfg.KAG.ConfigPath,
		ProjectID:   cfg.KAG.ProjectID,
		Namespace:   cfg.KAG.Namespace,
		Language:    cfg.KAG.Language,
		RuntimeDir:  cfg.KAG.RuntimeDir,
	}
	return New(Dependencies{
		Workspace:     workspace,
		Config:        cfg,
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		Knowledge:     versioned.New(versioned.Options{Workspace: workspace, Repo: repo, Versions: repo, Backend: kagClient, Mode: versioned.ModeFake}),
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
