package runtime

import (
	"context"
	"fmt"
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

func TestRuntimeRunnerInfoIncludesEinoInventory(t *testing.T) {
	rt := New(Dependencies{
		Workspace:    "/tmp/knote-test",
		RunnerMode:   RunnerModeDirect,
		EinoRunner:   &fakeEinoRunner{tools: []RunnerToolInfo{{Name: "knote_query", Description: "query knowledge"}}},
		NewSessionID: local.NewSessionID,
	})
	info, err := rt.RunnerInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ConfiguredMode != RunnerModeDirect || info.ActiveMode != RunnerModeDirect {
		t.Fatalf("unexpected runner modes: %+v", info)
	}
	if !info.EinoAvailable {
		t.Fatalf("expected Eino runner to be available: %+v", info)
	}
	if len(info.Tools) != 1 || info.Tools[0].Name != "knote_query" {
		t.Fatalf("unexpected tool inventory: %+v", info.Tools)
	}
}

func TestRuntimeEinoModeStartsAndSendsThroughBridge(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	einoRunner := &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "hello from eino", nil)}}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		RunnerMode:   RunnerModeEino,
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
	info, err := rt.RunnerInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ConfiguredMode != RunnerModeEino || info.ActiveMode != RunnerModeEino {
		t.Fatalf("unexpected Eino runner info: %+v", info)
	}
}

func TestRuntimeEinoModeConfirmsSideEffectTool(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	bridge := NewSideEffectBridge()
	einoRunner := &sideEffectEinoRunner{bridge: bridge}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		RunnerMode:   RunnerModeEino,
		EinoRunner:   einoRunner,
		SideEffects:  bridge,
		NewSessionID: func() string { return "sess_eino" },
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
	loaded, err := store.Load(context.Background(), "sess_eino")
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(loaded, protocol.EventConfirmRequest) || !hasEvent(loaded, protocol.EventToolComplete) {
		t.Fatalf("side-effect confirm/execution events were not persisted: %+v", loaded)
	}
}

func TestRuntimeEinoModeRejectsSideEffectTool(t *testing.T) {
	workspace := t.TempDir()
	bridge := NewSideEffectBridge()
	einoRunner := &sideEffectEinoRunner{bridge: bridge}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     local.New(workspace),
		RunnerMode:   RunnerModeEino,
		EinoRunner:   einoRunner,
		SideEffects:  bridge,
		NewSessionID: func() string { return "sess_eino" },
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

func TestRuntimeEinoModePersistsPartialEventsOnRunnerError(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		RunnerMode:   RunnerModeEino,
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "partial answer", nil)}, err: fmt.Errorf("runner failed")},
		NewSessionID: func() string { return "sess_eino" },
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
		RunnerMode:   RunnerModeEino,
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
		RunnerMode:   RunnerModeEino,
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

func hasMessage(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			return true
		}
	}
	return false
}

type fakeEinoRunner struct {
	tools       []RunnerToolInfo
	events      []protocol.Event
	lastHistory []protocol.Event
	err         error
}

type sideEffectEinoRunner struct {
	bridge     *SideEffectBridge
	executions int
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
		Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			r.executions++
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
	return append([]RunnerToolInfo(nil), r.tools...), nil
}

func (r *fakeEinoRunner) Run(_ context.Context, input EinoRunInput) ([]protocol.Event, error) {
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
