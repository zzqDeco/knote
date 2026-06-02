package tui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	agentpkg "github.com/zzqDeco/knote/internal/agent"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestInputHistoryCyclesComposerValues(t *testing.T) {
	model := newTestModel(t)

	model.composer.SetValue("/help")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	model.composer.SetValue("/status")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyUp})
	if got := model.composer.Value(); got != "/status" {
		t.Fatalf("first history step = %q, want /status", got)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyUp})
	if got := model.composer.Value(); got != "/help" {
		t.Fatalf("second history step = %q, want /help", got)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyDown})
	if got := model.composer.Value(); got != "/status" {
		t.Fatalf("history down = %q, want /status", got)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyDown})
	if got := model.composer.Value(); got != "" {
		t.Fatalf("history draft restore = %q, want empty", got)
	}
}

func TestConfirmRejectClosesOverlayWithoutRunningBuild(t *testing.T) {
	model := newTestModel(t)
	workspace := model.agent.Workspace()

	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil || model.overlayMode != overlayConfirm {
		t.Fatalf("build did not enter confirm overlay: pending=%v overlay=%s", model.pendingConfirm, model.overlayMode)
	}

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if model.pendingConfirm != nil {
		t.Fatalf("reject did not clear pending confirm: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayNone {
		t.Fatalf("reject did not close overlay: %s", model.overlayMode)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("rejected build wrote artifacts: %v", err)
	}
}

func TestOverlaySwitchAndEsc(t *testing.T) {
	model := newTestModel(t)

	model.composer.SetValue("/tasks")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.overlayMode != overlayTasks || !strings.Contains(model.overlay, "tasks") {
		t.Fatalf("/tasks did not show tasks overlay: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEsc})
	if model.overlayMode != overlayNone || strings.TrimSpace(model.overlay) != "" {
		t.Fatalf("esc did not close overlay: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
}

func TestClearProjectsTranscriptWithoutDeletingSession(t *testing.T) {
	model := newTestModel(t)
	store := local.New(model.agent.Workspace())
	sessionID := model.agent.SessionID()

	model.composer.SetValue("/help")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	model.composer.SetValue("/clear")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})

	if got := strings.TrimSpace(renderTranscript(model.events)); got != "knote ready" {
		t.Fatalf("clear should project empty transcript, got:\n%s", got)
	}
	events, err := store.Load(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTUIEvent(events, protocol.EventViewClear) || len(events) == 0 {
		t.Fatalf("clear did not persist a view event while keeping history: %+v", events)
	}
}

func TestResumeDoesNotReviveStaleConfirmation(t *testing.T) {
	model := newTestModel(t)
	sessionID := model.agent.SessionID()

	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil {
		t.Fatal("/build did not create a pending confirmation")
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if model.pendingConfirm != nil {
		t.Fatal("rejecting /build did not clear pending confirmation")
	}

	model.composer.SetValue("/new")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.agent.SessionID() == sessionID {
		t.Fatal("/new did not switch sessions")
	}

	model.composer.SetValue("/resume " + sessionID)
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm != nil {
		t.Fatalf("resume revived stale confirmation: %+v", model.pendingConfirm)
	}

	model.composer.SetValue("/eval")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil || model.pendingConfirm.Action != "eval" {
		t.Fatalf("/eval after resume did not create a fresh confirmation: %+v", model.pendingConfirm)
	}
}

func newTestModel(t *testing.T) Model {
	t.Helper()
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, initial, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	model := New(rt, initial)
	model.width = 100
	model.height = 30
	model.resize()
	model.refreshOverlay()
	model.refreshViewport()
	return model
}

func newTestAgent(t *testing.T, workspace string) (*agentpkg.Agent, []protocol.Event, error) {
	t.Helper()
	ctx := context.Background()
	repo := local.New(workspace)
	cfg, err := repo.Config(ctx)
	if err != nil {
		return nil, nil, err
	}
	cfg.KAG.Fake = true
	cfg.Workspace = workspace
	if err := repo.SaveConfig(ctx, cfg); err != nil {
		return nil, nil, err
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
	return agentpkg.New(ctx, agentpkg.Dependencies{
		Workspace:     workspace,
		Config:        cfg,
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		Knowledge:     versioned.New(versioned.Options{Workspace: workspace, Repo: repo, Versions: repo, Backend: kagClient, Mode: versioned.ModeFake}),
		NewSessionID:  local.NewSessionID,
	})
}

func updateModel(t *testing.T, model *Model, msg tea.Msg) {
	t.Helper()
	next, _ := model.Update(msg)
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("unexpected model type %T", next)
	}
	*model = updated
}

func hasTUIEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
