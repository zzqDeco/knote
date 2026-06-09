package agenttest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agentpkg "github.com/zzqDeco/knote/internal/agent"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestAgentBuildAndQueryWithFakeKAG(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	buildEvents := agent.Handle(context.Background(), "/build")
	if !hasEvent(buildEvents, protocol.EventConfirmRequest) {
		t.Fatalf("missing build confirmation: %+v", buildEvents)
	}
	confirm := firstConfirm(t, buildEvents)
	buildEvents = agent.Confirm(context.Background(), confirm, true)
	if !hasEvent(buildEvents, protocol.EventBuildComplete) {
		t.Fatalf("missing build complete: %+v", buildEvents)
	}
	queryEvents := agent.Handle(context.Background(), "what is knote?")
	if !hasEvent(queryEvents, protocol.EventAssistantDone) {
		t.Fatalf("missing assistant answer: %+v", queryEvents)
	}
}

func TestAgentBuildFailureDoesNotEmitSuccessOrWriteArtifacts(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	repo := local.New(workspace)
	cfg, err := repo.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Workspace = workspace
	if err := repo.SaveConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	agent, _, err := agentpkg.New(context.Background(), agentpkg.Dependencies{
		Workspace:     workspace,
		Config:        cfg,
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		Knowledge:     versioned.New(versioned.Options{Workspace: workspace, Repo: repo, Versions: repo, Backend: buildFailingBackend{}, Mode: versioned.ModeReal}),
		NewSessionID:  local.NewSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}

	events := agent.Handle(context.Background(), "/build")
	confirm := firstConfirm(t, events)
	events = agent.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventError) || !hasEvent(events, protocol.EventTaskComplete) {
		t.Fatalf("failed build did not emit error and task completion: %+v", events)
	}
	if hasEvent(events, protocol.EventBuildComplete) || hasEvent(events, protocol.EventToolComplete) {
		t.Fatalf("failed build emitted success events: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("failed build wrote artifacts: %v", err)
	}
}

func TestAgentRejectsSideEffectConfirmation(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	events := agent.Handle(context.Background(), "/build")
	confirm := firstConfirm(t, events)
	events = agent.Confirm(context.Background(), confirm, false)
	if hasEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("rejected build should not run: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("rejected build wrote artifacts: %v", err)
	}
}

type buildFailingBackend struct{}

func (buildFailingBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{}, fakeBackendError("adapter unavailable")
}

func (buildFailingBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{}, fakeBackendError("adapter unavailable")
}

func (buildFailingBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{}, fakeBackendError("adapter unavailable")
}

type fakeBackendError string

func (e fakeBackendError) Error() string {
	return string(e)
}

func TestAgentRejectsForgedAndReplayedConfirmation(t *testing.T) {
	workspace := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first."), 0o644))
	mustRun(t, workspace, "git", "init")

	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	forged := protocol.ConfirmRequest{
		RequestID: "forged",
		Action:    "build",
		Command:   "/build",
	}
	events := agent.Confirm(context.Background(), forged, true)
	if !hasEvent(events, protocol.EventError) {
		t.Fatalf("forged confirmation should fail: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("forged confirmation wrote artifacts: %v", err)
	}

	events = agent.Handle(context.Background(), "/build")
	confirm := firstConfirm(t, events)
	events = agent.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventBuildComplete) {
		t.Fatalf("valid confirmation should build: %+v", events)
	}
	events = agent.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventError) {
		t.Fatalf("replayed confirmation should fail: %+v", events)
	}
}

func TestAgentSessionCommands(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	oldID := agent.SessionID()

	clearEvents := agent.Handle(context.Background(), "/clear")
	if !hasEvent(clearEvents, protocol.EventViewClear) {
		t.Fatalf("missing view clear event: %+v", clearEvents)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".knote", "sessions", oldID+".jsonl")); err != nil {
		t.Fatalf("clear should keep session history file: %v", err)
	}

	newEvents := agent.Handle(context.Background(), "/new")
	newID := agent.SessionID()
	if newID == oldID {
		t.Fatal("/new did not create a new session id")
	}
	if !hasEvent(newEvents, protocol.EventSessionInfo) || !hasEvent(newEvents, protocol.EventViewClear) {
		t.Fatalf("/new did not emit session info and clear events: %+v", newEvents)
	}

	store := local.New(workspace)
	beforeResume, err := store.Load(context.Background(), oldID)
	if err != nil {
		t.Fatal(err)
	}
	resumeEvents := agent.Handle(context.Background(), "/resume "+oldID)
	if agent.SessionID() != oldID {
		t.Fatalf("/resume did not switch runtime session, got %s", agent.SessionID())
	}
	if !hasEvent(resumeEvents, protocol.EventSessionInfo) || !hasEvent(resumeEvents, protocol.EventViewClear) {
		t.Fatalf("/resume did not emit replay boundary and session info: %+v", resumeEvents)
	}
	afterResume, err := store.Load(context.Background(), oldID)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterResume) != len(beforeResume)+1 {
		t.Fatalf("/resume should append only fresh session.info to resumed session, before=%d after=%d", len(beforeResume), len(afterResume))
	}
}

func TestAgentReadOnlyCommands(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
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
		events := agent.Handle(context.Background(), tc.command)
		got := lastAssistant(events)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("%s output missing %q:\n%s", tc.command, tc.want, got)
		}
		if strings.Contains(got, "stubbed") {
			t.Fatalf("%s still returned stub output: %s", tc.command, got)
		}
	}
}

func TestAgentResumeWithoutIDListsRecentSessions(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := agent.SessionID()

	events := agent.Handle(context.Background(), "/resume")
	got := lastAssistant(events)
	if !strings.Contains(got, "Recent sessions") || !strings.Contains(got, sessionID) {
		t.Fatalf("/resume without id did not list recent sessions:\n%s", got)
	}
}

func TestAgentEvalWritesStableReport(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}

	events := agent.Handle(context.Background(), "/eval")
	confirm := firstConfirm(t, events)
	events = agent.Confirm(context.Background(), confirm, true)
	if !hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("eval did not report completion: %+v", events)
	}
	results, err := os.ReadFile(filepath.Join(workspace, "evals", "results.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(results), `"id":"smoke"`) || !strings.Contains(string(results), "Fake KAG answer") {
		t.Fatalf("unexpected eval results:\n%s", results)
	}
	report, err := os.ReadFile(filepath.Join(workspace, "evals", "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "adapter_errors: 0") {
		t.Fatalf("unexpected eval report:\n%s", report)
	}
}

func TestAgentReleaseRequiresEvalGateAndCleanWorkspace(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	mustRun(t, workspace, "git", "config", "user.email", "knote@example.com")
	mustRun(t, workspace, "git", "config", "user.name", "knote")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, workspace, "git", "add", ".knote/config.yaml")
	mustRun(t, workspace, "git", "commit", "-m", "initial")

	events := agent.Handle(context.Background(), "/release v0.1.0")
	if !hasEvent(events, protocol.EventError) || hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("release without eval should fail before confirm: %+v", events)
	}

	evalEvents := agent.Handle(context.Background(), "/eval")
	evalConfirm := firstConfirm(t, evalEvents)
	evalEvents = agent.Confirm(context.Background(), evalConfirm, true)
	if !hasEvent(evalEvents, protocol.EventAssistantDone) {
		t.Fatalf("eval failed: %+v", evalEvents)
	}

	events = agent.Handle(context.Background(), "/release v0.1.0")
	if !hasEvent(events, protocol.EventError) || !strings.Contains(lastError(events), "clean workspace") {
		t.Fatalf("release with uncommitted eval outputs should fail clean gate: %+v", events)
	}

	mustRun(t, workspace, "git", "add", "evals")
	mustRun(t, workspace, "git", "commit", "-m", "eval")
	events = agent.Handle(context.Background(), "/release v0.1.0")
	releaseConfirm := firstConfirm(t, events)
	events = agent.Confirm(context.Background(), releaseConfirm, true)
	if !hasEvent(events, protocol.EventVersionChanged) {
		t.Fatalf("release did not create tag: %+v", events)
	}
	if got := strings.TrimSpace(mustRunOutput(t, workspace, "git", "tag", "--list", "v0.1.0")); got != "v0.1.0" {
		t.Fatalf("tag missing after release: %q", got)
	}
}

func TestAgentReleaseRejectsStaleEvalAfterKnowledgeCommit(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	mustRun(t, workspace, "git", "config", "user.email", "knote@example.com")
	mustRun(t, workspace, "git", "config", "user.name", "knote")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("before\n"), 0o644))
	mustRun(t, workspace, "git", "add", ".knote/config.yaml", "sources")
	mustRun(t, workspace, "git", "commit", "-m", "initial")

	evalEvents := agent.Handle(context.Background(), "/eval")
	evalConfirm := firstConfirm(t, evalEvents)
	evalEvents = agent.Confirm(context.Background(), evalConfirm, true)
	if !hasEvent(evalEvents, protocol.EventAssistantDone) {
		t.Fatalf("eval failed: %+v", evalEvents)
	}
	mustRun(t, workspace, "git", "add", "evals")
	mustRun(t, workspace, "git", "commit", "-m", "eval")
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("after\n"), 0o644))
	mustRun(t, workspace, "git", "add", "sources")
	mustRun(t, workspace, "git", "commit", "-m", "knowledge changed")

	events := agent.Handle(context.Background(), "/release v0.1.0")
	if !hasEvent(events, protocol.EventError) || !strings.Contains(lastError(events), "stale") {
		t.Fatalf("stale eval should block release: %+v", events)
	}
}

func TestAgentCheckoutRequiresRefBeforeConfirm(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	agent, _, err := newTestAgent(t, workspace)
	if err != nil {
		t.Fatal(err)
	}

	events := agent.Handle(context.Background(), "/checkout")
	if !hasEvent(events, protocol.EventError) || hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("checkout without ref should fail before confirm: %+v", events)
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

func lastError(events []protocol.Event) string {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == protocol.EventError {
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

func mustRunOutput(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}
