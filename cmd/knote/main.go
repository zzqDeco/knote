package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
	"github.com/zzqDeco/knote/internal/runtime"
	"github.com/zzqDeco/knote/internal/tui"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	workspace := flag.String("workspace", ".", "workspace path")
	resume := flag.String("resume", "", "session id to resume")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("version=%s commit=%s date=%s\n", version, commit, date)
		return
	}

	rt, events, err := newRuntime(context.Background(), *workspace, *resume)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	program := tea.NewProgram(tui.New(rt, events), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRuntime(ctx context.Context, workspacePath string, resumeID string) (runtime.Runtime, []protocol.Event, error) {
	workspace, err := filepath.Abs(workspacePath)
	if err != nil {
		return nil, nil, err
	}
	repo := local.New(workspace)
	repoCfg, err := repo.Config(ctx)
	if err != nil {
		return nil, nil, err
	}
	if os.Getenv("KNOTE_KAG_FAKE") == "1" {
		repoCfg.KAG.Fake = true
	}
	repoCfg.Workspace = workspace
	if err := repo.SaveConfig(ctx, repoCfg); err != nil {
		return nil, nil, err
	}
	knowledgeMode := versioned.ModeReal
	if repoCfg.KAG.Fake {
		knowledgeMode = versioned.ModeFake
	}
	runnerMode := runtime.RunnerModeDirect
	if os.Getenv("KNOTE_RUNTIME_MODE") == string(runtime.RunnerModeEino) {
		runnerMode = runtime.RunnerModeEino
	}
	kagClient := kag.Client{
		AdapterPath: repoCfg.KAG.AdapterPath,
		Workspace:   workspace,
		Host:        repoCfg.KAG.Host,
		Fake:        repoCfg.KAG.Fake,
		ConfigPath:  repoCfg.KAG.ConfigPath,
		ProjectID:   repoCfg.KAG.ProjectID,
		Namespace:   repoCfg.KAG.Namespace,
		Language:    repoCfg.KAG.Language,
		RuntimeDir:  repoCfg.KAG.RuntimeDir,
	}
	knowledgeService := versioned.New(versioned.Options{Workspace: workspace, Repo: repo, Versions: repo, Backend: kagClient, Mode: knowledgeMode})
	einoTools := einotools.NewWithOptions(einotools.Options{
		Service: knowledgeService,
		SideEffectGate: func(_ context.Context, req einotools.SideEffectRequest) error {
			return fmt.Errorf("%s requires runtime confirmation; Eino runner confirmation bridge is not enabled", req.ToolName)
		},
	})
	einoRunner, err := newEinoRunner(ctx, runnerMode, repoCfg, einoTools)
	if err != nil {
		return nil, nil, err
	}
	rt := runtime.New(runtime.Dependencies{
		Workspace:     workspace,
		Config:        repoCfg,
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		Knowledge:     knowledgeService,
		RunnerMode:    runnerMode,
		EinoRunner:    einoRunner,
		NewSessionID:  local.NewSessionID,
	})
	events, err := rt.Start(ctx, runtime.StartOptions{ResumeID: resumeID})
	return rt, events, err
}
