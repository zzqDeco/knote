package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/zzqDeco/knote/internal/agent"
	"github.com/zzqDeco/knote/internal/knowledge"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
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

	agentRuntime, events, err := newAgent(context.Background(), *workspace, *resume)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	program := tea.NewProgram(tui.New(agentRuntime, events), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newAgent(ctx context.Context, workspacePath string, resumeID string) (*agent.Agent, []protocol.Event, error) {
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
	mode := knowledge.ModeReal
	if repoCfg.KAG.Fake {
		mode = knowledge.ModeFake
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
	return agent.New(ctx, agent.Dependencies{
		Workspace:     workspace,
		ResumeID:      resumeID,
		Config:        repoCfg,
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		Knowledge:     knowledge.New(knowledge.Options{Workspace: workspace, Repo: repo, Backend: kagClient, Mode: mode}),
		NewSessionID:  local.NewSessionID,
	})
}
