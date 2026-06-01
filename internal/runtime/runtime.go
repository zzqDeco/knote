package runtime

import (
	"context"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/zzqDeco/knote/internal/agent"
	"github.com/zzqDeco/knote/internal/config"
	"github.com/zzqDeco/knote/internal/knowledge"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
	"github.com/zzqDeco/knote/internal/session"
)

type Runtime = agent.Agent

type Options struct {
	Workspace string
	ResumeID  string
}

func New(ctx context.Context, opts Options) (*Runtime, []protocol.Event, error) {
	workspace, err := filepath.Abs(firstNonEmpty(opts.Workspace, "."))
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.LoadOrDefault(workspace)
	if err != nil {
		return nil, nil, err
	}
	if os.Getenv("KNOTE_KAG_FAKE") == "1" {
		cfg.KAG.Fake = true
	}
	if err := config.Ensure(workspace, cfg); err != nil {
		return nil, nil, err
	}
	settings, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	repo := local.New(workspace)
	repoCfg, err := repo.Config(ctx)
	if err != nil {
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
		ResumeID:      opts.ResumeID,
		Config:        repoCfg,
		SettingsYAML:  string(settings),
		Sessions:      repo,
		Versions:      repo,
		WorkspaceRepo: repo,
		Knowledge:     knowledge.New(knowledge.Options{Workspace: workspace, Repo: repo, Backend: kagClient, Mode: mode}),
		NewSessionID:  session.NewID,
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
