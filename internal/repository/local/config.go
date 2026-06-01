package local

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/zzqDeco/knote/internal/repository"
)

func defaultConfig(workspace string) repository.Config {
	return repository.Config{
		Workspace: workspace,
		Permissions: repository.PermissionConfig{
			BuildDefault: "confirm",
			GitDefault:   "confirm",
		},
		KAG: repository.KAGConfig{
			AdapterPath: "adapters/kag/knote_kag_adapter.py",
			Host:        "http://127.0.0.1:8887",
			ProjectID:   "1",
			Namespace:   "KnoteKB",
			Language:    "en",
			RuntimeDir:  ".knote/kag-runtime",
		},
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}
}

func loadConfigOrDefault(workspace string) (repository.Config, error) {
	cfg := defaultConfig(workspace)
	path := filepath.Join(workspace, ".knote", "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return normalizeConfig(cfg, workspace), nil
}

func ensureConfig(workspace string, cfg repository.Config) error {
	cfg = normalizeConfig(cfg, workspace)
	dir := filepath.Join(workspace, ".knote")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.yaml"), data, 0o644)
}

func normalizeConfig(cfg repository.Config, workspace string) repository.Config {
	if cfg.Workspace == "" {
		cfg.Workspace = workspace
	}
	if cfg.Permissions.BuildDefault == "" {
		cfg.Permissions.BuildDefault = "confirm"
	}
	if cfg.Permissions.GitDefault == "" {
		cfg.Permissions.GitDefault = "confirm"
	}
	if cfg.KAG.Host == "" {
		cfg.KAG.Host = "http://127.0.0.1:8887"
	}
	if cfg.KAG.AdapterPath == "" {
		cfg.KAG.AdapterPath = "adapters/kag/knote_kag_adapter.py"
	}
	if cfg.KAG.ProjectID == "" {
		cfg.KAG.ProjectID = "1"
	}
	if cfg.KAG.Namespace == "" {
		cfg.KAG.Namespace = "KnoteKB"
	}
	if cfg.KAG.Language == "" {
		cfg.KAG.Language = "en"
	}
	if cfg.KAG.RuntimeDir == "" {
		cfg.KAG.RuntimeDir = ".knote/kag-runtime"
	}
	if cfg.Models == nil {
		cfg.Models = map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		}
	}
	return cfg
}
