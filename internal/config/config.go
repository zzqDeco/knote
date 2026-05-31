package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Workspace   string           `yaml:"workspace"`
	Permissions PermissionConfig `yaml:"permissions"`
	KAG         KAGConfig        `yaml:"kag"`
	Models      map[string]Model `yaml:"models"`
}

type PermissionConfig struct {
	BuildDefault string `yaml:"build_default"`
	GitDefault   string `yaml:"git_default"`
}

type KAGConfig struct {
	AdapterPath string `yaml:"adapter_path"`
	Host        string `yaml:"host"`
	Fake        bool   `yaml:"fake"`
	ConfigPath  string `yaml:"config_path,omitempty"`
	ProjectID   string `yaml:"project_id,omitempty"`
	Namespace   string `yaml:"namespace,omitempty"`
	Language    string `yaml:"language,omitempty"`
	RuntimeDir  string `yaml:"runtime_dir,omitempty"`
}

type Model struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
	BaseURL  string `yaml:"base_url,omitempty"`
}

func Default(workspace string) Config {
	return Config{
		Workspace: workspace,
		Permissions: PermissionConfig{
			BuildDefault: "confirm",
			GitDefault:   "confirm",
		},
		KAG: KAGConfig{
			AdapterPath: "adapters/kag/knote_kag_adapter.py",
			Host:        "http://127.0.0.1:8887",
			ProjectID:   "1",
			Namespace:   "KnoteKB",
			Language:    "en",
			RuntimeDir:  ".knote/kag-runtime",
		},
		Models: map[string]Model{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}
}

func LoadOrDefault(workspace string) (Config, error) {
	cfg := Default(workspace)
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
	if cfg.Workspace == "" {
		cfg.Workspace = workspace
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
	return cfg, nil
}

func Ensure(workspace string, cfg Config) error {
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
