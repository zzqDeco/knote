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
