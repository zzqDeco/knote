package local

import (
	"context"
	"errors"
	"fmt"
	"io"
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

func saveConfig(ctx context.Context, workspace string, cfg repository.Config, beforeCommit func() error) error {
	return writeConfig(ctx, workspace, cfg, true, beforeCommit)
}

func ensureConfig(ctx context.Context, workspace string, cfg repository.Config, beforeCommit func() error) error {
	return writeConfig(ctx, workspace, cfg, false, beforeCommit)
}

func writeConfig(
	ctx context.Context,
	workspace string,
	cfg repository.Config,
	replace bool,
	beforeCommit func() error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg = normalizeConfig(cfg, workspace)
	dir := filepath.Join(workspace, ".knote")
	if err := ensureConfigDirectory(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "config.yaml")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("config target is not a regular file")
		}
		if !replace {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	closeTemporary := true
	defer func() {
		if closeTemporary {
			_ = temporary.Close()
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	written, err := temporary.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closeTemporary = false
	if err := ctx.Err(); err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if replace {
		err = replaceArtifactFile(temporaryPath, path)
	} else {
		err = installConfigFile(temporaryPath, path)
		if err != nil && errors.Is(err, os.ErrExist) {
			info, statErr := os.Lstat(path)
			if statErr == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
				return nil
			}
		}
	}
	if err != nil {
		return err
	}
	if err := syncArtifactDirectory(dir); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}

func ensureConfigDirectory(dir string) error {
	if err := ensureDirectoryTree(dir); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return nil
}

func ensureDirectoryTree(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	missing := make([]string, 0, 2)
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if len(missing) == 0 {
					return fmt.Errorf("directory path %q is not a directory", current)
				}
				resolvedInfo, err := os.Stat(current)
				if err != nil || !resolvedInfo.IsDir() {
					return fmt.Errorf("directory path %q is not a directory", current)
				}
				break
			}
			if !info.IsDir() {
				return fmt.Errorf("directory path %q is not a directory", current)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for directory %q", dir)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		path := missing[i]
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("directory path %q is not a directory", path)
		}
		if err := syncArtifactDirectory(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync parent of directory %q: %w", path, err)
		}
	}
	return nil
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
