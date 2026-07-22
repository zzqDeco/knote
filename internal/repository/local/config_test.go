package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/zzqDeco/knote/internal/repository"
)

func TestSaveConfigUsesRestrictiveModeAndRoundTrips(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	cfg := defaultConfig(workspace)
	cfg.KAG.Host = "http://127.0.0.1:9999"

	if err := store.SaveConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %04o; want 0600", got)
	}
	loaded, err := store.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KAG.Host != cfg.KAG.Host {
		t.Fatalf("config host = %q; want %q", loaded.KAG.Host, cfg.KAG.Host)
	}
}

func TestEnsureConfigLeavesExistingBytesUnchanged(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	original := defaultConfig(workspace)
	original.KAG.Host = "http://127.0.0.1:1111"
	if err := store.SaveConfig(ctx, original); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	replacement := original
	replacement.KAG.Host = "http://127.0.0.1:2222"
	if err := store.EnsureConfig(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("startup ensure rewrote existing config:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestEnsureConfigCreatesNestedWorkspaceWithRestrictiveDirectories(t *testing.T) {
	ctx := context.Background()
	workspace := filepath.Join(t.TempDir(), "missing", "workspace")
	store := New(workspace)
	if err := store.EnsureConfig(ctx, defaultConfig(workspace)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{workspace, filepath.Join(workspace, ".knote")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("directory %s mode = %04o; want 0700", path, got)
		}
	}
}

func TestEnsureConfigAllowsSymlinkedExistingParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on some Windows hosts")
	}
	ctx := context.Background()
	realParent := t.TempDir()
	linkRoot := t.TempDir()
	linkedParent := filepath.Join(linkRoot, "parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(linkedParent, "missing", "workspace")
	if err := New(workspace).EnsureConfig(ctx, defaultConfig(workspace)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "missing", "workspace", ".knote", "config.yaml")); err != nil {
		t.Fatalf("config was not created through symlinked parent: %v", err)
	}
}

func TestConcurrentEnsureConfigPublishesOneCompleteConfig(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	configs := []repository.Config{defaultConfig(workspace), defaultConfig(workspace)}
	configs[0].KAG.Host = "http://127.0.0.1:1111"
	configs[1].KAG.Host = "http://127.0.0.1:2222"
	start := make(chan struct{})
	errs := make(chan error, len(configs))
	var wg sync.WaitGroup
	for _, cfg := range configs {
		cfg := cfg
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- New(workspace).EnsureConfig(ctx, cfg)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := New(workspace).Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KAG.Host != configs[0].KAG.Host && loaded.KAG.Host != configs[1].KAG.Host {
		t.Fatalf("concurrent config publish produced unexpected host %q", loaded.KAG.Host)
	}
}

func TestConfigCommitFailurePreservesExistingBytes(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	original := defaultConfig(workspace)
	original.KAG.Host = "http://127.0.0.1:1111"
	if err := store.SaveConfig(ctx, original); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected config commit failure")
	failing := New(workspace)
	failing.beforeConfigCommit = func() error { return injected }
	replacement := original
	replacement.KAG.Host = "http://127.0.0.1:2222"
	if err := failing.SaveConfig(ctx, replacement); !errors.Is(err, injected) {
		t.Fatalf("SaveConfig error = %v; want %v", err, injected)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("failed config update changed existing bytes:\nbefore=%s\nafter=%s", before, after)
	}
	assertNoConfigTemps(t, workspace)
}

func TestConfigCommitFailureDoesNotCreateConfig(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	injected := errors.New("injected config commit failure")
	store := New(workspace)
	store.beforeConfigCommit = func() error { return injected }

	if err := store.EnsureConfig(ctx, defaultConfig(workspace)); !errors.Is(err, injected) {
		t.Fatalf("EnsureConfig error = %v; want %v", err, injected)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed initial config write left target behind: %v", err)
	}
	assertNoConfigTemps(t, workspace)
}

func assertNoConfigTemps(t *testing.T, workspace string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(workspace, ".knote", ".config-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary config files were not cleaned up: %v", matches)
	}
}
