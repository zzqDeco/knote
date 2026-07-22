package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestFakeOverrideRemainsEphemeralAcrossPermissionedRestart(t *testing.T) {
	clearEinoEnv(t)
	ctx := context.Background()
	workspace := t.TempDir()
	store := local.New(workspace)
	persisted, err := store.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	persisted.KAG.Fake = false
	if err := store.SaveConfig(ctx, persisted); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("KNOTE_KAG_FAKE", "1")
	fakeStartup, err := loadStartupConfiguration(ctx, workspace, store)
	if err != nil {
		t.Fatal(err)
	}
	if fakeStartup.Persisted.KAG.Fake {
		t.Fatal("persisted config inherited KNOTE_KAG_FAKE")
	}
	if !fakeStartup.Effective.KAG.Fake || !fakeStartup.Permissioned.Enabled || !fakeStartup.Permissioned.Fake {
		t.Fatalf("fake override was not applied to the process config: %+v", fakeStartup)
	}
	if err := store.EnsureConfig(ctx, fakeStartup.Persisted); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KNOTE_KAG_FAKE", "")
	setCompletePermissionedConfig(t)
	permissionedStartup, err := loadStartupConfiguration(ctx, workspace, store)
	if err != nil {
		t.Fatalf("permissioned restart rejected after fake run: %v", err)
	}
	if permissionedStartup.Effective.KAG.Fake || !permissionedStartup.Permissioned.Enabled || permissionedStartup.Permissioned.Fake {
		t.Fatalf("unexpected permissioned restart config: %+v", permissionedStartup)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("environment-only fake run rewrote config:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestNewRuntimeDoesNotRewriteExistingConfig(t *testing.T) {
	clearEinoEnv(t)
	ctx := context.Background()
	workspace := t.TempDir()
	store := local.New(workspace)
	cfg, err := store.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	canonical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte("# preserve startup formatting\n"), canonical...)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KNOTE_KAG_FAKE", "1")
	t.Setenv("KNOTE_EINO_PROVIDER", "openai-compatible")
	t.Setenv("KNOTE_EINO_MODEL", "test-model")
	t.Setenv("KNOTE_EINO_API_KEY", "test-key")
	t.Setenv("KNOTE_EINO_BASE_URL", "http://127.0.0.1:1/v1")
	if _, _, err := newRuntime(ctx, workspace, ""); err != nil {
		t.Fatalf("newRuntime failed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("startup rewrote existing config:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestNewRuntimeCreatesFreshNestedWorkspaceBeforeDefaultAuditResolution(t *testing.T) {
	clearEinoEnv(t)
	workspace := filepath.Join(t.TempDir(), "missing", "workspace")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	t.Setenv("KNOTE_EINO_PROVIDER", "openai-compatible")
	t.Setenv("KNOTE_EINO_MODEL", "test-model")
	t.Setenv("KNOTE_EINO_API_KEY", "test-key")
	t.Setenv("KNOTE_EINO_BASE_URL", "http://127.0.0.1:1/v1")

	rt, _, err := newRuntime(context.Background(), workspace, "")
	if err != nil {
		t.Fatalf("newRuntime with fresh nested workspace failed: %v", err)
	}
	if rt.SessionID() == "" {
		t.Fatal("fresh workspace runtime did not start a session")
	}
	if _, err := os.Stat(filepath.Join(workspace, ".knote", "config.yaml")); err != nil {
		t.Fatalf("fresh workspace config was not created: %v", err)
	}
	auditRoot, err := permissionedAuditRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(auditRoot) })
}

func TestPermissionedValidationFinishesBeforeInitialConfigWrite(t *testing.T) {
	clearEinoEnv(t)
	workspace := t.TempDir()
	t.Setenv(permissionedEnabledEnv, "1")

	_, _, err := newRuntime(context.Background(), workspace, "")
	if err == nil {
		t.Fatal("incomplete permissioned config should fail")
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("failed permissioned validation wrote config, stat err=%v", statErr)
	}
}

func TestPermissionedValidationFailurePreservesExistingConfig(t *testing.T) {
	clearEinoEnv(t)
	ctx := context.Background()
	workspace := t.TempDir()
	store := local.New(workspace)
	cfg, err := store.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "config.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(permissionedEnabledEnv, "1")
	if _, _, err := newRuntime(ctx, workspace, ""); err == nil {
		t.Fatal("incomplete permissioned config should fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("failed permissioned validation changed config:\nbefore=%s\nafter=%s", before, after)
	}
}

func setCompletePermissionedConfig(t *testing.T) {
	t.Helper()
	t.Setenv(permissionedEnabledEnv, "1")
	t.Setenv(permissionedProviderEnv, "permissioned_provider:create")
	t.Setenv(openFGAEndpointEnv, "http://127.0.0.1:8080")
	t.Setenv(openFGAStoreIDEnv, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	t.Setenv(openFGAModelIDEnv, "01ARZ3NDEKTSV4RRFFQ69G5FAW")
	t.Setenv(authz.APITokenEnv, "test-token")
}
