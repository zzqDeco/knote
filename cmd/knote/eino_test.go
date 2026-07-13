package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestValidateRuntimeModeRejectsDirect(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_RUNTIME_MODE", "direct")
	if err := validateRuntimeMode(); err == nil || !strings.Contains(err.Error(), "Eino runtime only") {
		t.Fatalf("expected direct runtime mode to be rejected, got %v", err)
	}
	t.Setenv("KNOTE_RUNTIME_MODE", "")
	if err := validateRuntimeMode(); err != nil {
		t.Fatalf("empty runtime mode should use Eino-only default: %v", err)
	}
	t.Setenv("KNOTE_RUNTIME_MODE", "eino")
	if err := validateRuntimeMode(); err != nil {
		t.Fatalf("explicit Eino runtime mode should be accepted: %v", err)
	}
}

func TestNewRuntimeRejectsRuntimeModeBeforeWritingConfig(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_RUNTIME_MODE", "direct")
	workspace := t.TempDir()
	_, _, err := newRuntime(context.Background(), workspace, "")
	if err == nil || !strings.Contains(err.Error(), "Eino runtime only") {
		t.Fatalf("expected runtime mode error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(workspace, ".knote", "config.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("invalid runtime mode should not write config, stat err=%v", statErr)
	}
}

func TestNewEinoRunnerFailsFastForDefaultLocalProfile(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_EINO_PROVIDER", "local")
	t.Setenv("KNOTE_EINO_API_KEY", "test-key")
	runner, err := newEinoRunner(context.Background(), repository.Config{
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "openai or openai-compatible") {
		t.Fatalf("expected provider error, got runner=%v err=%v", runner, err)
	}
}

func TestNewEinoRunnerUsesOpenAIEnvironmentOverrides(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("OPENAI_MODEL", "gpt-test")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", "https://example.invalid/v1")
	runner, err := newEinoRunner(context.Background(), repository.Config{
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Ready(context.Background()); err != nil {
		t.Fatalf("runner should be ready with environment-configured agent: %v", err)
	}
}

func TestPermissionedPrincipalUsesTrustedRuntimeEnvironment(t *testing.T) {
	t.Setenv(permissionedPrincipalEnv, "")
	principal, err := permissionedPrincipal()
	if err != nil || principal != "alice" {
		t.Fatalf("default principal = %q, %v; want alice", principal, err)
	}

	t.Setenv(permissionedPrincipalEnv, "bob")
	principal, err = permissionedPrincipal()
	if err != nil || principal != "bob" {
		t.Fatalf("configured principal = %q, %v; want bob", principal, err)
	}

	t.Setenv(permissionedPrincipalEnv, "mallory")
	if _, err := permissionedPrincipal(); err == nil || !strings.Contains(err.Error(), permissionedPrincipalEnv) {
		t.Fatalf("unknown principal should fail closed, got %v", err)
	}
}

func TestPermissionedAuthorizationProviderOnlyEnablesFakeMode(t *testing.T) {
	t.Setenv(permissionedPrincipalEnv, "mallory")
	provider, err := permissionedAuthorizationProvider(false)
	if err != nil || provider != nil {
		t.Fatalf("real-mode provider = %v, %v; want nil", provider, err)
	}
	if _, err := permissionedAuthorizationProvider(true); err == nil {
		t.Fatal("fake mode accepted an unknown fixture principal")
	}

	t.Setenv(permissionedPrincipalEnv, "bob")
	provider, err = permissionedAuthorizationProvider(true)
	if err != nil || provider == nil {
		t.Fatalf("fake-mode provider = %v, %v; want configured provider", provider, err)
	}
	authorization, err := provider(context.Background(), "sess_fake")
	if err != nil || authorization.PrincipalID != "bob" || authorization.SessionID != "sess_fake" {
		t.Fatalf("fake-mode authorization = %+v, %v", authorization, err)
	}
}

func TestPermissionedToolsAreNotSelectedWithoutImplementedPrimitives(t *testing.T) {
	service := versioned.New(versioned.Options{})
	all := einotools.New(service)
	realMode := permissionedTools(all, false)
	for _, candidate := range realMode {
		info, err := candidate.Info(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Name == einotools.NameQuery || info.Name == einotools.NameExplain || info.Name == einotools.NameEval {
			t.Fatalf("real mode selected unsupported permissioned tool %s", info.Name)
		}
	}
	if got, want := len(realMode), len(all)-3; got != want {
		t.Fatalf("real-mode tool count = %d, want %d", got, want)
	}
	fakeMode := permissionedTools(all, true)
	if got, want := len(fakeMode), len(all)-1; got != want {
		t.Fatalf("fake mode tool count = %d, want %d", got, want)
	}
	for _, candidate := range fakeMode {
		info, err := candidate.Info(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Name == einotools.NameEval {
			t.Fatal("fake mode retained eval before authorized explain is implemented")
		}
	}

	registry := einotools.ByName(service)
	permissionedToolMap(registry, false)
	if registry[einotools.NameQuery] != nil || registry[einotools.NameExplain] != nil || registry[einotools.NameEval] != nil {
		t.Fatal("real-mode approved registry retained query, explain, or eval")
	}
	registry = einotools.ByName(service)
	permissionedToolMap(registry, true)
	if registry[einotools.NameEval] != nil || registry[einotools.NameQuery] == nil || registry[einotools.NameExplain] == nil {
		t.Fatal("fake-mode approved registry did not retain only authorized knowledge tools")
	}
}

func clearEinoEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"KNOTE_EINO_PROVIDER",
		"KNOTE_EINO_MODEL",
		"KNOTE_EINO_API_KEY",
		"KNOTE_EINO_BASE_URL",
		"KNOTE_EINO_REASONING_EFFORT",
		"KNOTE_EINO_MODEL_PROFILE",
		"KNOTE_RUNTIME_MODE",
		permissionedPrincipalEnv,
		"OPENAI_MODEL",
		"OPENAI_API_KEY",
		"OPENAI_BASE_URL",
		"OPENAI_REASONING_EFFORT",
	} {
		t.Setenv(name, "")
	}
}
