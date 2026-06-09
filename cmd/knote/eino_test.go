package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		"OPENAI_MODEL",
		"OPENAI_API_KEY",
		"OPENAI_BASE_URL",
		"OPENAI_REASONING_EFFORT",
	} {
		t.Setenv(name, "")
	}
}
