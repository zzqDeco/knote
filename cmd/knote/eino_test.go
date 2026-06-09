package main

import (
	"context"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestNewEinoRunnerDirectModeDoesNotRequireModelConfig(t *testing.T) {
	clearEinoEnv(t)
	runner, err := newEinoRunner(context.Background(), runtime.RunnerModeDirect, repository.Config{
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if runner == nil {
		t.Fatal("expected runner")
	}
}

func TestNewEinoRunnerFailsFastForDefaultLocalProfile(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_EINO_API_KEY", "test-key")
	runner, err := newEinoRunner(context.Background(), runtime.RunnerModeEino, repository.Config{
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
	t.Setenv("KNOTE_EINO_PROVIDER", "openai-compatible")
	t.Setenv("KNOTE_EINO_MODEL", "gpt-test")
	t.Setenv("KNOTE_EINO_API_KEY", "test-key")
	t.Setenv("KNOTE_EINO_BASE_URL", "https://example.invalid/v1")
	runner, err := newEinoRunner(context.Background(), runtime.RunnerModeEino, repository.Config{
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
		"OPENAI_MODEL",
		"OPENAI_API_KEY",
		"OPENAI_BASE_URL",
		"OPENAI_REASONING_EFFORT",
	} {
		t.Setenv(name, "")
	}
}
