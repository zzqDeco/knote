package eino

import (
	"context"
	"strings"
	"testing"

	openai "github.com/cloudwego/eino-ext/components/model/openai"
	einotool "github.com/cloudwego/eino/components/tool"
)

func TestResolveOpenAIChatModelConfigRequiresCompatibleProvider(t *testing.T) {
	_, err := ResolveOpenAIChatModelConfig(ChatModelAgentOptions{
		Profile: ChatModelProfile{Provider: "local", Model: "deterministic"},
		APIKey:  "test-key",
	})
	if err == nil || !strings.Contains(err.Error(), "openai or openai-compatible") {
		t.Fatalf("expected provider error, got %v", err)
	}
}

func TestResolveOpenAIChatModelConfigUsesOverrides(t *testing.T) {
	cfg, err := ResolveOpenAIChatModelConfig(ChatModelAgentOptions{
		Profile:          ChatModelProfile{Provider: "local", Model: "deterministic", BaseURL: "https://profile.example/v1"},
		ProviderOverride: "openai-compatible",
		ModelOverride:    "gpt-test",
		BaseURLOverride:  "https://override.example/v1",
		APIKey:           "test-key",
		ReasoningEffort:  "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "openai-compatible" {
		t.Fatalf("unexpected provider %q", cfg.Provider)
	}
	if cfg.Model != "gpt-test" {
		t.Fatalf("unexpected model %q", cfg.Model)
	}
	if cfg.BaseURL != "https://override.example/v1" {
		t.Fatalf("unexpected base URL %q", cfg.BaseURL)
	}
	if cfg.ReasoningEffort != openai.ReasoningEffortLevelHigh {
		t.Fatalf("unexpected reasoning effort %q", cfg.ReasoningEffort)
	}
}

func TestNewChatModelAgentBuildsReadyAgent(t *testing.T) {
	agent, err := NewChatModelAgent(context.Background(), ChatModelAgentOptions{
		Profile: ChatModelProfile{
			Provider: "openai",
			Model:    "gpt-test",
		},
		APIKey: "test-key",
		Tools:  []einotool.InvokableTool{fakeTool{name: "knote_query", desc: "Query knowledge."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent == nil {
		t.Fatal("expected agent")
	}
	runner := NewRunner(Options{Agent: agent})
	if err := runner.Ready(context.Background()); err != nil {
		t.Fatalf("runner should be ready with ADK agent: %v", err)
	}
}
