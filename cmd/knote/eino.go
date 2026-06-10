package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/repository"
	runtimeeino "github.com/zzqDeco/knote/internal/runtime/eino"
)

func newEinoRunner(ctx context.Context, cfg repository.Config, tools []einotool.InvokableTool) (*runtimeeino.Runner, error) {
	opts := runtimeeino.Options{Tools: tools}
	profile, err := selectEinoModelProfile(cfg)
	if err != nil {
		return nil, err
	}
	agent, err := runtimeeino.NewChatModelAgent(ctx, runtimeeino.ChatModelAgentOptions{
		Profile:          profile,
		ProviderOverride: einoProviderOverride(),
		ModelOverride:    firstEnv("KNOTE_EINO_MODEL", "OPENAI_MODEL"),
		BaseURLOverride:  firstEnv("KNOTE_EINO_BASE_URL", "OPENAI_BASE_URL"),
		APIKey:           firstEnv("KNOTE_EINO_API_KEY", "OPENAI_API_KEY"),
		ReasoningEffort:  firstEnv("KNOTE_EINO_REASONING_EFFORT", "OPENAI_REASONING_EFFORT"),
		Tools:            tools,
	})
	if err != nil {
		return nil, err
	}
	opts.Agent = agent
	return runtimeeino.NewRunner(opts), nil
}

func einoProviderOverride() string {
	if provider := strings.TrimSpace(os.Getenv("KNOTE_EINO_PROVIDER")); provider != "" {
		return provider
	}
	if firstEnv("KNOTE_EINO_MODEL", "OPENAI_MODEL", "KNOTE_EINO_API_KEY", "OPENAI_API_KEY", "KNOTE_EINO_BASE_URL", "OPENAI_BASE_URL") != "" {
		return "openai-compatible"
	}
	return ""
}

func selectEinoModelProfile(cfg repository.Config) (runtimeeino.ChatModelProfile, error) {
	name := strings.TrimSpace(os.Getenv("KNOTE_EINO_MODEL_PROFILE"))
	if name == "" {
		name = "default"
	}
	if cfg.Models == nil {
		return runtimeeino.ChatModelProfile{}, fmt.Errorf("Eino model profile %q not found in config", name)
	}
	profile, ok := cfg.Models[name]
	if !ok {
		return runtimeeino.ChatModelProfile{}, fmt.Errorf("Eino model profile %q not found in config", name)
	}
	return runtimeeino.ChatModelProfile{
		Provider: profile.Provider,
		Model:    profile.Model,
		BaseURL:  profile.BaseURL,
	}, nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
