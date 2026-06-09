package eino

import (
	"context"
	"fmt"
	"strings"
	"time"

	openai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/adk"
	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
)

const defaultChatModelAgentInstruction = "You are knote's knowledge agent. Use knote tools when workspace knowledge, artifacts, versions, or eval results are needed. Do not call mutating tools unless the user explicitly requested that operation."

type ChatModelProfile struct {
	Provider string
	Model    string
	BaseURL  string
}

type ChatModelAgentOptions struct {
	Profile          ChatModelProfile
	ProviderOverride string
	ModelOverride    string
	BaseURLOverride  string
	APIKey           string
	ReasoningEffort  string
	Timeout          time.Duration
	Tools            []einotool.InvokableTool
	Instruction      string
}

type OpenAIChatModelConfig struct {
	Provider        string
	Model           string
	BaseURL         string
	APIKey          string
	ReasoningEffort openai.ReasoningEffortLevel
	Timeout         time.Duration
}

func NewChatModelAgent(ctx context.Context, opts ChatModelAgentOptions) (adk.Agent, error) {
	cfg, err := ResolveOpenAIChatModelConfig(opts)
	if err != nil {
		return nil, err
	}
	chatModel, err := openai.NewChatModel(ctx, &openai.ChatModelConfig{
		APIKey:          cfg.APIKey,
		Model:           cfg.Model,
		BaseURL:         cfg.BaseURL,
		ReasoningEffort: cfg.ReasoningEffort,
		Timeout:         cfg.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create OpenAI-compatible Eino chat model: %w", err)
	}
	instruction := strings.TrimSpace(opts.Instruction)
	if instruction == "" {
		instruction = defaultChatModelAgentInstruction
	}
	agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:        "knote",
		Description: "Knowledge agent for knote workspaces.",
		Instruction: instruction,
		Model:       chatModel,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools: invokableToolsAsBaseTools(opts.Tools),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create Eino ChatModelAgent: %w", err)
	}
	return agent, nil
}

func ResolveOpenAIChatModelConfig(opts ChatModelAgentOptions) (OpenAIChatModelConfig, error) {
	provider := strings.ToLower(strings.TrimSpace(firstNonEmpty(opts.ProviderOverride, opts.Profile.Provider)))
	if provider == "" {
		return OpenAIChatModelConfig{}, fmt.Errorf("Eino mode requires an OpenAI-compatible model provider")
	}
	if provider != "openai" && provider != "openai-compatible" && provider != "openai_compatible" {
		return OpenAIChatModelConfig{}, fmt.Errorf("Eino mode requires model provider openai or openai-compatible, got %q", provider)
	}
	model := strings.TrimSpace(firstNonEmpty(opts.ModelOverride, opts.Profile.Model))
	if model == "" {
		return OpenAIChatModelConfig{}, fmt.Errorf("Eino mode requires a model name")
	}
	apiKey := strings.TrimSpace(opts.APIKey)
	if apiKey == "" {
		return OpenAIChatModelConfig{}, fmt.Errorf("Eino mode requires KNOTE_EINO_API_KEY or OPENAI_API_KEY")
	}
	effort, err := parseReasoningEffort(opts.ReasoningEffort)
	if err != nil {
		return OpenAIChatModelConfig{}, err
	}
	return OpenAIChatModelConfig{
		Provider:        provider,
		Model:           model,
		BaseURL:         strings.TrimSpace(firstNonEmpty(opts.BaseURLOverride, opts.Profile.BaseURL)),
		APIKey:          apiKey,
		ReasoningEffort: effort,
		Timeout:         opts.Timeout,
	}, nil
}

func parseReasoningEffort(value string) (openai.ReasoningEffortLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return "", nil
	case "low":
		return openai.ReasoningEffortLevelLow, nil
	case "medium":
		return openai.ReasoningEffortLevelMedium, nil
	case "high":
		return openai.ReasoningEffortLevelHigh, nil
	default:
		return "", fmt.Errorf("unsupported Eino reasoning effort %q", value)
	}
}

func invokableToolsAsBaseTools(tools []einotool.InvokableTool) []einotool.BaseTool {
	out := make([]einotool.BaseTool, 0, len(tools))
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		out = append(out, candidate)
	}
	return out
}
