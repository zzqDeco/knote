package eino

import (
	"context"
	"fmt"

	"github.com/cloudwego/eino/adk"
	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

type Options struct {
	Tools           []einotool.InvokableTool
	EnableStreaming bool
	CheckPointStore adk.CheckPointStore
}

type Runner struct {
	tools           []einotool.InvokableTool
	enableStreaming bool
	checkPointStore adk.CheckPointStore
}

var _ runtime.EinoRunner = (*Runner)(nil)

func NewRunner(opts Options) *Runner {
	return &Runner{
		tools:           append([]einotool.InvokableTool(nil), opts.Tools...),
		enableStreaming: opts.EnableStreaming,
		checkPointStore: opts.CheckPointStore,
	}
}

func (r *Runner) ToolInventory(ctx context.Context) ([]runtime.RunnerToolInfo, error) {
	out := make([]runtime.RunnerToolInfo, 0, len(r.tools))
	for _, candidate := range r.tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(ctx)
		if err != nil {
			return nil, fmt.Errorf("load Eino tool info: %w", err)
		}
		out = append(out, runtime.RunnerToolInfo{
			Name:        info.Name,
			Description: info.Desc,
		})
	}
	return out, nil
}

func (r *Runner) Run(context.Context, runtime.EinoRunInput) ([]protocol.Event, error) {
	return nil, fmt.Errorf("eino runner skeleton is not connected to a chat model")
}

func (r *Runner) RunnerConfig(agent adk.Agent) adk.RunnerConfig {
	return adk.RunnerConfig{
		Agent:           agent,
		EnableStreaming: r.enableStreaming,
		CheckPointStore: r.checkPointStore,
	}
}

func (r *Runner) NewADKRunner(ctx context.Context, agent adk.Agent) *adk.Runner {
	return adk.NewRunner(ctx, r.RunnerConfig(agent))
}
