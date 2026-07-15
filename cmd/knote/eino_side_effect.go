package main

import (
	"context"
	"fmt"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/runtime"
	runtimeeino "github.com/zzqDeco/knote/internal/runtime/eino"
)

func newEinoSideEffectGate(bridge *runtime.SideEffectBridge, approvedTools map[string]einotool.InvokableTool) einotools.SideEffectGate {
	execute := runtimeeino.NewSideEffectExecutor(approvedTools)
	return func(ctx context.Context, req einotools.SideEffectRequest) error {
		if bridge == nil {
			return fmt.Errorf("%s requires runtime confirmation; Eino side-effect bridge is not configured", req.ToolName)
		}
		return bridge.Request(ctx, runtime.SideEffectRequest{
			ToolName:        req.ToolName,
			Action:          req.Action,
			ArgumentsInJSON: req.ArgumentsInJSON,
			Summary:         req.Summary,
			Execute:         execute,
		})
	}
}
