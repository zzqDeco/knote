package main

import (
	"context"
	"errors"
	"fmt"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
	runtimeeino "github.com/zzqDeco/knote/internal/runtime/eino"
)

func newEinoSideEffectGate(
	bridge *runtime.SideEffectBridge,
	approvedTools map[string]einotool.InvokableTool,
	fakeBuildAuthorization runtime.AuthorizationContextProvider,
	permissionedScopeRefresh func(context.Context) error,
) einotools.SideEffectGate {
	execute := runtimeeino.NewSideEffectExecutor(approvedTools)
	return func(ctx context.Context, req einotools.SideEffectRequest) error {
		if bridge == nil {
			return fmt.Errorf("%s requires runtime confirmation; Eino side-effect bridge is not configured", req.ToolName)
		}
		request := runtime.SideEffectRequest{
			ToolName:        req.ToolName,
			Action:          req.Action,
			ArgumentsInJSON: req.ArgumentsInJSON,
			Summary:         req.Summary,
			Execute:         execute,
		}
		if req.ToolName == einotools.NameBuild && fakeBuildAuthorization != nil {
			request.Execute = func(runCtx context.Context, sideEffect runtime.SideEffectRequest) ([]protocol.Event, error) {
				authorization, err := fakeBuildAuthorization(runCtx, sideEffect.SessionID)
				if err != nil {
					return nil, errors.New("side effect failed")
				}
				runCtx, err = protocol.WithAuthorizationContext(runCtx, authorization)
				if err != nil {
					return nil, errors.New("side effect failed")
				}
				return execute(runCtx, sideEffect)
			}
		}
		request.Execute = withPermissionedScopeRefresh(
			req.ToolName, request.Execute, permissionedScopeRefresh,
		)
		return bridge.Request(ctx, request)
	}
}

func withPermissionedScopeRefresh(
	toolName string,
	execute runtime.SideEffectExecutor,
	refresh func(context.Context) error,
) runtime.SideEffectExecutor {
	if execute == nil || refresh == nil || !permissionedScopeChangingTool(toolName) {
		return execute
	}
	return func(ctx context.Context, request runtime.SideEffectRequest) ([]protocol.Event, error) {
		events, err := execute(ctx, request)
		if err != nil {
			return events, err
		}
		if err := refresh(ctx); err != nil {
			return nil, errors.New("side effect failed")
		}
		return events, nil
	}
}

func permissionedScopeChangingTool(toolName string) bool {
	return toolName == einotools.NameBuild || toolName == einotools.NameCheckout
}
