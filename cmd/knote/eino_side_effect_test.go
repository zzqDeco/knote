package main

import (
	"context"
	"errors"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestPermissionedScopeRefreshFollowsSuccessfulScopeChangingSideEffects(t *testing.T) {
	for _, toolName := range []string{einotools.NameBuild, einotools.NameCheckout} {
		t.Run(toolName, func(t *testing.T) {
			refreshCalls := 0
			execute := withPermissionedScopeRefresh(
				toolName,
				func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
					return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, "session_a", "done", nil)}, nil
				},
				func(context.Context) error {
					refreshCalls++
					return nil
				},
			)
			events, err := execute(context.Background(), runtime.SideEffectRequest{ToolName: toolName})
			if err != nil {
				t.Fatal(err)
			}
			if refreshCalls != 1 || len(events) != 1 || events[0].Type != protocol.EventToolComplete {
				t.Fatalf("refresh calls=%d events=%+v", refreshCalls, events)
			}
		})
	}
}

func TestPermissionedScopeRefreshSkipsNonScopeChangingSideEffects(t *testing.T) {
	refreshCalls := 0
	execute := withPermissionedScopeRefresh(
		einotools.NameCommit,
		func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) { return nil, nil },
		func(context.Context) error {
			refreshCalls++
			return nil
		},
	)
	if _, err := execute(context.Background(), runtime.SideEffectRequest{ToolName: einotools.NameCommit}); err != nil {
		t.Fatal(err)
	}
	if refreshCalls != 0 {
		t.Fatalf("commit refresh calls = %d, want 0", refreshCalls)
	}
}

func TestPermissionedScopeRefreshFailsClosedWithoutSuccessEvents(t *testing.T) {
	execute := withPermissionedScopeRefresh(
		einotools.NameBuild,
		func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
			return []protocol.Event{protocol.NewEvent(protocol.EventBuildComplete, "session_a", "done", nil)}, nil
		},
		func(context.Context) error { return errors.New("private scope error") },
	)
	events, err := execute(context.Background(), runtime.SideEffectRequest{ToolName: einotools.NameBuild})
	if err == nil || err.Error() != "side effect failed" {
		t.Fatalf("refresh error = %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("refresh failure leaked success events: %+v", events)
	}
}
