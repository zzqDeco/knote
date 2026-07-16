package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestPermissionedScopeRefreshFollowsSuccessfulScopeChangingSideEffects(t *testing.T) {
	for _, toolName := range []string{einotools.NameBuild, einotools.NameCheckout} {
		t.Run(toolName, func(t *testing.T) {
			var calls []string
			execute := withPermissionedScopeRefresh(
				toolName,
				func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
					calls = append(calls, "execute")
					return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, "session_a", "done", nil)}, nil
				},
				func(context.Context) error {
					calls = append(calls, "refresh")
					return nil
				},
				func(_ context.Context, sessionID string) error {
					calls = append(calls, "rebind:"+sessionID)
					return nil
				},
			)
			events, err := execute(context.Background(), runtime.SideEffectRequest{SessionID: "session_a", ToolName: toolName})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(calls, ",") != "execute,refresh,rebind:session_a" || len(events) != 1 || events[0].Type != protocol.EventToolComplete {
				t.Fatalf("calls=%v events=%+v", calls, events)
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
		nil,
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
		func(context.Context, string) error { t.Fatal("rebind called after refresh failure"); return nil },
	)
	events, err := execute(context.Background(), runtime.SideEffectRequest{ToolName: einotools.NameBuild})
	if err == nil || err.Error() != "side effect failed" {
		t.Fatalf("refresh error = %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("refresh failure leaked success events: %+v", events)
	}
}

func TestPermissionedScopeRefreshFailsClosedWithoutRebindSuccessEvents(t *testing.T) {
	execute := withPermissionedScopeRefresh(
		einotools.NameCheckout,
		func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
			return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, "session_a", "done", nil)}, nil
		},
		func(context.Context) error { return nil },
		func(context.Context, string) error { return errors.New("private rebind error") },
	)
	events, err := execute(context.Background(), runtime.SideEffectRequest{SessionID: "session_a", ToolName: einotools.NameCheckout})
	if err == nil || err.Error() != "side effect failed" {
		t.Fatalf("rebind error = %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("rebind failure leaked success events: %+v", events)
	}
}

func TestPermissionedScopeRefreshRejectsMissingRebindBeforeExecution(t *testing.T) {
	executeCalls := 0
	execute := withPermissionedScopeRefresh(
		einotools.NameBuild,
		func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
			executeCalls++
			return nil, nil
		},
		func(context.Context) error { return nil },
		nil,
	)
	if _, err := execute(context.Background(), runtime.SideEffectRequest{SessionID: "session_a"}); err == nil {
		t.Fatal("missing rebind dependency did not fail closed")
	}
	if executeCalls != 0 {
		t.Fatalf("side effect executed %d times without a rebind dependency", executeCalls)
	}
}
