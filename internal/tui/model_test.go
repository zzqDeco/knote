package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestInputHistoryCyclesComposerValues(t *testing.T) {
	model := newTestModel(t)

	model.composer.SetValue("/help")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	model.composer.SetValue("/status")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyUp})
	if got := model.composer.Value(); got != "/status" {
		t.Fatalf("first history step = %q, want /status", got)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyUp})
	if got := model.composer.Value(); got != "/help" {
		t.Fatalf("second history step = %q, want /help", got)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyDown})
	if got := model.composer.Value(); got != "/status" {
		t.Fatalf("history down = %q, want /status", got)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyDown})
	if got := model.composer.Value(); got != "" {
		t.Fatalf("history draft restore = %q, want empty", got)
	}
}

func TestConfirmRejectClosesOverlayWithoutRunningBuild(t *testing.T) {
	model := newTestModel(t)
	workspace := model.runtime.Workspace()

	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil || model.overlayMode != overlayConfirm {
		t.Fatalf("build did not enter confirm overlay: pending=%v overlay=%s", model.pendingConfirm, model.overlayMode)
	}

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if model.pendingConfirm != nil {
		t.Fatalf("reject did not clear pending confirm: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayNone {
		t.Fatalf("reject did not close overlay: %s", model.overlayMode)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("rejected build wrote artifacts: %v", err)
	}
}

func TestConfirmAuthorizationFailureRestoresCanonicalOverlayAndRetriesOnce(t *testing.T) {
	providerCalls := 0
	model := newTestModelWithAuthorizationProvider(t, func(_ context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		providerCalls++
		if providerCalls == 2 {
			return protocol.AuthorizationContext{}, fmt.Errorf("authorization service temporarily unavailable")
		}
		return testTUIAuthorizationContext(sessionID), nil
	})

	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil || model.overlayMode != overlayConfirm {
		t.Fatalf("build did not enter confirm overlay: pending=%v overlay=%s", model.pendingConfirm, model.overlayMode)
	}
	canonical := *model.pendingConfirm

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if providerCalls != 2 {
		t.Fatalf("authorization calls after failed approval = %d, want 2", providerCalls)
	}
	if model.pendingConfirm == nil || *model.pendingConfirm != canonical {
		t.Fatalf("failed approval did not restore canonical confirmation: got=%+v want=%+v", model.pendingConfirm, canonical)
	}
	if model.overlayMode != overlayConfirm {
		t.Fatalf("failed approval overlay = %s, want %s", model.overlayMode, overlayConfirm)
	}
	if got := countTUIEvents(model.events, protocol.EventToolComplete); got != 0 {
		t.Fatalf("failed approval executed build %d times", got)
	}

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if providerCalls != 3 {
		t.Fatalf("authorization calls after retry = %d, want 3", providerCalls)
	}
	if model.pendingConfirm != nil || model.overlayMode != overlayNone {
		t.Fatalf("successful retry did not clear confirmation: pending=%+v overlay=%s", model.pendingConfirm, model.overlayMode)
	}
	if got := countTUIEvents(model.events, protocol.EventToolComplete); got != 1 {
		t.Fatalf("successful retry executions = %d, want 1", got)
	}
}

func TestOverlaySwitchAndEsc(t *testing.T) {
	model := newTestModel(t)

	model.composer.SetValue("/tasks")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.overlayMode != overlayTasks || !strings.Contains(model.overlay, "tasks") {
		t.Fatalf("/tasks did not show tasks overlay: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
	tracked := &interruptRecordingRuntime{Runtime: model.runtime}
	model.setRuntime(tracked)
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEsc})
	if model.overlayMode != overlayNone || strings.TrimSpace(model.overlay) != "" {
		t.Fatalf("esc did not close overlay: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
	if tracked.interruptCalls != 0 {
		t.Fatalf("esc interrupted runtime while closing overlay %d times", tracked.interruptCalls)
	}
}

func TestEscWithoutOverlayInterruptsAndAppliesReturnedEventsOnce(t *testing.T) {
	model := newTestModel(t)
	wantErr := errors.New("interrupt failed")
	interruptEvent := protocol.NewEvent(protocol.EventStatusUpdate, model.runtime.SessionID(), "turn interrupted", nil)
	tracked := &interruptRecordingRuntime{
		Runtime:         model.runtime,
		interruptEvents: []protocol.Event{interruptEvent},
		interruptErr:    wantErr,
	}
	model.setRuntime(tracked)

	var subscribed []protocol.Event
	unsubscribe := tracked.Subscribe(func(events []protocol.Event) {
		subscribed = append(subscribed, events...)
	})
	defer unsubscribe()

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEsc})
	if tracked.interruptCalls != 1 {
		t.Fatalf("esc interrupt calls = %d, want 1", tracked.interruptCalls)
	}
	if !errors.Is(model.err, wantErr) {
		t.Fatalf("esc interrupt error = %v, want %v", model.err, wantErr)
	}
	if got := countTUIEventMessages(model.events, protocol.EventStatusUpdate, interruptEvent.Message); got != 1 {
		t.Fatalf("returned interrupt events in model = %d, want 1", got)
	}
	if got := countTUIEventMessages(subscribed, protocol.EventStatusUpdate, interruptEvent.Message); got != 1 {
		t.Fatalf("subscription interrupt events = %d, want 1", got)
	}
}

func TestCtrlCInterruptsBeforeQuittingWithOverlayActive(t *testing.T) {
	model := newTestModel(t)
	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil || model.overlayMode != overlayConfirm {
		t.Fatalf("build did not enter confirm overlay: pending=%v overlay=%s", model.pendingConfirm, model.overlayMode)
	}

	wantErr := errors.New("interrupt failed")
	tracked := &interruptRecordingRuntime{Runtime: model.runtime, interruptErr: wantErr}
	model.setRuntime(tracked)
	next, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("unexpected model type %T", next)
	}
	if tracked.interruptCalls != 0 {
		t.Fatalf("ctrl+c blocked Update with %d synchronous interrupt calls", tracked.interruptCalls)
	}
	if cmd == nil {
		t.Fatal("ctrl+c did not return an interrupt command")
	}
	next, quitCmd := updated.Update(cmd())
	updated = next.(Model)
	if tracked.interruptCalls != 1 {
		t.Fatalf("ctrl+c interrupt calls = %d, want 1", tracked.interruptCalls)
	}
	if !errors.Is(updated.err, wantErr) {
		t.Fatalf("ctrl+c interrupt error = %v, want %v", updated.err, wantErr)
	}
	if quitCmd == nil {
		t.Fatal("ctrl+c did not quit after interrupt completion")
	}
	if _, ok := quitCmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c completion did not produce tea.QuitMsg")
	}
}

func TestSendMessageRetainsRuntimeErrorWithoutDuplicatingReturnedEvents(t *testing.T) {
	model := newTestModel(t)
	wantErr := runtime.ErrTurnBusy
	returned := protocol.NewEvent(protocol.EventError, model.runtime.SessionID(), "turn already active", nil)
	stub := &sendResultRuntime{
		Runtime: model.runtime,
		events:  []protocol.Event{returned},
		err:     wantErr,
	}
	model.setRuntime(stub)
	model.composer.SetValue("hello")

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if stub.calls != 1 {
		t.Fatalf("send message calls = %d, want 1", stub.calls)
	}
	if !errors.Is(model.err, wantErr) {
		t.Fatalf("send message error = %v, want %v", model.err, wantErr)
	}
	if got := model.composer.Value(); got != "hello" {
		t.Fatalf("busy send composer = %q, want rejected input restored", got)
	}
	if got := countTUIEventMessages(model.events, protocol.EventError, returned.Message); got != 1 {
		t.Fatalf("returned send events in model = %d, want 1", got)
	}
}

func TestGenericSendFailureRestoresInputAndClosesStartedTask(t *testing.T) {
	model := newTestModel(t)
	wantErr := errors.New("persist task result: storage unavailable")
	now := time.Now().UTC()
	started := protocol.NewEvent(protocol.EventTaskStarted, model.runtime.SessionID(), "Task started", protocol.Task{
		ID: "task_failed_send", Title: "Message", Status: protocol.TaskRunning, CreatedAt: now, UpdatedAt: now,
	})
	stub := &sendResultRuntime{
		Runtime: model.runtime,
		events:  []protocol.Event{started},
		err:     wantErr,
	}
	model.setRuntime(stub)
	model.composer.SetValue("retry this message")

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})

	if !errors.Is(model.err, wantErr) {
		t.Fatalf("send message error = %v, want %v", model.err, wantErr)
	}
	if got := model.composer.Value(); got != "retry this message" {
		t.Fatalf("failed send composer = %q, want original input restored", got)
	}
	if view := model.View(); !strings.Contains(view, wantErr.Error()) {
		t.Fatalf("failed send error is not visible in view: %q", view)
	}
	if got := currentTaskStatuses(model.events)["task_failed_send"]; got != protocol.TaskFailed {
		t.Fatalf("failed send task status = %q, want %q", got, protocol.TaskFailed)
	}
	if got := countTUIEvents(model.events, protocol.EventTaskStarted); got != 1 {
		t.Fatalf("task.started events = %d, want 1", got)
	}
	if got := countTUIEvents(model.events, protocol.EventTaskComplete); got != 1 {
		t.Fatalf("task.complete events = %d, want 1", got)
	}
	if !strings.Contains(model.status, "tasks 0") {
		t.Fatalf("failed send left active task in status: %q", model.status)
	}
}

func TestBusyConfirmationRestoresCanonicalOverlay(t *testing.T) {
	model := newTestModel(t)
	req := protocol.ConfirmRequest{
		RequestID: "confirm_busy", Title: "Confirm build", Summary: "Run build.", Command: "/build",
		ApproveText: "approve", RejectText: "reject",
	}
	model.restoreConfirmation(req)
	stub := &busyConfirmRuntime{Runtime: model.runtime}
	model.setRuntime(stub)

	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if !errors.Is(model.err, runtime.ErrTurnBusy) {
		t.Fatalf("confirm error = %v, want ErrTurnBusy", model.err)
	}
	if model.pendingConfirm == nil || *model.pendingConfirm != req {
		t.Fatalf("busy confirmation was not restored: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayConfirm || !strings.Contains(model.overlay, req.Title) {
		t.Fatalf("busy confirmation overlay = mode:%s content:%q", model.overlayMode, model.overlay)
	}
}

func TestUnstartedConfirmationRestoresCanonicalOverlay(t *testing.T) {
	model := newTestModel(t)
	req := protocol.ConfirmRequest{
		RequestID: "confirm_unstarted", Title: "Confirm build", Summary: "Run build.", Command: "/build",
		ApproveText: "approve", RejectText: "reject",
	}
	model.applyRuntimeResult(runtimeResultMsg{
		commandID: 1,
		kind:      runtimeCommandConfirm,
		confirm:   &req,
		err:       fmt.Errorf("%w: storage unavailable", runtime.ErrTurnNotStarted),
	})

	if model.pendingConfirm == nil || *model.pendingConfirm != req {
		t.Fatalf("unstarted confirmation was not restored: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayConfirm || !strings.Contains(model.overlay, req.Title) {
		t.Fatalf("unstarted confirmation overlay = mode:%s content:%q", model.overlayMode, model.overlay)
	}
}

func TestUnstartedRotationDeadlineRestoresComposer(t *testing.T) {
	model := newTestModel(t)
	commandID := model.nextRuntimeCommand(true)
	next, _ := model.Update(runtimeResultMsg{
		commandID: commandID,
		kind:      runtimeCommandSend,
		input:     "/new",
		err:       fmt.Errorf("%w: %w", runtime.ErrTurnNotStarted, context.DeadlineExceeded),
	})
	model = next.(Model)
	if got := model.composer.Value(); got != "/new" {
		t.Fatalf("restored composer = %q, want /new", got)
	}
	if len(model.inFlightCommands) != 0 {
		t.Fatalf("completed rotation remains in flight: %+v", model.inFlightCommands)
	}
}

func TestUnexecutedConfirmationRestoresCanonicalOverlay(t *testing.T) {
	model := newTestModel(t)
	req := protocol.ConfirmRequest{
		RequestID: "confirm_unexecuted", Title: "Confirm build", Summary: "Run build.", Command: "/build",
		ApproveText: "approve", RejectText: "reject",
	}
	model.applyRuntimeResult(runtimeResultMsg{
		commandID: 1,
		kind:      runtimeCommandConfirm,
		confirm:   &req,
		err:       fmt.Errorf("%w: cancelled", runtime.ErrConfirmationNotExecuted),
	})

	if model.pendingConfirm == nil || *model.pendingConfirm != req {
		t.Fatalf("unexecuted confirmation was not restored: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayConfirm || !strings.Contains(model.overlay, req.Title) {
		t.Fatalf("unexecuted confirmation overlay = mode:%s content:%q", model.overlayMode, model.overlay)
	}
}

func TestUnrelatedCompletionCannotHidePendingConfirmation(t *testing.T) {
	model := newTestModel(t)
	req := protocol.ConfirmRequest{
		RequestID: "confirm_visible", Title: "Confirm build", Summary: "Run build.", Command: "/build",
		ApproveText: "approve", RejectText: "reject",
	}
	model.applyEvents([]protocol.Event{protocol.NewEvent(
		protocol.EventConfirmRequest, model.runtime.SessionID(), req.Title, req,
	)})
	model.applyEvents([]protocol.Event{protocol.NewEvent(
		protocol.EventAssistantDone, model.runtime.SessionID(), "unrelated completion", nil,
	)})

	if model.pendingConfirm == nil || *model.pendingConfirm != req {
		t.Fatalf("unrelated completion cleared pending confirmation: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayConfirm || !strings.Contains(model.overlay, req.Title) {
		t.Fatalf("pending confirmation became hidden: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
}

func TestViewClearBatchCannotReactivateHistoricalConfirmation(t *testing.T) {
	model := newTestModel(t)
	req := protocol.ConfirmRequest{RequestID: "confirm_stale", Title: "Stale confirmation", Action: "build", Command: "/build"}
	model.applyEvents([]protocol.Event{
		protocol.NewEvent(protocol.EventViewClear, "sess_resumed", "resume session", nil),
		protocol.NewEvent(protocol.EventConfirmRequest, "sess_resumed", req.Title, req),
		protocol.NewEvent(protocol.EventSessionInfo, "sess_resumed", "session resumed", protocol.SessionInfo{ID: "sess_resumed", Resumed: true}),
	})

	if model.pendingConfirm != nil {
		t.Fatalf("clear batch reactivated stale confirmation: %+v", model.pendingConfirm)
	}
	if model.overlayMode != overlayNone || strings.TrimSpace(model.overlay) != "" {
		t.Fatalf("clear batch reopened stale overlay: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
}

func TestStaleCommandResultCannotMutateRotatedInteractionState(t *testing.T) {
	model := newTestModel(t)
	req := protocol.ConfirmRequest{RequestID: "confirm_new", Title: "Current confirmation"}
	model.restoreConfirmation(req)
	model.latestRotation = 2

	next, _ := model.Update(runtimeResultMsg{commandID: 1, kind: runtimeCommandSend, input: "old input", err: context.Canceled})
	model = next.(Model)
	if model.err != nil {
		t.Fatalf("stale result changed current error: %v", model.err)
	}
	if model.pendingConfirm == nil || model.pendingConfirm.RequestID != req.RequestID || model.overlayMode != overlayConfirm {
		t.Fatalf("stale result changed current confirmation: pending=%+v overlay=%s", model.pendingConfirm, model.overlayMode)
	}
}

func TestBlockedSendCommandLeavesInterruptHandlingResponsive(t *testing.T) {
	model := newTestModel(t)
	blocked := &blockingSendRuntime{
		Runtime: model.runtime,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	model.setRuntime(blocked)
	model.composer.SetValue("blocked request")

	next, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("unexpected model type %T", next)
	}
	model = updated
	if cmd == nil {
		t.Fatal("send did not return a tea.Cmd")
	}
	result := make(chan tea.Msg, 1)
	go func() { result <- cmd() }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("send command did not reach runtime")
	}
	drainRuntimeEvents(t, &model)
	if !hasTUIEvent(model.events, protocol.EventTaskStarted) || !strings.Contains(model.status, "tasks 1") {
		t.Fatalf("task.started was not rendered while runner was blocked: status=%q events=%+v", model.status, model.events)
	}

	next, interrupt := model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = next.(Model)
	if interrupt == nil {
		t.Fatal("esc did not return an asynchronous interrupt command")
	}
	next, _ = model.Update(interrupt())
	model = next.(Model)
	if got := blocked.interruptCalls.Load(); got != 1 {
		t.Fatalf("interrupt calls = %d, want 1 while send is blocked", got)
	}
	select {
	case <-result:
		t.Fatal("send command completed before the runtime was released")
	default:
	}
	close(blocked.release)
	select {
	case msg := <-result:
		next, _ = model.Update(msg)
		model = next.(Model)
		drainRuntimeEvents(t, &model)
	case <-time.After(time.Second):
		t.Fatal("send command did not complete after release")
	}
	if !hasTUIEvent(model.events, protocol.EventAssistantDone) {
		t.Fatalf("async send result was not applied: %+v", model.events)
	}
}

func TestCtrlCWaitsForActiveTaskTerminalBeforeQuitting(t *testing.T) {
	model := newTestModel(t)
	blocked := &blockingSendRuntime{
		Runtime: model.runtime,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	model.setRuntime(blocked)
	model.composer.SetValue("blocked request")

	next, send := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = next.(Model)
	sendResult := make(chan tea.Msg, 1)
	go func() { sendResult <- send() }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("send command did not reach runtime")
	}
	drainRuntimeEvents(t, &model)

	next, interrupt := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model = next.(Model)
	if interrupt == nil || blocked.interruptCalls.Load() != 0 {
		t.Fatal("ctrl+c did not schedule interruption asynchronously")
	}
	next, drainTimeout := model.Update(interrupt())
	model = next.(Model)
	if drainTimeout == nil {
		t.Fatal("ctrl+c did not wait for the active task terminal")
	}

	close(blocked.release)
	select {
	case msg := <-sendResult:
		next, _ = model.Update(msg)
		model = next.(Model)
	case <-time.After(time.Second):
		t.Fatal("send command did not finish after release")
	}
	var quit tea.Cmd
	for {
		events, ok := model.runtimeEvents.popNow()
		if !ok {
			break
		}
		next, quit = model.Update(runtimeEventsMsg{events: events})
		model = next.(Model)
	}
	if quit == nil {
		t.Fatal("task terminal did not release ctrl+c quit")
	}
	if _, ok := quit().(tea.QuitMsg); !ok {
		t.Fatal("task terminal did not produce tea.QuitMsg")
	}
}

func TestCtrlCWaitsForInFlightCommandBeforeTaskStartCommits(t *testing.T) {
	model := newTestModel(t)
	blocked := &preStartBlockingRuntime{
		Runtime: model.runtime,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	model.setRuntime(blocked)
	model.composer.SetValue("blocked before task start")

	next, send := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = next.(Model)
	sendResult := make(chan tea.Msg, 1)
	go func() { sendResult <- send() }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("send command did not reach runtime")
	}

	next, interrupt := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model = next.(Model)
	if interrupt == nil {
		t.Fatal("ctrl+c did not schedule interruption")
	}
	next, drainTimeout := model.Update(interrupt())
	model = next.(Model)
	if drainTimeout == nil {
		t.Fatal("ctrl+c quit before the in-flight command resolved task-start commitment")
	}

	close(blocked.release)
	select {
	case msg := <-sendResult:
		next, quit := model.Update(msg)
		model = next.(Model)
		if quit == nil {
			t.Fatal("completed in-flight command did not release quit")
		}
		if _, ok := quit().(tea.QuitMsg); !ok {
			t.Fatal("completed in-flight command did not produce tea.QuitMsg")
		}
	case <-time.After(time.Second):
		t.Fatal("send command did not finish after release")
	}
}

func TestCtrlCRetriesInterruptForTurnStartedAfterInitialInterrupt(t *testing.T) {
	tests := []struct {
		name  string
		start func(*Model) (tea.Model, tea.Cmd)
	}{
		{
			name: "message",
			start: func(model *Model) (tea.Model, tea.Cmd) {
				model.composer.SetValue("late turn")
				return model.Update(tea.KeyMsg{Type: tea.KeyEnter})
			},
		},
		{
			name: "confirmation",
			start: func(model *Model) (tea.Model, tea.Cmd) {
				model.restoreConfirmation(protocol.ConfirmRequest{
					RequestID: "confirm_late_turn", Title: "Confirm late turn", Command: "/build",
				})
				return model.Update(tea.KeyMsg{Type: tea.KeyEnter})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := newTestModel(t)
			stub := newLateStartRuntime(model.runtime, "task_late_"+tt.name)
			model.setRuntime(stub)

			next, command := tt.start(&model)
			model = next.(Model)
			commandResult := make(chan tea.Msg, 1)
			go func() { commandResult <- command() }()
			select {
			case <-stub.commandEntered:
			case <-time.After(time.Second):
				t.Fatal("command did not reach runtime")
			}

			next, interrupt := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
			model = next.(Model)
			next, initialDrain := model.Update(interrupt())
			model = next.(Model)
			if initialDrain == nil {
				t.Fatal("initial interrupt did not start drain timeout")
			}
			if got := stub.interruptCalls.Load(); got != 1 {
				t.Fatalf("initial interrupt calls = %d, want 1", got)
			}

			close(stub.allowTurnStart)
			select {
			case <-stub.turnStarted:
			case <-time.After(time.Second):
				t.Fatal("turn did not start after initial interrupt")
			}
			drainRuntimeEvents(t, &model)

			next, retry := model.Update(quitDrainTimeoutMsg{})
			model = next.(Model)
			if retry == nil {
				t.Fatal("drain timeout did not schedule another interrupt")
			}
			retryMsg := retry()
			if _, quitting := retryMsg.(tea.QuitMsg); quitting {
				t.Fatal("drain timeout quit while a late turn was still active")
			}
			if _, ok := retryMsg.(interruptResultMsg); !ok {
				t.Fatalf("retry command returned %T, want interruptResultMsg", retryMsg)
			}
			next, nextDrain := model.Update(retryMsg)
			model = next.(Model)
			if nextDrain == nil {
				t.Fatal("second interrupt quit before command and task terminal drained")
			}
			if got := stub.interruptCalls.Load(); got != 2 {
				t.Fatalf("interrupt calls = %d, want 2", got)
			}

			select {
			case msg := <-commandResult:
				next, quit := model.Update(msg)
				model = next.(Model)
				if quit != nil {
					if _, quitting := quit().(tea.QuitMsg); quitting {
						t.Fatal("command completion quit before task terminal was consumed")
					}
				}
			case <-time.After(time.Second):
				t.Fatal("command did not complete after second interrupt")
			}

			var quit tea.Cmd
			for {
				events, ok := model.runtimeEvents.popNow()
				if !ok {
					break
				}
				next, cmd := model.Update(runtimeEventsMsg{events: events})
				model = next.(Model)
				if cmd != nil {
					quit = cmd
				}
			}
			if quit == nil {
				t.Fatal("drained late turn did not release quit")
			}
			if _, ok := quit().(tea.QuitMsg); !ok {
				t.Fatal("drained late turn did not produce tea.QuitMsg")
			}
		})
	}
}

func TestStatusRefreshRunsOutsideUpdate(t *testing.T) {
	model := newTestModel(t)
	stub := &blockingStatusRuntime{
		Runtime: model.runtime,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	model.setRuntime(stub)
	refresh := model.nextStatusRefreshCmd()
	result := make(chan tea.Msg, 1)
	go func() { result <- refresh() }()
	select {
	case <-stub.started:
	case <-time.After(time.Second):
		t.Fatal("status refresh did not reach runtime")
	}

	updated := make(chan Model, 1)
	go func() {
		next, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
		updated <- next.(Model)
	}()
	select {
	case model = <-updated:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Update blocked behind status I/O")
	}
	if got := model.composer.Value(); got != "x" {
		t.Fatalf("composer value = %q, want responsive input", got)
	}

	close(stub.release)
	select {
	case msg := <-result:
		next, _ := model.Update(msg)
		model = next.(Model)
	case <-time.After(time.Second):
		t.Fatal("status refresh did not complete")
	}
	if !strings.Contains(model.status, "branch async-status") {
		t.Fatalf("async status was not applied: %q", model.status)
	}
}

func TestGovernanceOverlayScrollsAndCloses(t *testing.T) {
	model := newTestModel(t)
	model.applyEvents([]protocol.Event{protocol.NewEvent(
		protocol.EventAssistantDone,
		model.runtime.SessionID(),
		"governance\ntenant\n  id: local\nconnectors\n  total: 0",
		map[string]any{"overlay": "governance"},
	)})
	if model.overlayMode != overlayGovernance || !strings.Contains(model.overlay, "connectors") {
		t.Fatalf("governance overlay = mode %s content %q", model.overlayMode, model.overlay)
	}
	updateModel(t, &model, tea.WindowSizeMsg{Width: 48, Height: 16})
	if model.overlayViewport.Width <= 0 || model.overlayViewport.Height <= 0 {
		t.Fatalf("governance overlay did not resize: %+v", model.overlayViewport)
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyPgDown})
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEsc})
	if model.overlayMode != overlayNone || strings.TrimSpace(model.overlay) != "" {
		t.Fatalf("governance overlay did not close: mode=%s overlay=%q", model.overlayMode, model.overlay)
	}
}

func TestClearProjectsTranscriptWithoutDeletingSession(t *testing.T) {
	model := newTestModel(t)
	store := local.New(model.runtime.Workspace())
	sessionID := model.runtime.SessionID()

	model.composer.SetValue("/help")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	model.composer.SetValue("/clear")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})

	if got := strings.TrimSpace(renderTranscript(model.events)); got != "knote ready" {
		t.Fatalf("clear should project empty transcript, got:\n%s", got)
	}
	events, err := store.Load(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTUIEvent(events, protocol.EventViewClear) || len(events) == 0 {
		t.Fatalf("clear did not persist a view event while keeping history: %+v", events)
	}
}

func TestResumeDoesNotReviveStaleConfirmation(t *testing.T) {
	model := newTestModel(t)
	sessionID := model.runtime.SessionID()

	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil {
		t.Fatal("/build did not create a pending confirmation")
	}
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if model.pendingConfirm != nil {
		t.Fatal("rejecting /build did not clear pending confirmation")
	}

	model.composer.SetValue("/new")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.runtime.SessionID() == sessionID {
		t.Fatal("/new did not switch sessions")
	}

	model.composer.SetValue("/resume " + sessionID)
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm != nil {
		t.Fatalf("resume revived stale confirmation: %+v", model.pendingConfirm)
	}

	model.composer.SetValue("/build")
	updateModel(t, &model, tea.KeyMsg{Type: tea.KeyEnter})
	if model.pendingConfirm == nil || model.pendingConfirm.Action != "build" {
		t.Fatalf("/build after resume did not create a fresh confirmation: %+v", model.pendingConfirm)
	}
}

func newTestModel(t *testing.T) Model {
	t.Helper()
	return newTestModelWithAuthorizationProvider(t, nil)
}

func newTestModelWithAuthorizationProvider(t *testing.T, provider runtime.AuthorizationContextProvider) Model {
	t.Helper()
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	t.Setenv("KNOTE_KAG_FAKE", "1")
	rt, initial, err := newTestAgent(t, workspace, provider)
	if err != nil {
		t.Fatal(err)
	}
	model := New(rt, initial)
	model.width = 100
	model.height = 30
	model.resize()
	model.refreshOverlay()
	model.refreshViewport()
	return model
}

func newTestAgent(t *testing.T, workspace string, provider runtime.AuthorizationContextProvider) (runtime.Runtime, []protocol.Event, error) {
	t.Helper()
	ctx := context.Background()
	repo := local.New(workspace)
	cfg, err := repo.Config(ctx)
	if err != nil {
		return nil, nil, err
	}
	cfg.KAG.Fake = true
	cfg.Workspace = workspace
	if err := repo.SaveConfig(ctx, cfg); err != nil {
		return nil, nil, err
	}
	bridge := runtime.NewSideEffectBridge()
	toolExecutor := &fakeToolExecutor{}
	toolExecutor.onInvoke = func(ctx context.Context, sessionID string, toolName string, args string) ([]protocol.Event, error) {
		action := strings.TrimPrefix(toolName, "knote_")
		return nil, bridge.Request(ctx, runtime.SideEffectRequest{
			ToolName:        toolName,
			Action:          action,
			ArgumentsInJSON: args,
			Summary:         fmt.Sprintf("Run %s.", toolName),
			Execute: func(context.Context, runtime.SideEffectRequest) ([]protocol.Event, error) {
				return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", nil)}, nil
			},
		})
	}
	rt := runtime.New(runtime.Dependencies{
		Workspace:                    workspace,
		Config:                       cfg,
		Sessions:                     repo,
		Versions:                     repo,
		WorkspaceRepo:                repo,
		EinoRunner:                   fakeEinoRunner{},
		AuthorizationContextProvider: provider,
		SideEffects:                  bridge,
		ToolExecutor:                 toolExecutor,
		NewSessionID:                 local.NewSessionID,
	})
	initial, err := rt.Start(ctx, runtime.StartOptions{})
	return rt, initial, err
}

type fakeEinoRunner struct{}

func (fakeEinoRunner) Ready(context.Context) error {
	return nil
}

func (fakeEinoRunner) ToolInventory(context.Context) ([]runtime.RunnerToolInfo, error) {
	return []runtime.RunnerToolInfo{{Name: "knote_query", Description: "query knowledge"}}, nil
}

func (fakeEinoRunner) Run(_ context.Context, input runtime.EinoRunInput) ([]protocol.Event, error) {
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, "fake answer", nil)}, nil
}

type fakeToolExecutor struct {
	onInvoke func(context.Context, string, string, string) ([]protocol.Event, error)
}

func (e *fakeToolExecutor) Invoke(ctx context.Context, sessionID string, toolName string, argumentsInJSON string) ([]protocol.Event, error) {
	if e.onInvoke != nil {
		return e.onInvoke(ctx, sessionID, toolName, argumentsInJSON)
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, sessionID, toolName+" complete", nil)}, nil
}

type interruptRecordingRuntime struct {
	runtime.Runtime
	interruptCalls  int
	interruptEvents []protocol.Event
	interruptErr    error
	publisher       runtimePublisher
}

func (r *interruptRecordingRuntime) Interrupt(context.Context) ([]protocol.Event, error) {
	r.interruptCalls++
	r.publisher.publish(r.interruptEvents)
	return r.interruptEvents, r.interruptErr
}

func (r *interruptRecordingRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

type sendResultRuntime struct {
	runtime.Runtime
	calls     int
	events    []protocol.Event
	err       error
	publisher runtimePublisher
}

type busyConfirmRuntime struct {
	runtime.Runtime
	publisher runtimePublisher
}

func (r *busyConfirmRuntime) Confirm(context.Context, protocol.ConfirmRequest, bool) ([]protocol.Event, error) {
	return nil, runtime.ErrTurnBusy
}

func (r *busyConfirmRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

type blockingSendRuntime struct {
	runtime.Runtime
	started        chan struct{}
	release        chan struct{}
	interruptCalls atomic.Int32
	publisher      runtimePublisher
}

type preStartBlockingRuntime struct {
	runtime.Runtime
	started        chan struct{}
	release        chan struct{}
	interruptCalls atomic.Int32
	publisher      runtimePublisher
}

type lateStartRuntime struct {
	runtime.Runtime
	taskID         string
	commandEntered chan struct{}
	allowTurnStart chan struct{}
	turnStarted    chan struct{}
	finish         chan struct{}
	finishOnce     sync.Once
	interruptCalls atomic.Int32
	publisher      runtimePublisher
}

func newLateStartRuntime(rt runtime.Runtime, taskID string) *lateStartRuntime {
	return &lateStartRuntime{
		Runtime:        rt,
		taskID:         taskID,
		commandEntered: make(chan struct{}),
		allowTurnStart: make(chan struct{}),
		turnStarted:    make(chan struct{}),
		finish:         make(chan struct{}),
	}
}

type blockingStatusRuntime struct {
	runtime.Runtime
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	publisher runtimePublisher
}

func (r *blockingStatusRuntime) CurrentSessionInfo(context.Context) protocol.SessionInfo {
	r.startOnce.Do(func() { close(r.started) })
	<-r.release
	return protocol.SessionInfo{ID: r.SessionID(), Branch: "async-status", KAGMode: "fake"}
}

func (r *blockingStatusRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

func (r *blockingSendRuntime) SendMessage(context.Context, string) ([]protocol.Event, error) {
	now := time.Now().UTC()
	r.publisher.publish([]protocol.Event{protocol.NewEvent(protocol.EventTaskStarted, r.SessionID(), "Task started", protocol.Task{
		ID: "task_blocked", Title: "Message", Status: protocol.TaskRunning, CreatedAt: now, UpdatedAt: now,
	})})
	close(r.started)
	<-r.release
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventAssistantDone, r.SessionID(), "released", nil),
		protocol.NewEvent(protocol.EventTaskComplete, r.SessionID(), "Task completed", protocol.Task{
			ID: "task_blocked", Title: "Message", Status: protocol.TaskCompleted, CreatedAt: now, UpdatedAt: time.Now().UTC(),
		}),
	}
	r.publisher.publish(events)
	return events, nil
}

func (r *blockingSendRuntime) Interrupt(context.Context) ([]protocol.Event, error) {
	r.interruptCalls.Add(1)
	return nil, nil
}

func (r *blockingSendRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

func (r *preStartBlockingRuntime) SendMessage(context.Context, string) ([]protocol.Event, error) {
	close(r.started)
	<-r.release
	return nil, nil
}

func (r *preStartBlockingRuntime) Interrupt(context.Context) ([]protocol.Event, error) {
	r.interruptCalls.Add(1)
	return nil, nil
}

func (r *preStartBlockingRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

func (r *lateStartRuntime) SendMessage(context.Context, string) ([]protocol.Event, error) {
	return r.runCommand()
}

func (r *lateStartRuntime) Confirm(context.Context, protocol.ConfirmRequest, bool) ([]protocol.Event, error) {
	return r.runCommand()
}

func (r *lateStartRuntime) runCommand() ([]protocol.Event, error) {
	close(r.commandEntered)
	<-r.allowTurnStart
	now := time.Now().UTC()
	started := protocol.NewEvent(protocol.EventTaskStarted, r.SessionID(), "Task started", protocol.Task{
		ID: r.taskID, Title: "Late turn", Status: protocol.TaskRunning, CreatedAt: now, UpdatedAt: now,
	})
	r.publisher.publish([]protocol.Event{started})
	close(r.turnStarted)
	<-r.finish
	terminal := protocol.NewEvent(protocol.EventTaskComplete, r.SessionID(), "Task interrupted", protocol.Task{
		ID: r.taskID, Title: "Late turn", Status: protocol.TaskKilled, CreatedAt: now, UpdatedAt: time.Now().UTC(),
	})
	r.publisher.publish([]protocol.Event{terminal})
	return []protocol.Event{started, terminal}, context.Canceled
}

func (r *lateStartRuntime) Interrupt(context.Context) ([]protocol.Event, error) {
	call := r.interruptCalls.Add(1)
	payload := map[string]string{}
	message := "no active task"
	if call > 1 {
		payload["task_id"] = r.taskID
		message = "interrupt requested"
		r.finishOnce.Do(func() { close(r.finish) })
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, r.SessionID(), message, payload)}
	r.publisher.publish(events)
	return events, nil
}

func (r *lateStartRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

func (r *sendResultRuntime) SendMessage(context.Context, string) ([]protocol.Event, error) {
	r.calls++
	r.publisher.publish(r.events)
	return r.events, r.err
}

func (r *sendResultRuntime) Subscribe(fn runtime.EventSubscriber) func() {
	return r.publisher.subscribe(fn)
}

type runtimePublisher struct {
	mu          sync.Mutex
	nextID      int
	subscribers map[int]runtime.EventSubscriber
}

func (p *runtimePublisher) subscribe(fn runtime.EventSubscriber) func() {
	p.mu.Lock()
	if p.subscribers == nil {
		p.subscribers = map[int]runtime.EventSubscriber{}
	}
	id := p.nextID
	p.nextID++
	p.subscribers[id] = fn
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		delete(p.subscribers, id)
		p.mu.Unlock()
	}
}

func (p *runtimePublisher) publish(events []protocol.Event) {
	if len(events) == 0 {
		return
	}
	p.mu.Lock()
	subscribers := make([]runtime.EventSubscriber, 0, len(p.subscribers))
	for _, subscriber := range p.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	p.mu.Unlock()
	for _, subscriber := range subscribers {
		subscriber(events)
	}
}

func updateModel(t *testing.T, model *Model, msg tea.Msg) {
	t.Helper()
	next, cmd := model.Update(msg)
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("unexpected model type %T", next)
	}
	*model = updated
	if cmd != nil {
		result := cmd()
		switch result.(type) {
		case runtimeResultMsg, interruptResultMsg:
			next, _ = model.Update(result)
			updated, ok = next.(Model)
			if !ok {
				t.Fatalf("unexpected model type %T", next)
			}
			*model = updated
		}
	}
	drainRuntimeEvents(t, model)
}

func drainRuntimeEvents(t *testing.T, model *Model) {
	t.Helper()
	for {
		events, ok := model.runtimeEvents.popNow()
		if !ok {
			return
		}
		next, _ := model.Update(runtimeEventsMsg{events: events})
		updated, ok := next.(Model)
		if !ok {
			t.Fatalf("unexpected model type %T", next)
		}
		*model = updated
	}
}

func hasTUIEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func countTUIEvents(events []protocol.Event, eventType protocol.EventType) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func countTUIEventMessages(events []protocol.Event, eventType protocol.EventType, message string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			count++
		}
	}
	return count
}

func testTUIAuthorizationContext(sessionID string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:                   protocol.SecurityContractVersion,
		TenantID:                  "local",
		KnowledgeBaseID:           "default",
		PrincipalID:               "local-user",
		SessionID:                 sessionID,
		RequestID:                 "request-1",
		AgentID:                   "agent-1",
		TaskID:                    "task-1",
		DelegationWatermark:       "delegation-v1",
		AgentTaskScopeFingerprint: "scope_00000000000000000000000000000001",
		AuthorizationModelID:      "local-v1",
		IdentityWatermark:         "identity-v1",
		ACLWatermark:              "acl-v1",
		Consistency:               protocol.ConsistencyHigherConsistency,
	}
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
