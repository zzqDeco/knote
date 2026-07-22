package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestTurnControllerRejectsOverlapAndInterruptsActiveTurn(t *testing.T) {
	runner := newControlledTurnRunner()
	manager := newTurnTestManager(t, runner, time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	type result struct {
		events []protocol.Event
		err    error
	}
	first := make(chan result, 1)
	go func() {
		events, err := manager.SendMessage(context.Background(), "first")
		first <- result{events: events, err: err}
	}()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("first turn did not reach runner")
	}

	if events, err := manager.SendMessage(context.Background(), "overlap"); !errors.Is(err, ErrTurnBusy) || len(events) != 0 {
		t.Fatalf("overlap = events:%+v err:%v, want ErrTurnBusy", events, err)
	}
	interruptEvents, err := manager.Interrupt(context.Background())
	if err != nil || !hasMessage(interruptEvents, protocol.EventStatusUpdate, "interrupt requested") {
		t.Fatalf("interrupt = events:%+v err:%v", interruptEvents, err)
	}

	var completed result
	select {
	case completed = <-first:
	case <-time.After(time.Second):
		t.Fatal("interrupted turn did not finish")
	}
	if !errors.Is(completed.err, context.Canceled) {
		t.Fatalf("interrupted turn error = %v, want context.Canceled", completed.err)
	}
	assertSingleTaskLifecycle(t, completed.events, protocol.TaskKilled)
	if got := runner.calls.Load(); got != 1 {
		t.Fatalf("runner calls = %d, want 1", got)
	}
}

func TestTurnControllerStopsOnlyMatchingTask(t *testing.T) {
	runner := newControlledTurnRunner()
	manager := newTurnTestManager(t, runner, time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	startedEvents := make(chan []protocol.Event, 4)
	unsubscribe := manager.Subscribe(func(events []protocol.Event) {
		if hasEvent(events, protocol.EventTaskStarted) {
			startedEvents <- events
		}
	})
	defer unsubscribe()

	done := make(chan error, 1)
	go func() {
		_, err := manager.SendMessage(context.Background(), "stop me")
		done <- err
	}()
	var taskID string
	select {
	case events := <-startedEvents:
		taskID = taskIDFromEvents(t, events)
	case <-time.After(time.Second):
		t.Fatal("task.started was not published")
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("turn did not reach runner")
	}

	if _, err := manager.StopTask(context.Background(), "task_999999"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("wrong task stop error = %v, want ErrTaskNotFound", err)
	}
	if _, err := manager.StopTask(context.Background(), taskID); err != nil {
		t.Fatalf("stop matching task: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stopped turn error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stopped turn did not finish")
	}
}

func TestInterruptRevalidatesReplacementTurnUnderCommitSerialization(t *testing.T) {
	manager := newTurnTestManager(t, newControlledTurnRunner(), time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	oldCtx, cancelOldContext := context.WithCancel(context.Background())
	defer cancelOldContext()
	oldCancelled := make(chan struct{})
	var oldCancelOnce sync.Once
	oldTurn := &activeTurn{
		id:             "task_old",
		ctx:            oldCtx,
		cancel:         func() { oldCancelOnce.Do(func() { close(oldCancelled) }); cancelOldContext() },
		done:           make(chan struct{}),
		startCommitted: true,
	}
	replacementCtx, cancelReplacementContext := context.WithCancel(context.Background())
	defer cancelReplacementContext()
	replacementTurn := &activeTurn{
		id:             "task_replacement",
		ctx:            replacementCtx,
		cancel:         cancelReplacementContext,
		done:           make(chan struct{}),
		startCommitted: true,
	}
	manager.mu.Lock()
	manager.activeTurn = oldTurn
	manager.mu.Unlock()

	manager.commitMu.Lock()
	type result struct {
		events []protocol.Event
		err    error
	}
	invoked := make(chan struct{})
	completed := make(chan result, 1)
	go func() {
		close(invoked)
		events, err := manager.Interrupt(context.Background())
		completed <- result{events: events, err: err}
	}()
	<-invoked
	staleCancelled := false
	select {
	case <-oldCancelled:
		staleCancelled = true
	case <-time.After(25 * time.Millisecond):
	}
	manager.mu.Lock()
	manager.activeTurn = replacementTurn
	manager.mu.Unlock()
	manager.commitMu.Unlock()

	var got result
	select {
	case got = <-completed:
	case <-time.After(time.Second):
		t.Fatal("interrupt did not complete after commit serialization was released")
	}
	if staleCancelled {
		t.Fatal("interrupt cancelled the stale turn before commit revalidation")
	}
	if got.err != nil || len(got.events) != 1 {
		t.Fatalf("interrupt replacement = events:%+v err:%v", got.events, got.err)
	}
	payload, ok := got.events[0].Payload.(map[string]string)
	if !ok || payload["task_id"] != replacementTurn.id {
		t.Fatalf("interrupt targeted stale task: %+v", got.events)
	}
	select {
	case <-replacementCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("interrupt did not cancel the replacement turn")
	}
}

func TestStopTaskRevalidatesReplacementTurnUnderCommitSerialization(t *testing.T) {
	manager := newTurnTestManager(t, newControlledTurnRunner(), time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	oldCtx, cancelOldContext := context.WithCancel(context.Background())
	defer cancelOldContext()
	oldCancelled := make(chan struct{})
	var oldCancelOnce sync.Once
	oldTurn := &activeTurn{
		id:             "task_old",
		ctx:            oldCtx,
		cancel:         func() { oldCancelOnce.Do(func() { close(oldCancelled) }); cancelOldContext() },
		done:           make(chan struct{}),
		startCommitted: true,
	}
	replacementCtx, cancelReplacementContext := context.WithCancel(context.Background())
	defer cancelReplacementContext()
	replacementTurn := &activeTurn{
		id:             "task_replacement",
		ctx:            replacementCtx,
		cancel:         cancelReplacementContext,
		done:           make(chan struct{}),
		startCommitted: true,
	}
	manager.mu.Lock()
	manager.activeTurn = oldTurn
	manager.mu.Unlock()

	manager.commitMu.Lock()
	type result struct {
		events []protocol.Event
		err    error
	}
	invoked := make(chan struct{})
	completed := make(chan result, 1)
	go func() {
		close(invoked)
		events, err := manager.StopTask(context.Background(), oldTurn.id)
		completed <- result{events: events, err: err}
	}()
	<-invoked
	staleCancelled := false
	select {
	case <-oldCancelled:
		staleCancelled = true
	case <-time.After(25 * time.Millisecond):
	}
	manager.mu.Lock()
	manager.activeTurn = replacementTurn
	manager.mu.Unlock()
	manager.commitMu.Unlock()

	var got result
	select {
	case got = <-completed:
	case <-time.After(time.Second):
		t.Fatal("stop did not complete after commit serialization was released")
	}
	if staleCancelled {
		t.Fatal("stop cancelled the stale turn before commit revalidation")
	}
	if !errors.Is(got.err, ErrTaskNotFound) || len(got.events) != 0 {
		t.Fatalf("stale stop = events:%+v err:%v, want ErrTaskNotFound", got.events, got.err)
	}
	select {
	case <-replacementCtx.Done():
		t.Fatal("stale stop cancelled the replacement turn")
	default:
	}
}

func TestAcceptedResultAndTerminalCommitBeforeConcurrentInterrupt(t *testing.T) {
	store := &blockingResultSessions{
		Sessions:  local.New(t.TempDir()),
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		blockType: protocol.EventAssistantDone,
	}
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_atomic_finish" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	type result struct {
		events []protocol.Event
		err    error
	}
	sendDone := make(chan result, 1)
	go func() {
		events, err := manager.SendMessage(context.Background(), "finish atomically")
		sendDone <- result{events: events, err: err}
	}()
	select {
	case <-store.blocked:
	case <-time.After(time.Second):
		t.Fatal("result persistence did not reach the blocking commit point")
	}

	interruptDone := make(chan result, 1)
	go func() {
		events, err := manager.Interrupt(context.Background())
		interruptDone <- result{events: events, err: err}
	}()
	select {
	case interrupted := <-interruptDone:
		if interrupted.err != nil || !hasMessage(interrupted.events, protocol.EventStatusUpdate, "task completion in progress") {
			t.Fatalf("interrupt during result commit = events:%+v err:%v", interrupted.events, interrupted.err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("interrupt blocked behind result persistence")
	}
	close(store.release)

	var sent result
	select {
	case sent = <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("send did not finish after persistence was released")
	}
	if sent.err != nil {
		t.Fatalf("send error: %v", sent.err)
	}
	if !hasMessage(sent.events, protocol.EventAssistantDone, "accepted answer") {
		t.Fatalf("accepted result missing: %+v", sent.events)
	}
	assertTaskStatus(t, sent.events, "Message", protocol.TaskCompleted)

	if interrupted, err := manager.Interrupt(context.Background()); err != nil || !hasMessage(interrupted, protocol.EventStatusUpdate, "no active task") {
		t.Fatalf("post-commit interrupt = events:%+v err:%v", interrupted, err)
	}
}

func TestInterruptCancelsBlockedTaskStartWithoutWaitingForDeadline(t *testing.T) {
	store := &blockingResultSessions{
		Sessions:  local.New(t.TempDir()),
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		blockType: protocol.EventTaskStarted,
	}
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   newControlledTurnRunner(),
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_atomic_start" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	type result struct {
		events []protocol.Event
		err    error
	}
	sendDone := make(chan result, 1)
	go func() {
		events, err := manager.SendMessage(context.Background(), "interrupt start")
		sendDone <- result{events: events, err: err}
	}()
	select {
	case <-store.blocked:
	case <-time.After(time.Second):
		t.Fatal("task.started persistence did not reach the blocking commit point")
	}
	interruptDone := make(chan result, 1)
	go func() {
		events, err := manager.Interrupt(context.Background())
		interruptDone <- result{events: events, err: err}
	}()
	select {
	case interrupted := <-interruptDone:
		if interrupted.err != nil || !hasMessage(interrupted.events, protocol.EventStatusUpdate, "interrupt requested") {
			t.Fatalf("interrupt result = events:%+v err:%v", interrupted.events, interrupted.err)
		}
		if len(interruptTaskIDsForTest(interrupted.events)) != 0 {
			t.Fatalf("uncommitted task start exposed a task id: %+v", interrupted.events)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("interrupt waited for blocked task.started persistence")
	}
	select {
	case sent := <-sendDone:
		if !errors.Is(sent.err, context.Canceled) || !errors.Is(sent.err, ErrTurnNotStarted) {
			t.Fatalf("send error = %v, want cancelled ErrTurnNotStarted", sent.err)
		}
		if len(sent.events) != 0 {
			t.Fatalf("cancelled uncommitted start published lifecycle: %+v", sent.events)
		}
	case <-time.After(time.Second):
		t.Fatal("interrupted send did not finish")
	}
	close(store.release)
}

func TestTaskStartPersistenceHonorsTurnDeadlineAndClearsActiveTurn(t *testing.T) {
	store := &blockingResultSessions{
		Sessions:  local.New(t.TempDir()),
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		blockType: protocol.EventTaskStarted,
	}
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		TurnTimeout:  25 * time.Millisecond,
		NewSessionID: func() string { return "sess_start_deadline" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	startedAt := time.Now()
	events, err := manager.SendMessage(context.Background(), "blocked task start")
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrTurnNotStarted) || len(events) != 0 {
		t.Fatalf("blocked task start = events:%+v err:%v, want deadline without published lifecycle", events, err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked task start ignored turn deadline: %s", elapsed)
	}
	select {
	case <-store.blocked:
	default:
		t.Fatal("task.started append was not attempted")
	}
	manager.mu.Lock()
	active := manager.activeTurn
	manager.mu.Unlock()
	if active != nil {
		t.Fatalf("failed task start left active turn %+v", active)
	}

	close(store.release)
	events, err = manager.SendMessage(context.Background(), "retry after persistence recovered")
	if err != nil {
		t.Fatalf("retry after persistence recovery: %v", err)
	}
	assertSingleTaskLifecycle(t, events, protocol.TaskCompleted)
}

func TestTurnControllerAppliesConfiguredDeadline(t *testing.T) {
	runner := newControlledTurnRunner()
	manager := newTurnTestManager(t, runner, 25*time.Millisecond)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	events, err := manager.SendMessage(context.Background(), "wait")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v, want context.DeadlineExceeded", err)
	}
	assertSingleTaskLifecycle(t, events, protocol.TaskFailed)
}

func TestCommittedSideEffectOutcomeSurvivesTurnDeadline(t *testing.T) {
	store := local.New(t.TempDir())
	bridge := NewSideEffectBridge()
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		SideEffects:  bridge,
		TurnTimeout:  25 * time.Millisecond,
		NewSessionID: func() string { return "sess_committed_side_effect" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionID := manager.SessionID()
	var executions atomic.Int32
	err := bridge.Request(withSideEffectSession(context.Background(), sessionID), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(ctx context.Context, req SideEffectRequest) ([]protocol.Event, error) {
			<-ctx.Done()
			executions.Add(1)
			return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, req.SessionID, "build committed", nil)}, nil
		},
	})
	if !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed side effect: %v", err)
	}
	pending := bridge.PendingEvents(sessionID)
	if len(pending) != 1 {
		t.Fatalf("pending confirmation events = %+v", pending)
	}

	events, err := manager.Confirm(context.Background(), firstConfirm(t, pending), true)
	if err != nil {
		t.Fatalf("committed side effect returned a retryable deadline: %v", err)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("side-effect executions = %d, want 1", got)
	}
	if !hasMessage(events, protocol.EventToolComplete, "build committed") {
		t.Fatalf("committed result was dropped: %+v", events)
	}
	assertTaskStatus(t, events, "Confirmation", protocol.TaskCompleted)
	loaded, err := store.Load(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasMessage(loaded, protocol.EventToolComplete, "build committed") {
		t.Fatalf("committed result was not persisted: %+v", loaded)
	}
}

func TestCommittedSideEffectRemainsBusyUntilOutcomeIsDurable(t *testing.T) {
	store := &blockingResultSessions{
		Sessions:  local.New(t.TempDir()),
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		blockType: protocol.EventToolComplete,
	}
	bridge := NewSideEffectBridge()
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		SideEffects:  bridge,
		TurnTimeout:  25 * time.Millisecond,
		NewSessionID: func() string { return "sess_durable_side_effect" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionID := manager.SessionID()
	err := bridge.Request(withSideEffectSession(context.Background(), sessionID), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(ctx context.Context, req SideEffectRequest) ([]protocol.Event, error) {
			<-ctx.Done()
			return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, req.SessionID, "durable build", nil)}, nil
		},
	})
	if !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed side effect: %v", err)
	}
	confirm := firstConfirm(t, bridge.PendingEvents(sessionID))
	type result struct {
		events []protocol.Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		events, confirmErr := manager.Confirm(context.Background(), confirm, true)
		done <- result{events: events, err: confirmErr}
	}()
	select {
	case <-store.blocked:
	case <-time.After(time.Second):
		t.Fatal("committed outcome did not reach durable persistence")
	}
	select {
	case got := <-done:
		t.Fatalf("committed outcome returned before persistence completed: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	if events, err := manager.Confirm(context.Background(), confirm, true); !errors.Is(err, ErrTurnBusy) || len(events) != 0 {
		t.Fatalf("retry while committed outcome persisted = events:%+v err:%v, want ErrTurnBusy", events, err)
	}
	close(store.release)
	var got result
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("committed outcome did not finish after persistence recovered")
	}
	if got.err != nil || !hasMessage(got.events, protocol.EventToolComplete, "durable build") {
		t.Fatalf("committed outcome = events:%+v err:%v", got.events, got.err)
	}
	loaded, err := store.Load(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasMessage(loaded, protocol.EventToolComplete, "durable build") {
		t.Fatalf("committed outcome missing from durable log: %+v", loaded)
	}
}

func TestInterruptedTurnPersistsTerminalAfterContextCancellation(t *testing.T) {
	store := &blockingResultSessions{
		Sessions:  local.New(t.TempDir()),
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		blockType: protocol.EventTaskComplete,
	}
	runner := newControlledTurnRunner()
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   runner,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_durable_terminal" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		events []protocol.Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		events, err := manager.SendMessage(context.Background(), "interrupt with durable terminal")
		done <- result{events: events, err: err}
	}()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("turn did not reach runner")
	}
	if _, err := manager.Interrupt(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.blocked:
	case <-time.After(time.Second):
		t.Fatal("cancelled turn did not attempt durable terminal persistence")
	}
	select {
	case got := <-done:
		t.Fatalf("cancelled turn returned before terminal was durable: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(store.release)
	var got result
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled turn did not finish after terminal persistence recovered")
	}
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("cancelled turn error = %v, want context.Canceled", got.err)
	}
	assertTaskStatus(t, got.events, "Message", protocol.TaskKilled)
	loaded, err := store.Load(context.Background(), manager.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	assertTaskStatus(t, loaded, "Message", protocol.TaskKilled)
}

func TestConfirmationCanRetryWhenTaskStartNeverCommits(t *testing.T) {
	store := &blockingResultSessions{
		Sessions:  local.New(t.TempDir()),
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		blockType: protocol.EventTaskStarted,
	}
	bridge := NewSideEffectBridge()
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		SideEffects:  bridge,
		TurnTimeout:  25 * time.Millisecond,
		NewSessionID: func() string { return "sess_retry_confirmation" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	var executions atomic.Int32
	err := bridge.Request(withSideEffectSession(context.Background(), manager.SessionID()), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			executions.Add(1)
			return nil, nil
		},
	})
	if !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed side effect: %v", err)
	}
	confirm := firstConfirm(t, bridge.PendingEvents(manager.SessionID()))
	if events, err := manager.Confirm(context.Background(), confirm, true); !errors.Is(err, ErrTurnNotStarted) || len(events) != 0 {
		t.Fatalf("failed confirmation start = events:%+v err:%v", events, err)
	}
	if got := executions.Load(); got != 0 {
		t.Fatalf("uncommitted confirmation executed %d times", got)
	}
	close(store.release)
	if _, err := manager.Confirm(context.Background(), confirm, true); err != nil {
		t.Fatalf("retry confirmation after storage recovery: %v", err)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("retried confirmation executions = %d, want 1", got)
	}
}

func TestConfirmationCanRetryWhenCancelledBeforeConsumption(t *testing.T) {
	bridge := NewSideEffectBridge()
	manager := New(Dependencies{
		Sessions:     local.New(t.TempDir()),
		EinoRunner:   immediateTurnRunner{},
		SideEffects:  bridge,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_cancel_before_confirm" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	var executions atomic.Int32
	err := bridge.Request(withSideEffectSession(context.Background(), manager.SessionID()), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			executions.Add(1)
			return nil, nil
		},
	})
	if !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed side effect: %v", err)
	}
	confirm := firstConfirm(t, bridge.PendingEvents(manager.SessionID()))
	var interrupted atomic.Bool
	unsubscribe := manager.Subscribe(func(events []protocol.Event) {
		if hasTaskTitle(events, protocol.EventTaskStarted, confirmationTurnTitle) && interrupted.CompareAndSwap(false, true) {
			_, _ = manager.Interrupt(context.Background())
		}
	})

	events, err := manager.Confirm(context.Background(), confirm, true)
	unsubscribe()
	if !errors.Is(err, ErrConfirmationNotExecuted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled pre-consumption confirmation = events:%+v err:%v", events, err)
	}
	if got := executions.Load(); got != 0 {
		t.Fatalf("pre-consumption cancellation executed side effect %d times", got)
	}
	if _, err := manager.Confirm(context.Background(), confirm, true); err != nil {
		t.Fatalf("retry after pre-consumption cancellation: %v", err)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("retried confirmation executions = %d, want 1", got)
	}
}

func TestConfirmationCanRetryWhenAuthorizationIsCancelledBeforeConsumption(t *testing.T) {
	bridge := NewSideEffectBridge()
	var manager *Manager
	var interruptOnce atomic.Bool
	manager = New(Dependencies{
		Sessions:   local.New(t.TempDir()),
		EinoRunner: immediateTurnRunner{},
		AuthorizationContextProvider: func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			if interruptOnce.CompareAndSwap(false, true) {
				_, _ = manager.Interrupt(context.Background())
				return protocol.AuthorizationContext{}, ctx.Err()
			}
			return testAuthorizationContext(sessionID), nil
		},
		SideEffects:  bridge,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_cancel_authorization" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	var executions atomic.Int32
	err := bridge.Request(withSideEffectSession(context.Background(), manager.SessionID()), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			executions.Add(1)
			return nil, nil
		},
	})
	if !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed side effect: %v", err)
	}
	confirm := firstConfirm(t, bridge.PendingEvents(manager.SessionID()))

	events, err := manager.Confirm(context.Background(), confirm, true)
	if !errors.Is(err, ErrConfirmationNotExecuted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled authorization confirmation = events:%+v err:%v", events, err)
	}
	if !hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("cancelled authorization did not re-emit confirmation: %+v", events)
	}
	if got := executions.Load(); got != 0 {
		t.Fatalf("cancelled authorization executed side effect %d times", got)
	}
	if _, err := manager.Confirm(context.Background(), confirm, true); err != nil {
		t.Fatalf("retry after cancelled authorization: %v", err)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("retried authorization confirmation executions = %d, want 1", got)
	}
}

func TestCommittedSideEffectPersistenceErrorFailsClosedAcrossRestart(t *testing.T) {
	underlying := local.New(t.TempDir())
	writeErr := errors.New("session disk unavailable")
	store := &failingEventSessions{Sessions: underlying, failType: protocol.EventToolComplete, err: writeErr}
	bridge := NewSideEffectBridge()
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		SideEffects:  bridge,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_unknown_side_effect" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionID := manager.SessionID()
	var executions atomic.Int32
	err := bridge.Request(withSideEffectSession(context.Background(), sessionID), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(_ context.Context, req SideEffectRequest) ([]protocol.Event, error) {
			executions.Add(1)
			return []protocol.Event{protocol.NewEvent(protocol.EventToolComplete, req.SessionID, "uncertain build", nil)}, nil
		},
	})
	if !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed side effect: %v", err)
	}
	confirm := firstConfirm(t, bridge.PendingEvents(sessionID))
	events, err := manager.Confirm(context.Background(), confirm, true)
	if !errors.Is(err, writeErr) {
		t.Fatalf("committed persistence failure = events:%+v err:%v", events, err)
	}
	if hasEvent(events, protocol.EventToolComplete) {
		t.Fatalf("undurable committed outcome was returned as complete: %+v", events)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("side-effect executions = %d, want 1", got)
	}
	if retryEvents, retryErr := manager.Confirm(context.Background(), confirm, true); !errors.Is(retryErr, ErrTurnBusy) || len(retryEvents) != 0 {
		t.Fatalf("same-process retry = events:%+v err:%v, want ErrTurnBusy", retryEvents, retryErr)
	}

	restarted := New(Dependencies{
		Sessions:     underlying,
		EinoRunner:   immediateTurnRunner{},
		NewSessionID: func() string { return "sess_fresh_after_unknown" },
	})
	if resumed, resumeErr := restarted.Start(context.Background(), StartOptions{ResumeID: sessionID}); !errors.Is(resumeErr, ErrSideEffectOutcomeUnknown) || len(resumed) != 0 {
		t.Fatalf("uncertain side-effect resume = events:%+v err:%v", resumed, resumeErr)
	}
	if _, err := restarted.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatalf("fresh session after refused resume: %v", err)
	}
	loaded, err := underlying.Load(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := countTaskTitle(loaded, protocol.EventTaskComplete, confirmationTurnTitle); got != 0 {
		t.Fatalf("uncertain confirmation was auto-reconciled: %+v", loaded)
	}
}

func TestSessionRotationDrainUsesConfiguredDeadline(t *testing.T) {
	runner := &stubbornTurnRunner{started: make(chan struct{}), release: make(chan struct{})}
	manager := newTurnTestManager(t, runner, 25*time.Millisecond)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	oldDone := make(chan error, 1)
	go func() {
		_, err := manager.SendMessage(context.Background(), "stubborn turn")
		oldDone <- err
	}()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("stubborn turn did not reach runner")
	}

	startedAt := time.Now()
	events, err := manager.SendMessage(context.Background(), "/new")
	if !errors.Is(err, context.DeadlineExceeded) || len(events) != 0 {
		t.Fatalf("rotation = events:%+v err:%v, want deadline without lifecycle", events, err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("rotation exceeded its configured drain deadline: %s", elapsed)
	}
	close(runner.release)
	select {
	case err := <-oldDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("old turn error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old turn did not finish after runner release")
	}
}

func TestTurnControllerRejectsCancelledParentWithoutLifecycle(t *testing.T) {
	runner := newControlledTurnRunner()
	manager := newTurnTestManager(t, runner, time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	events, err := manager.SendMessage(ctx, "cancelled before start")
	if !errors.Is(err, context.Canceled) || len(events) != 0 {
		t.Fatalf("cancelled send = events:%+v err:%v, want context.Canceled without events", events, err)
	}
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("runner calls = %d, want 0", got)
	}
	manager.mu.Lock()
	active := manager.activeTurn
	manager.mu.Unlock()
	if active != nil {
		t.Fatalf("cancelled send left active turn %+v", active)
	}
}

func TestCancelledTurnDropsRunnerEventsReturnedAfterCancellation(t *testing.T) {
	runner := &lateEventTurnRunner{started: make(chan struct{})}
	store := local.New(t.TempDir())
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   runner,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_late" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	type result struct {
		events []protocol.Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		events, err := manager.SendMessage(context.Background(), "cancel")
		done <- result{events: events, err: err}
	}()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("turn did not reach runner")
	}
	if _, err := manager.Interrupt(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed := <-done
	if !errors.Is(completed.err, context.Canceled) {
		t.Fatalf("cancelled turn error = %v", completed.err)
	}
	if hasMessage(completed.events, protocol.EventAssistantDone, "late answer") {
		t.Fatalf("cancelled turn returned late event: %+v", completed.events)
	}
	persisted, err := store.Load(context.Background(), "sess_late")
	if err != nil {
		t.Fatal(err)
	}
	if hasMessage(persisted, protocol.EventAssistantDone, "late answer") {
		t.Fatalf("cancelled turn persisted late event: %+v", persisted)
	}
}

func TestCancelledTurnClearsItsAbandonedConfirmation(t *testing.T) {
	bridge := NewSideEffectBridge()
	runner := &cancelPendingTurnRunner{bridge: bridge, requested: make(chan struct{})}
	manager := New(Dependencies{
		Sessions:     local.New(t.TempDir()),
		EinoRunner:   runner,
		SideEffects:  bridge,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_cancel_pending" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := manager.SendMessage(context.Background(), "queue then cancel")
		done <- err
	}()
	select {
	case <-runner.requested:
	case <-time.After(time.Second):
		t.Fatal("runner did not queue a confirmation")
	}
	if _, err := manager.Interrupt(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled send error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled send did not finish")
	}
	bridge.mu.Lock()
	pendingCount := len(bridge.pending)
	queueCount := len(bridge.queue)
	bridge.mu.Unlock()
	if pendingCount != 0 || queueCount != 0 {
		t.Fatalf("abandoned confirmations remain pending=%d queued=%d", pendingCount, queueCount)
	}
}

func TestFailedResumePreservesCurrentSessionConfirmation(t *testing.T) {
	bridge := NewSideEffectBridge()
	executions := atomic.Int32{}
	manager := New(Dependencies{
		Sessions:     local.New(t.TempDir()),
		EinoRunner:   newControlledTurnRunner(),
		SideEffects:  bridge,
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_current" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Request(withSideEffectSession(context.Background(), "sess_current"), SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			executions.Add(1)
			return nil, nil
		},
	}); !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed confirmation: %v", err)
	}
	pending := bridge.PendingEvents("sess_current")
	if len(pending) != 1 {
		t.Fatalf("seed pending events = %+v", pending)
	}
	confirm := firstConfirm(t, pending)

	if events, err := manager.SendMessage(context.Background(), "/resume sess_missing"); err != nil || !hasEvent(events, protocol.EventError) {
		t.Fatalf("failed resume = events:%+v err:%v", events, err)
	}
	if got := manager.SessionID(); got != "sess_current" {
		t.Fatalf("failed resume changed session to %q", got)
	}
	if _, err := manager.Confirm(context.Background(), confirm, true); err != nil {
		t.Fatalf("confirm after failed resume: %v", err)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("preserved confirmation executions = %d, want 1", got)
	}
}

func TestSessionRotationCancelsActiveTurnAndClearsOldConfirmations(t *testing.T) {
	runner := newControlledTurnRunner()
	bridge := NewSideEffectBridge()
	ids := []string{"sess_old", "sess_new"}
	var idMu sync.Mutex
	manager := New(Dependencies{
		Sessions:    local.New(t.TempDir()),
		EinoRunner:  runner,
		SideEffects: bridge,
		TurnTimeout: time.Second,
		NewSessionID: func() string {
			idMu.Lock()
			defer idMu.Unlock()
			id := ids[0]
			ids = ids[1:]
			return id
		},
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	var observedMu sync.Mutex
	var observed []protocol.Event
	unsubscribe := manager.Subscribe(func(events []protocol.Event) {
		observedMu.Lock()
		observed = append(observed, events...)
		observedMu.Unlock()
	})
	defer unsubscribe()
	if err := bridge.Request(withSideEffectSession(context.Background(), "sess_old"), SideEffectRequest{
		ToolName: "knote_build", Action: "build", Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			return nil, nil
		},
	}); !errors.Is(err, ErrSideEffectPending) {
		t.Fatalf("seed confirmation: %v", err)
	}
	if pending := bridge.PendingEvents("sess_old"); len(pending) != 1 {
		t.Fatalf("pending confirmation events = %+v", pending)
	}

	oldDone := make(chan error, 1)
	go func() {
		_, err := manager.SendMessage(context.Background(), "old turn")
		oldDone <- err
	}()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("old turn did not reach runner")
	}

	newEvents, err := manager.SendMessage(context.Background(), "/new")
	if err != nil {
		t.Fatalf("rotate session: %v", err)
	}
	if manager.SessionID() != "sess_new" || !hasEvent(newEvents, protocol.EventSessionInfo) {
		t.Fatalf("rotation = session:%q events:%+v", manager.SessionID(), newEvents)
	}
	select {
	case err := <-oldDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("old turn error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old turn was not drained before rotation")
	}
	bridge.mu.Lock()
	pendingCount := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingCount != 0 {
		t.Fatalf("old confirmation count after rotation = %d, want 0", pendingCount)
	}
	store := manager.deps.Sessions
	oldEvents, err := store.Load(context.Background(), "sess_old")
	if err != nil {
		t.Fatal(err)
	}
	newSessionEvents, err := store.Load(context.Background(), "sess_new")
	if err != nil {
		t.Fatal(err)
	}
	if !hasTaskTitle(oldEvents, protocol.EventTaskComplete, "/new") {
		t.Fatalf("old session is missing the rotation terminal: %+v", oldEvents)
	}
	if hasTaskTitle(newSessionEvents, protocol.EventTaskComplete, "/new") {
		t.Fatalf("rotation terminal leaked into new session: %+v", newSessionEvents)
	}
	observedMu.Lock()
	defer observedMu.Unlock()
	oldTerminalIndex := eventIndex(observed, protocol.EventTaskComplete, "Message")
	rotationStartIndex := eventIndex(observed, protocol.EventTaskStarted, "/new")
	if oldTerminalIndex < 0 || rotationStartIndex <= oldTerminalIndex {
		t.Fatalf("subscription order does not match durable rotation order: %+v", observed)
	}
}

func TestSessionRotationPublishesTransitionAfterItsCommitPoint(t *testing.T) {
	manager := newTurnTestManager(t, newControlledTurnRunner(), time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	turn, started, err := manager.beginTurn(context.Background(), "/new", true)
	if err != nil {
		t.Fatal(err)
	}
	info := protocol.SessionInfo{ID: "sess_rotated", CreatedAt: time.Now().UTC()}
	if !manager.rotateSession(turn, info, nil) {
		t.Fatal("rotation did not reach its commit point")
	}
	turn.cancel()
	transition := protocol.NewEvent(protocol.EventSessionInfo, info.ID, "session ready", info)
	completed, err := manager.finishTurn(turn, []protocol.Event{transition}, nil)
	if err != nil {
		t.Fatalf("post-commit cancellation changed rotation outcome: %v", err)
	}
	events := append(started, completed...)
	if !hasEvent(events, protocol.EventSessionInfo) {
		t.Fatalf("committed transition was dropped: %+v", events)
	}
	assertSingleTaskLifecycle(t, events, protocol.TaskCompleted)
}

func TestSubscriberCanRotateSessionFromTaskStartedWithoutDeadlock(t *testing.T) {
	runner := newControlledTurnRunner()
	ids := []string{"sess_old", "sess_new"}
	var idMu sync.Mutex
	manager := New(Dependencies{
		Sessions:    local.New(t.TempDir()),
		EinoRunner:  runner,
		TurnTimeout: time.Second,
		NewSessionID: func() string {
			idMu.Lock()
			defer idMu.Unlock()
			id := ids[0]
			ids = ids[1:]
			return id
		},
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	var once atomic.Bool
	nested := make(chan error, 1)
	var observedMu sync.Mutex
	var observed []protocol.Event
	unsubscribe := manager.Subscribe(func(events []protocol.Event) {
		observedMu.Lock()
		observed = append(observed, events...)
		observedMu.Unlock()
		if hasTaskTitle(events, protocol.EventTaskStarted, "Message") && once.CompareAndSwap(false, true) {
			_, err := manager.SendMessage(context.Background(), "/new")
			nested <- err
		}
	})
	defer unsubscribe()

	type result struct {
		events []protocol.Event
		err    error
	}
	outer := make(chan result, 1)
	go func() {
		events, err := manager.SendMessage(context.Background(), "rotate from subscriber")
		outer <- result{events: events, err: err}
	}()

	select {
	case err := <-nested:
		if err != nil {
			t.Fatalf("subscriber rotation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber rotation deadlocked")
	}
	var completed result
	select {
	case completed = <-outer:
	case <-time.After(time.Second):
		t.Fatal("outer turn did not finish after subscriber rotation")
	}
	if !errors.Is(completed.err, context.Canceled) {
		t.Fatalf("outer turn error = %v, want context.Canceled", completed.err)
	}
	assertSingleTaskLifecycle(t, completed.events, protocol.TaskKilled)
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("runner calls = %d, want 0 after reentrant cancellation", got)
	}
	if got := manager.SessionID(); got != "sess_new" {
		t.Fatalf("session ID = %q, want sess_new", got)
	}

	observedMu.Lock()
	defer observedMu.Unlock()
	startedIndex := eventIndex(observed, protocol.EventTaskStarted, "Message")
	terminalIndex := eventIndex(observed, protocol.EventTaskComplete, "Message")
	rotationIndex := eventIndex(observed, protocol.EventTaskStarted, "/new")
	if startedIndex < 0 || terminalIndex <= startedIndex || rotationIndex <= terminalIndex {
		t.Fatalf("subscriber lifecycle order is invalid: %+v", observed)
	}
}

func TestResumeCurrentSessionDoesNotReplayActiveTaskStart(t *testing.T) {
	manager := newTurnTestManager(t, newControlledTurnRunner(), time.Second)
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	var observedMu sync.Mutex
	var observed []protocol.Event
	unsubscribe := manager.Subscribe(func(events []protocol.Event) {
		observedMu.Lock()
		observed = append(observed, events...)
		observedMu.Unlock()
	})
	defer unsubscribe()

	events, err := manager.SendMessage(context.Background(), "/resume "+manager.SessionID())
	if err != nil {
		t.Fatalf("resume current session: %v", err)
	}
	assertSingleTaskLifecycle(t, events, protocol.TaskCompleted)
	observedMu.Lock()
	defer observedMu.Unlock()
	if got := countEvents(observed, protocol.EventTaskStarted); got != 1 {
		t.Fatalf("subscribed task.started count = %d, want 1: %+v", got, observed)
	}
	if got := countEvents(observed, protocol.EventTaskComplete); got != 1 {
		t.Fatalf("subscribed task.complete count = %d, want 1: %+v", got, observed)
	}
}

func TestResumePreservesHistoricalLifecycleWhenTaskIDCollides(t *testing.T) {
	store := local.New(t.TempDir())
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   newControlledTurnRunner(),
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_resume_collision" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionID := manager.SessionID()
	historicalTime := time.Now().UTC().Add(-time.Hour)
	historicalTask := protocol.Task{
		ID:        "task_000001",
		Title:     "Historical task",
		Status:    protocol.TaskRunning,
		CreatedAt: historicalTime,
		UpdatedAt: historicalTime,
	}
	historical := []protocol.Event{
		protocol.NewEvent(protocol.EventTaskStarted, sessionID, "Historical task started", historicalTask),
		protocol.NewEvent(protocol.EventTaskProgress, sessionID, "Historical task progressed", historicalTask),
		protocol.NewEvent(protocol.EventTaskComplete, sessionID, "Historical task completed", protocol.Task{
			ID:        historicalTask.ID,
			Title:     historicalTask.Title,
			Status:    protocol.TaskCompleted,
			CreatedAt: historicalTime,
			UpdatedAt: historicalTime.Add(time.Minute),
		}),
	}
	for _, event := range historical {
		if err := store.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}

	events, err := manager.SendMessage(context.Background(), "/resume "+sessionID)
	if err != nil {
		t.Fatalf("resume current session: %v", err)
	}
	for _, eventType := range []protocol.EventType{
		protocol.EventTaskStarted,
		protocol.EventTaskProgress,
		protocol.EventTaskComplete,
	} {
		if got := countTaskTitle(events, eventType, historicalTask.Title); got != 1 {
			t.Fatalf("historical %s count = %d, want 1: %+v", eventType, got, events)
		}
	}
	if got := countTaskTitle(events, protocol.EventTaskStarted, "/resume"); got != 1 {
		t.Fatalf("current resume start count = %d, want 1: %+v", got, events)
	}
	assertTaskStatus(t, events, "/resume", protocol.TaskCompleted)
}

func TestResumeReplayErrorsDoNotFailCurrentTask(t *testing.T) {
	store := local.New(t.TempDir())
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   newControlledTurnRunner(),
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_resume_errors" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionID := manager.SessionID()
	for _, event := range []protocol.Event{
		protocol.NewEvent(protocol.EventError, sessionID, "historical runtime error", nil),
		protocol.NewEvent(protocol.EventToolError, sessionID, "historical tool error", map[string]string{"tool": "knote_diff"}),
	} {
		if err := store.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}

	events, err := manager.SendMessage(context.Background(), "/resume "+sessionID)
	if err != nil {
		t.Fatalf("resume current session: %v", err)
	}
	if !hasMessage(events, protocol.EventError, "historical runtime error") ||
		!hasMessage(events, protocol.EventToolError, "historical tool error") {
		t.Fatalf("historical errors were not replayed: %+v", events)
	}
	assertTaskStatus(t, events, "/resume", protocol.TaskCompleted)
}

func TestSlashResumeDropsStaleConfirmationAndReconcilesOrphanTask(t *testing.T) {
	store := local.New(t.TempDir())
	manager := New(Dependencies{
		Sessions:     store,
		EinoRunner:   immediateTurnRunner{},
		TurnTimeout:  time.Second,
		NewSessionID: func() string { return "sess_current" },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	targetSessionID := "sess_orphaned"
	createdAt := time.Now().UTC().Add(-time.Hour)
	orphan := protocol.Task{
		ID:        "task_orphaned",
		Title:     "Interrupted historical task",
		Status:    protocol.TaskRunning,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}
	confirm := protocol.ConfirmRequest{RequestID: "stale_confirm", Action: "build", Command: "/build"}
	for _, event := range []protocol.Event{
		protocol.NewEvent(protocol.EventTaskStarted, targetSessionID, "Task started", orphan),
		protocol.NewEvent(protocol.EventConfirmRequest, targetSessionID, "Stale confirmation", confirm),
	} {
		if err := store.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}

	events, err := manager.SendMessage(context.Background(), "/resume "+targetSessionID)
	if err != nil {
		t.Fatalf("resume orphaned session: %v", err)
	}
	if hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("resume replayed an unexecutable confirmation: %+v", events)
	}
	assertTaskStatus(t, events, orphan.Title, protocol.TaskKilled)
	loaded, err := store.Load(context.Background(), targetSessionID)
	if err != nil {
		t.Fatal(err)
	}
	assertTaskStatus(t, loaded, orphan.Title, protocol.TaskKilled)
	if got := countTaskTitle(loaded, protocol.EventTaskComplete, orphan.Title); got != 1 {
		t.Fatalf("persisted orphan terminals = %d, want 1: %+v", got, loaded)
	}
}

func TestStartResumeDropsStaleConfirmationAndReconcilesOrphanTask(t *testing.T) {
	store := local.New(t.TempDir())
	sessionID := "sess_start_orphaned"
	createdAt := time.Now().UTC().Add(-time.Hour)
	orphan := protocol.Task{
		ID:        "task_start_orphaned",
		Title:     "Startup interrupted task",
		Status:    protocol.TaskRunning,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}
	for _, event := range []protocol.Event{
		protocol.NewEvent(protocol.EventTaskStarted, sessionID, "Task started", orphan),
		protocol.NewEvent(protocol.EventConfirmRequest, sessionID, "Stale confirmation", protocol.ConfirmRequest{
			RequestID: "startup_stale_confirm", Action: "build", Command: "/build",
		}),
	} {
		if err := store.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	manager := New(Dependencies{Sessions: store, EinoRunner: immediateTurnRunner{}})

	events, err := manager.Start(context.Background(), StartOptions{ResumeID: sessionID})
	if err != nil {
		t.Fatalf("start resumed session: %v", err)
	}
	if hasEvent(events, protocol.EventConfirmRequest) {
		t.Fatalf("startup replayed an unexecutable confirmation: %+v", events)
	}
	assertTaskStatus(t, events, orphan.Title, protocol.TaskKilled)
	loaded, err := store.Load(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	assertTaskStatus(t, loaded, orphan.Title, protocol.TaskKilled)
	if got := countTaskTitle(loaded, protocol.EventTaskComplete, orphan.Title); got != 1 {
		t.Fatalf("persisted startup orphan terminals = %d, want 1: %+v", got, loaded)
	}
}

func TestStartDoesNotHoldStateMutexAcrossDependencyIO(t *testing.T) {
	store := local.New(t.TempDir())
	if err := store.Append(context.Background(), protocol.NewEvent(protocol.EventAssistantDone, "sess_resume", "stored", nil)); err != nil {
		t.Fatal(err)
	}
	var manager *Manager
	var callbacks atomic.Int32
	reentrant := func() {
		callbacks.Add(1)
		_ = manager.SessionID()
	}
	runner := &reentrantReadyRunner{onReady: reentrant}
	sessions := &reentrantSessions{Sessions: store, onLoad: reentrant}
	versions := &reentrantVersions{delegate: store, onStatus: reentrant}
	manager = New(Dependencies{
		Sessions:     sessions,
		Versions:     versions,
		EinoRunner:   runner,
		NewSessionID: func() string { return "sess_new" },
	})

	done := make(chan error, 1)
	go func() {
		_, err := manager.Start(context.Background(), StartOptions{ResumeID: "sess_resume"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start deadlocked while a dependency re-entered runtime state")
	}
	if got := callbacks.Load(); got != 3 {
		t.Fatalf("reentrant callbacks = %d, want runner, session, and versions callbacks", got)
	}
}

type controlledTurnRunner struct {
	started chan struct{}
	calls   atomic.Int32
}

type immediateTurnRunner struct{}

func (immediateTurnRunner) Ready(context.Context) error { return nil }

func (immediateTurnRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return nil, nil
}

func (immediateTurnRunner) Run(_ context.Context, input EinoRunInput) ([]protocol.Event, error) {
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, "accepted answer", nil)}, nil
}

type lateEventTurnRunner struct{ started chan struct{} }

type stubbornTurnRunner struct {
	started chan struct{}
	release chan struct{}
}

func (*stubbornTurnRunner) Ready(context.Context) error { return nil }

func (*stubbornTurnRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return nil, nil
}

func (r *stubbornTurnRunner) Run(ctx context.Context, _ EinoRunInput) ([]protocol.Event, error) {
	close(r.started)
	<-r.release
	return nil, ctx.Err()
}

type cancelPendingTurnRunner struct {
	bridge    *SideEffectBridge
	requested chan struct{}
}

func (*cancelPendingTurnRunner) Ready(context.Context) error { return nil }

func (*cancelPendingTurnRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return nil, nil
}

func (r *cancelPendingTurnRunner) Run(ctx context.Context, _ EinoRunInput) ([]protocol.Event, error) {
	err := r.bridge.Request(ctx, SideEffectRequest{
		ToolName: "knote_build",
		Action:   "build",
		Execute: func(context.Context, SideEffectRequest) ([]protocol.Event, error) {
			return nil, nil
		},
	})
	close(r.requested)
	<-ctx.Done()
	return nil, err
}

func (*lateEventTurnRunner) Ready(context.Context) error { return nil }

func (*lateEventTurnRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return nil, nil
}

func (r *lateEventTurnRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	close(r.started)
	<-ctx.Done()
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, "late answer", nil)}, nil
}

func newControlledTurnRunner() *controlledTurnRunner {
	return &controlledTurnRunner{started: make(chan struct{}, 8)}
}

func (r *controlledTurnRunner) Ready(context.Context) error { return nil }

func (r *controlledTurnRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return nil, nil
}

func (r *controlledTurnRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	r.calls.Add(1)
	r.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func newTurnTestManager(t *testing.T, runner EinoRunner, timeout time.Duration) *Manager {
	t.Helper()
	return New(Dependencies{
		Sessions:     local.New(t.TempDir()),
		EinoRunner:   runner,
		TurnTimeout:  timeout,
		NewSessionID: func() string { return "sess_turn" },
	})
}

func assertSingleTaskLifecycle(t *testing.T, events []protocol.Event, wantStatus protocol.TaskStatus) {
	t.Helper()
	if got := countEvents(events, protocol.EventTaskStarted); got != 1 {
		t.Fatalf("task.started count = %d, want 1: %+v", got, events)
	}
	if got := countEvents(events, protocol.EventTaskComplete); got != 1 {
		t.Fatalf("task.complete count = %d, want 1: %+v", got, events)
	}
	for _, event := range events {
		if event.Type != protocol.EventTaskComplete {
			continue
		}
		data, err := json.Marshal(event.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var task protocol.Task
		if err := json.Unmarshal(data, &task); err != nil {
			t.Fatal(err)
		}
		if task.Status != wantStatus {
			t.Fatalf("task status = %s, want %s", task.Status, wantStatus)
		}
	}
}

func taskIDFromEvents(t *testing.T, events []protocol.Event) string {
	t.Helper()
	for _, event := range events {
		if event.Type != protocol.EventTaskStarted {
			continue
		}
		data, err := json.Marshal(event.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var task protocol.Task
		if err := json.Unmarshal(data, &task); err != nil {
			t.Fatal(err)
		}
		if task.ID != "" {
			return task.ID
		}
	}
	t.Fatalf("task id missing from %+v", events)
	return ""
}

func hasTaskTitle(events []protocol.Event, eventType protocol.EventType, title string) bool {
	for _, event := range events {
		if event.Type != eventType {
			continue
		}
		data, err := json.Marshal(event.Payload)
		if err != nil {
			continue
		}
		var task protocol.Task
		if json.Unmarshal(data, &task) == nil && task.Title == title {
			return true
		}
	}
	return false
}

func countTaskTitle(events []protocol.Event, eventType protocol.EventType, title string) int {
	count := 0
	for _, event := range events {
		if hasTaskTitle([]protocol.Event{event}, eventType, title) {
			count++
		}
	}
	return count
}

func assertTaskStatus(t *testing.T, events []protocol.Event, title string, want protocol.TaskStatus) {
	t.Helper()
	for _, event := range events {
		if event.Type != protocol.EventTaskComplete {
			continue
		}
		data, err := json.Marshal(event.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var task protocol.Task
		if err := json.Unmarshal(data, &task); err != nil {
			t.Fatal(err)
		}
		if task.Title == title {
			if task.Status != want {
				t.Fatalf("task %q status = %s, want %s", title, task.Status, want)
			}
			return
		}
	}
	t.Fatalf("task %q terminal missing from %+v", title, events)
}

func eventIndex(events []protocol.Event, eventType protocol.EventType, title string) int {
	for i, event := range events {
		if hasTaskTitle([]protocol.Event{event}, eventType, title) {
			return i
		}
	}
	return -1
}

type reentrantReadyRunner struct{ onReady func() }

func (r *reentrantReadyRunner) Ready(context.Context) error {
	r.onReady()
	return nil
}

func (*reentrantReadyRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return nil, nil
}

func (*reentrantReadyRunner) Run(context.Context, EinoRunInput) ([]protocol.Event, error) {
	return nil, fmt.Errorf("unexpected run")
}

type reentrantSessions struct {
	repository.Sessions
	onLoad func()
}

type blockingResultSessions struct {
	repository.Sessions
	blocked   chan struct{}
	release   chan struct{}
	blockType protocol.EventType
	once      sync.Once
}

type failingEventSessions struct {
	repository.Sessions
	failType protocol.EventType
	err      error
}

func (s *failingEventSessions) Append(ctx context.Context, event protocol.Event) error {
	if event.Type == s.failType {
		return s.err
	}
	return s.Sessions.Append(ctx, event)
}

func (s *blockingResultSessions) Append(ctx context.Context, event protocol.Event) error {
	if event.Type == s.blockType {
		s.once.Do(func() { close(s.blocked) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Sessions.Append(ctx, event)
}

func interruptTaskIDsForTest(events []protocol.Event) []string {
	var ids []string
	for _, event := range events {
		if event.Type != protocol.EventStatusUpdate {
			continue
		}
		data, _ := json.Marshal(event.Payload)
		var payload struct {
			TaskID string `json:"task_id"`
		}
		if json.Unmarshal(data, &payload) == nil && payload.TaskID != "" {
			ids = append(ids, payload.TaskID)
		}
	}
	return ids
}

func (s *reentrantSessions) Load(ctx context.Context, sessionID string) ([]protocol.Event, error) {
	s.onLoad()
	return s.Sessions.Load(ctx, sessionID)
}

type reentrantVersions struct {
	delegate repository.Versions
	onStatus func()
}

func (v *reentrantVersions) Status(ctx context.Context) (repository.Status, error) {
	v.onStatus()
	return v.delegate.Status(ctx)
}

func (v *reentrantVersions) Diff(ctx context.Context, ref string) (string, error) {
	return v.delegate.Diff(ctx, ref)
}

func (v *reentrantVersions) Versions(ctx context.Context, limit int) ([]repository.Version, error) {
	return v.delegate.Versions(ctx, limit)
}

func (v *reentrantVersions) Commit(ctx context.Context, message string) (repository.CommitResult, error) {
	return v.delegate.Commit(ctx, message)
}

func (v *reentrantVersions) Tag(ctx context.Context, tag string) error {
	return v.delegate.Tag(ctx, tag)
}

func (v *reentrantVersions) Checkout(ctx context.Context, ref string, opts repository.CheckoutOptions) error {
	return v.delegate.Checkout(ctx, ref, opts)
}
