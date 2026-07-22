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

type lateEventTurnRunner struct{ started chan struct{} }

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
