package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const DefaultTurnTimeout = 3 * time.Minute

var (
	ErrTurnBusy                 = errors.New("runtime turn is already active")
	ErrTurnNotStarted           = errors.New("runtime turn did not start")
	ErrConfirmationNotExecuted  = errors.New("runtime confirmation was not executed")
	ErrSideEffectOutcomeUnknown = errors.New("runtime side-effect outcome is unknown")
	ErrTaskNotFound             = errors.New("runtime task not found")
)

const confirmationTurnTitle = "Confirmation"

type activeTurn struct {
	id                 string
	title              string
	lifecycleSessionID string
	targetSessionID    string
	targetGeneration   uint64
	createdAt          time.Time
	ctx                context.Context
	cancel             context.CancelFunc
	done               chan struct{}
	rotation           bool
	rotationCommitted  bool
	notifying          bool
	finished           bool
	startCommitted     bool
	lifecycleStart     protocol.Event
	terminal           protocol.Event
}

type activeTurnContextKey struct{}

func (m *Manager) beginTurn(parent context.Context, title string, rotation bool) (*activeTurn, []protocol.Event, error) {
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	timeout := m.deps.TurnTimeout
	if timeout <= 0 {
		timeout = DefaultTurnTimeout
	}
	timedCtx, cancel := context.WithTimeout(parent, timeout)
	keepContext := false
	defer func() {
		if !keepContext {
			cancel()
		}
	}()

	if rotation {
		m.mu.Lock()
		if m.starting || m.rotating {
			m.mu.Unlock()
			return nil, nil, ErrTurnBusy
		}
		if m.einoSession.ID == "" {
			m.mu.Unlock()
			return nil, nil, fmt.Errorf("runtime has not started")
		}
		m.rotating = true
		previous := m.activeTurn
		reentrant := previous != nil && (previous.notifying || activeTurnIDFromContext(parent) == previous.id)
		m.mu.Unlock()

		if previous != nil {
			previous.cancel()
			if reentrant {
				m.completeTurn(previous, protocol.TaskKilled, "Task interrupted")
			} else {
				select {
				case <-previous.done:
				case <-timedCtx.Done():
					m.mu.Lock()
					m.rotating = false
					m.mu.Unlock()
					return nil, nil, timedCtx.Err()
				}
			}
		}
	}

	m.commitMu.Lock()
	m.mu.Lock()
	if err := timedCtx.Err(); err != nil {
		if rotation {
			m.rotating = false
		}
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, nil, err
	}
	if m.starting || (!rotation && (m.rotating || m.activeTurn != nil)) {
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, nil, ErrTurnBusy
	}
	if m.einoSession.ID == "" {
		if rotation {
			m.rotating = false
		}
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, nil, fmt.Errorf("runtime has not started")
	}
	if rotation && m.activeTurn != nil {
		m.rotating = false
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, nil, ErrTurnBusy
	}
	m.nextTurnID++
	taskID := fmt.Sprintf("task_%06d", m.nextTurnID)
	turnCtx := context.WithValue(timedCtx, activeTurnContextKey{}, taskID)
	now := time.Now().UTC()
	turn := &activeTurn{
		id:                 taskID,
		title:              turnTitle(title),
		lifecycleSessionID: m.einoSession.ID,
		targetSessionID:    m.einoSession.ID,
		targetGeneration:   m.generation,
		createdAt:          now,
		ctx:                turnCtx,
		cancel:             cancel,
		done:               make(chan struct{}),
		rotation:           rotation,
	}
	started := protocol.NewEvent(protocol.EventTaskStarted, turn.lifecycleSessionID, "Task started", protocol.Task{
		ID:        turn.id,
		Title:     turn.title,
		Status:    protocol.TaskRunning,
		CreatedAt: now,
		UpdatedAt: now,
	})
	turn.lifecycleStart = started
	m.activeTurn = turn
	m.mu.Unlock()
	m.commitMu.Unlock()
	persistErr := m.persist(turn.ctx, []protocol.Event{started})
	m.commitMu.Lock()
	m.mu.Lock()
	if persistErr != nil {
		turn.finished = true
		if m.activeTurn == turn {
			m.activeTurn = nil
		}
		if turn.rotation {
			m.rotating = false
		}
		close(turn.done)
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, nil, fmt.Errorf("%w: persist task start: %w", ErrTurnNotStarted, persistErr)
	}
	if m.activeTurn != turn || turn.finished {
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, nil, ErrTurnBusy
	}
	turn.startCommitted = true
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	dispatch := m.enqueueNotifications(turn, subscribers, []protocol.Event{started})
	m.commitMu.Unlock()
	if dispatch {
		m.drainNotifications()
	}
	keepContext = true
	return turn, []protocol.Event{started}, nil
}

func (m *Manager) completeTurn(turn *activeTurn, status protocol.TaskStatus, message string) (protocol.Event, bool) {
	if turn == nil {
		return protocol.Event{}, false
	}
	m.commitMu.Lock()
	m.mu.Lock()
	if m.activeTurn != turn || turn.finished {
		m.mu.Unlock()
		m.commitMu.Unlock()
		return protocol.Event{}, false
	}
	turn.finished = true
	terminalSessionID := turn.lifecycleSessionID
	now := time.Now().UTC()
	terminal := protocol.NewEvent(protocol.EventTaskComplete, terminalSessionID, message, protocol.Task{
		ID:        turn.id,
		Title:     turn.title,
		Status:    status,
		CreatedAt: turn.createdAt,
		UpdatedAt: now,
		Message:   message,
	})
	turn.terminal = terminal
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	m.commitMu.Unlock()
	if status == protocol.TaskKilled && m.deps.SideEffects != nil {
		m.deps.SideEffects.ClearTurn(turn.lifecycleSessionID, turn.id)
	}
	if err := m.persist(context.WithoutCancel(turn.ctx), []protocol.Event{terminal}); err != nil {
		return terminal, false
	}
	m.commitMu.Lock()
	dispatch := m.enqueueNotifications(turn, subscribers, []protocol.Event{terminal})
	m.mu.Lock()
	if m.activeTurn == turn {
		m.activeTurn = nil
	}
	if turn.rotation {
		m.rotating = false
	}
	close(turn.done)
	m.mu.Unlock()
	m.commitMu.Unlock()
	turn.cancel()
	if dispatch {
		m.drainNotifications()
	}
	return terminal, true
}

func (m *Manager) rotateSession(turn *activeTurn, info protocol.SessionInfo, binding *authorizationBinding) bool {
	if turn == nil || strings.TrimSpace(info.ID) == "" {
		return false
	}
	m.commitMu.Lock()
	m.mu.Lock()
	if m.activeTurn != turn || turn.finished || turn.ctx.Err() != nil {
		m.mu.Unlock()
		m.commitMu.Unlock()
		return false
	}
	oldSessionID := m.einoSession.ID
	m.mu.Unlock()
	if m.deps.SideEffects != nil {
		m.deps.SideEffects.ClearSession(oldSessionID)
	}
	m.mu.Lock()
	m.generation++
	m.einoSession = info
	m.authorizationBinding = binding
	turn.targetSessionID = info.ID
	turn.targetGeneration = m.generation
	turn.rotationCommitted = true
	m.mu.Unlock()
	m.commitMu.Unlock()
	return true
}

func (m *Manager) finishTurn(turn *activeTurn, events []protocol.Event, operationErr error) ([]protocol.Event, error) {
	return m.finishTurnWithCommittedOutcome(turn, events, operationErr, false)
}

func (m *Manager) finishTurnWithCommittedOutcome(
	turn *activeTurn,
	events []protocol.Event,
	operationErr error,
	committed bool,
) ([]protocol.Event, error) {
	return m.finishTurnResultWithStatusEvents(turn, events, events, events, operationErr, committed)
}

func (m *Manager) finishTurnResult(turn *activeTurn, persisted, emitted []protocol.Event, operationErr error) ([]protocol.Event, error) {
	return m.finishTurnResultWithStatusEvents(turn, persisted, emitted, emitted, operationErr, false)
}

func (m *Manager) finishTurnResultWithStatusEvents(
	turn *activeTurn,
	persisted []protocol.Event,
	emitted []protocol.Event,
	statusEvents []protocol.Event,
	operationErr error,
	committedOutcome bool,
) ([]protocol.Event, error) {
	if turn == nil {
		return nil, operationErr
	}
	m.commitMu.Lock()
	m.mu.Lock()
	rotationCommitted := turn.rotationCommitted
	contextErr := turn.ctx.Err()
	if m.activeTurn != turn || turn.finished {
		terminal := turn.terminal
		m.mu.Unlock()
		m.commitMu.Unlock()
		var returnErr error
		if contextErr != nil && !rotationCommitted {
			returnErr = contextErr
		}
		if terminal.Type == "" {
			return nil, returnErr
		}
		return []protocol.Event{terminal}, returnErr
	}
	commitResult := (contextErr == nil || rotationCommitted || committedOutcome) &&
		m.generation == turn.targetGeneration && m.einoSession.ID == turn.targetSessionID
	status := protocol.TaskCompleted
	message := "Task completed"
	returnErr := error(nil)
	clearTurn := false
	if contextErr != nil && !rotationCommitted && !committedOutcome {
		commitResult = false
		returnErr = contextErr
		clearTurn = true
		if errors.Is(contextErr, context.DeadlineExceeded) {
			status = protocol.TaskFailed
			message = "Task timed out"
		} else {
			status = protocol.TaskKilled
			message = "Task interrupted"
		}
	} else if operationErr != nil || hasErrorEvent(statusEvents) {
		status = protocol.TaskFailed
		message = "Task failed"
	}
	if !commitResult {
		persisted = nil
		emitted = nil
	}
	turn.finished = true
	now := time.Now().UTC()
	terminal := protocol.NewEvent(protocol.EventTaskComplete, turn.lifecycleSessionID, message, protocol.Task{
		ID:        turn.id,
		Title:     turn.title,
		Status:    status,
		CreatedAt: turn.createdAt,
		UpdatedAt: now,
		Message:   message,
	})
	turn.terminal = terminal
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	m.commitMu.Unlock()

	if clearTurn && m.deps.SideEffects != nil {
		m.deps.SideEffects.ClearTurn(turn.lifecycleSessionID, turn.id)
	}
	toPersist := make([]protocol.Event, 0, len(persisted)+1)
	toPersist = append(toPersist, persisted...)
	toPersist = append(toPersist, terminal)
	// Once a result is accepted, cancellation stops new work but cannot split the
	// result from its terminal record. Keep the turn busy until both are durable.
	persistCtx := context.WithoutCancel(turn.ctx)
	persistErr := m.persist(persistCtx, toPersist)
	if persistErr != nil {
		turn.cancel()
		if returnErr == nil {
			returnErr = fmt.Errorf("persist task result: %w", persistErr)
		}
		return nil, returnErr
	}
	m.commitMu.Lock()
	dispatch := false
	if commitResult && m.enqueueNotifications(turn, subscribers, emitted) {
		dispatch = true
	}
	if m.enqueueNotifications(turn, subscribers, []protocol.Event{terminal}) {
		dispatch = true
	}
	m.mu.Lock()
	if m.activeTurn == turn {
		m.activeTurn = nil
	}
	if turn.rotation {
		m.rotating = false
	}
	close(turn.done)
	m.mu.Unlock()
	m.commitMu.Unlock()
	turn.cancel()
	if dispatch {
		m.drainNotifications()
	}
	return append(emitted, terminal), returnErr
}

func activeTurnIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	taskID, _ := ctx.Value(activeTurnContextKey{}).(string)
	return taskID
}

func turnTitle(input string) string {
	title := strings.TrimSpace(input)
	const maxTitleBytes = 96
	if len(title) <= maxTitleBytes {
		return title
	}
	return strings.TrimSpace(title[:maxTitleBytes])
}

func (m *Manager) subscribersLocked() []EventSubscriber {
	subscribers := make([]EventSubscriber, 0, len(m.subscribers))
	for _, fn := range m.subscribers {
		subscribers = append(subscribers, fn)
	}
	return subscribers
}

func (m *Manager) publishNotifications(turn *activeTurn, subscribers []EventSubscriber, events []protocol.Event) {
	if m.enqueueNotifications(turn, subscribers, events) {
		m.drainNotifications()
	}
}

func (m *Manager) enqueueNotifications(turn *activeTurn, subscribers []EventSubscriber, events []protocol.Event) bool {
	if len(events) == 0 {
		return false
	}
	batch := notificationBatch{
		subscribers: append([]EventSubscriber(nil), subscribers...),
		events:      append([]protocol.Event(nil), events...),
		turn:        turn,
	}
	m.notifyMu.Lock()
	m.notificationQueue = append(m.notificationQueue, batch)
	if m.dispatching {
		m.notifyMu.Unlock()
		return false
	}
	m.dispatching = true
	m.notifyMu.Unlock()
	return true
}

func (m *Manager) drainNotifications() {
	m.notifyMu.Lock()
	for len(m.notificationQueue) > 0 {
		batch := m.notificationQueue[0]
		m.notificationQueue[0] = notificationBatch{}
		m.notificationQueue = m.notificationQueue[1:]
		m.notifyMu.Unlock()
		if batch.turn != nil {
			m.mu.Lock()
			batch.turn.notifying = true
			m.mu.Unlock()
		}
		for _, fn := range batch.subscribers {
			fn(append([]protocol.Event(nil), batch.events...))
		}
		if batch.turn != nil {
			m.mu.Lock()
			batch.turn.notifying = false
			m.mu.Unlock()
		}
		m.notifyMu.Lock()
	}
	m.dispatching = false
	m.notifyMu.Unlock()
}
