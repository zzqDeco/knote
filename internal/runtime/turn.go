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
	ErrTurnBusy     = errors.New("runtime turn is already active")
	ErrTaskNotFound = errors.New("runtime task not found")
)

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
				case <-parent.Done():
					m.mu.Lock()
					m.rotating = false
					m.mu.Unlock()
					return nil, nil, parent.Err()
				}
			}
		}
		m.mu.Lock()
		oldSessionID := m.einoSession.ID
		m.mu.Unlock()
		if m.deps.SideEffects != nil {
			m.deps.SideEffects.ClearSession(oldSessionID)
		}
	}

	m.mu.Lock()
	if m.starting || (!rotation && (m.rotating || m.activeTurn != nil)) {
		m.mu.Unlock()
		return nil, nil, ErrTurnBusy
	}
	if m.einoSession.ID == "" {
		if rotation {
			m.rotating = false
		}
		m.mu.Unlock()
		return nil, nil, fmt.Errorf("runtime has not started")
	}
	if rotation && m.activeTurn != nil {
		m.rotating = false
		m.mu.Unlock()
		return nil, nil, ErrTurnBusy
	}
	m.nextTurnID++
	taskID := fmt.Sprintf("task_%06d", m.nextTurnID)
	timeout := m.deps.TurnTimeout
	if timeout <= 0 {
		timeout = DefaultTurnTimeout
	}
	turnCtx, cancel := context.WithTimeout(context.WithValue(parent, activeTurnContextKey{}, taskID), timeout)
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
	m.activeTurn = turn
	m.mu.Unlock()

	started := protocol.NewEvent(protocol.EventTaskStarted, turn.lifecycleSessionID, "Task started", protocol.Task{
		ID:        turn.id,
		Title:     turn.title,
		Status:    protocol.TaskRunning,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if !m.commitTurnResult(turn, []protocol.Event{started}, []protocol.Event{started}) {
		turn.cancel()
		m.mu.Lock()
		if m.activeTurn == turn {
			m.activeTurn = nil
		}
		if turn.rotation {
			m.rotating = false
		}
		close(turn.done)
		m.mu.Unlock()
		if err := turn.ctx.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrTurnBusy
	}
	return turn, []protocol.Event{started}, nil
}

func (m *Manager) commitTurnResult(turn *activeTurn, persisted, emitted []protocol.Event) bool {
	if turn == nil {
		return false
	}
	m.commitMu.Lock()
	m.mu.Lock()
	valid := m.activeTurn == turn && !turn.finished && (turn.ctx.Err() == nil || turn.rotationCommitted) &&
		m.generation == turn.targetGeneration && m.einoSession.ID == turn.targetSessionID
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	if !valid {
		m.commitMu.Unlock()
		return false
	}
	m.persist(persisted)
	dispatch := m.enqueueNotifications(turn, subscribers, emitted)
	m.commitMu.Unlock()
	if dispatch {
		m.drainNotifications()
	}
	return true
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
	m.persist([]protocol.Event{terminal})
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
	m.mu.Lock()
	if m.activeTurn != turn || turn.finished || turn.ctx.Err() != nil {
		m.mu.Unlock()
		return false
	}
	oldSessionID := m.einoSession.ID
	m.mu.Unlock()
	if m.deps.SideEffects != nil {
		m.deps.SideEffects.ClearSession(oldSessionID)
	}
	m.commitMu.Lock()
	m.mu.Lock()
	if m.activeTurn != turn || turn.finished || turn.ctx.Err() != nil {
		m.mu.Unlock()
		m.commitMu.Unlock()
		return false
	}
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
	return m.finishTurnResult(turn, events, events, operationErr)
}

func (m *Manager) finishTurnResult(turn *activeTurn, persisted, emitted []protocol.Event, operationErr error) ([]protocol.Event, error) {
	committed := m.commitTurnResult(turn, persisted, emitted)
	if !committed {
		emitted = nil
	}

	m.mu.Lock()
	rotationCommitted := turn.rotationCommitted
	m.mu.Unlock()
	status := protocol.TaskCompleted
	message := "Task completed"
	returnErr := error(nil)
	if err := turn.ctx.Err(); err != nil && !rotationCommitted {
		returnErr = err
		if errors.Is(err, context.DeadlineExceeded) {
			status = protocol.TaskFailed
			message = "Task timed out"
		} else {
			status = protocol.TaskKilled
			message = "Task interrupted"
		}
	} else if operationErr != nil || hasErrorEvent(emitted) {
		status = protocol.TaskFailed
		message = "Task failed"
	}
	terminal, ok := m.completeTurn(turn, status, message)
	if ok {
		emitted = append(emitted, terminal)
	} else if terminal, ok := m.terminalEvent(turn); ok {
		emitted = append(emitted, terminal)
	}
	return emitted, returnErr
}

func (m *Manager) terminalEvent(turn *activeTurn) (protocol.Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if turn == nil || turn.terminal.Type == "" {
		return protocol.Event{}, false
	}
	return turn.terminal, true
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
