package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/governance"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

type Runtime interface {
	Start(ctx context.Context, opts StartOptions) ([]protocol.Event, error)
	SendMessage(ctx context.Context, input string) ([]protocol.Event, error)
	Confirm(ctx context.Context, req protocol.ConfirmRequest, approved bool) ([]protocol.Event, error)
	Interrupt(ctx context.Context) ([]protocol.Event, error)
	StopTask(ctx context.Context, taskID string) ([]protocol.Event, error)
	WorkspaceStatus(ctx context.Context) (repository.Status, error)
	RunnerInfo(ctx context.Context) (RunnerInfo, error)
	Subscribe(fn EventSubscriber) func()

	SessionID() string
	Workspace() string
	CurrentSessionInfo(ctx context.Context) protocol.SessionInfo
}

type Dependencies struct {
	Workspace                    string
	Capabilities                 SessionCapabilityProfile
	Config                       repository.Config
	SettingsYAML                 string
	Sessions                     repository.Sessions
	Versions                     repository.Versions
	WorkspaceRepo                repository.Workspace
	Knowledge                    versioned.Service
	RunnerMode                   RunnerMode
	EinoRunner                   EinoRunner
	AuthorizationContextProvider AuthorizationContextProvider
	ProtectedContentAuthorizer   ProtectedContentAuthorizer
	SideEffects                  *SideEffectBridge
	ToolExecutor                 ToolExecutor
	Governance                   GovernanceProvider
	NewSessionID                 func() string
	TurnTimeout                  time.Duration
}

type AuthorizationContextProvider func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error)

type StartOptions struct {
	ResumeID string
}

type RunnerMode string

const (
	RunnerModeEino RunnerMode = "eino"
)

type EinoRunner interface {
	Ready(ctx context.Context) error
	ToolInventory(ctx context.Context) ([]RunnerToolInfo, error)
	Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error)
}

type EinoRunInput struct {
	SessionID string
	Message   string
	History   []protocol.Event
}

type RunnerInfo struct {
	ConfiguredMode RunnerMode       `json:"configured_mode"`
	ActiveMode     RunnerMode       `json:"active_mode"`
	EinoAvailable  bool             `json:"eino_available"`
	Tools          []RunnerToolInfo `json:"tools,omitempty"`
}

type RunnerToolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type ToolExecutor interface {
	Invoke(ctx context.Context, sessionID string, toolName string, argumentsInJSON string) ([]protocol.Event, error)
}

type GovernanceProvider interface {
	View(context.Context, protocol.AuthorizationContext) (governance.Snapshot, error)
}

type EventSubscriber func([]protocol.Event)

type notificationBatch struct {
	subscribers []EventSubscriber
	events      []protocol.Event
	turn        *activeTurn
}

type Manager struct {
	mu                   sync.Mutex
	commitMu             sync.Mutex
	notifyMu             sync.Mutex
	deps                 Dependencies
	einoSession          protocol.SessionInfo
	authorizationBinding *authorizationBinding
	subscribers          map[int]EventSubscriber
	nextSubID            int
	nextTurnID           uint64
	generation           uint64
	activeTurn           *activeTurn
	starting             bool
	rotating             bool
	dispatching          bool
	notificationQueue    []notificationBatch
}

var _ Runtime = (*Manager)(nil)

func New(deps Dependencies) *Manager {
	deps.RunnerMode = RunnerModeEino
	if deps.TurnTimeout <= 0 {
		deps.TurnTimeout = DefaultTurnTimeout
	}
	return &Manager{
		deps:        deps,
		subscribers: map[int]EventSubscriber{},
	}
}

func (m *Manager) Start(ctx context.Context, opts StartOptions) ([]protocol.Event, error) {
	m.mu.Lock()
	if m.einoSession.ID != "" {
		sessionID := m.einoSession.ID
		m.mu.Unlock()
		events := []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, sessionID, "runtime already started", nil)}
		m.emit(events)
		return events, nil
	}
	if m.starting {
		m.mu.Unlock()
		return nil, ErrTurnBusy
	}
	if m.deps.EinoRunner == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("Eino-only runtime requires an Eino runner")
	}
	if m.deps.Sessions == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("Eino-only runtime requires session storage")
	}
	m.starting = true
	deps := m.deps
	m.mu.Unlock()
	started := false
	defer func() {
		if started {
			return
		}
		m.mu.Lock()
		m.starting = false
		m.mu.Unlock()
	}()
	if err := deps.EinoRunner.Ready(ctx); err != nil {
		return nil, err
	}
	resumeID := strings.TrimSpace(opts.ResumeID)
	var resumeAuthorization *protocol.AuthorizationContext
	if resumeID != "" && deps.Capabilities.IsPermissioned() && deps.AuthorizationContextProvider == nil {
		return nil, permissionedResumeError()
	}
	if resumeID != "" && deps.AuthorizationContextProvider != nil {
		authorization, err := m.authorizeSessionResume(ctx, resumeID)
		if err != nil {
			return nil, err
		}
		resumeAuthorization = &authorization
	}
	var loaded []protocol.Event
	if resumeID != "" {
		var err error
		loaded, err = deps.Sessions.Load(ctx, resumeID)
		if err != nil {
			if resumeAuthorization != nil {
				return nil, permissionedResumeError()
			}
			return nil, fmt.Errorf("resume failed: %w", err)
		}
		authorization := protocol.AuthorizationContext{}
		if resumeAuthorization != nil {
			authorization = *resumeAuthorization
		}
		loaded = m.filterPersistedEvents(ctx, authorization, loaded)
	}
	info := m.newEinoSession(ctx, resumeID)
	var binding *authorizationBinding
	if resumeAuthorization == nil {
		binding = nil
	} else {
		value := newAuthorizationBinding(*resumeAuthorization)
		binding = &value
	}
	startupEvents := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, info.ID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, info.ID, "session ready", info),
	}
	events := startupEvents
	if info.Resumed {
		events = append(append([]protocol.Event(nil), loaded...), startupEvents...)
	}
	m.commitMu.Lock()
	m.mu.Lock()
	if m.einoSession.ID != "" {
		m.starting = false
		m.mu.Unlock()
		m.commitMu.Unlock()
		return nil, ErrTurnBusy
	}
	m.generation++
	m.einoSession = info
	m.authorizationBinding = binding
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	m.persist(startupEvents)
	dispatch := m.enqueueNotifications(nil, subscribers, events)
	m.commitMu.Unlock()
	if dispatch {
		m.drainNotifications()
	}
	m.mu.Lock()
	m.starting = false
	m.mu.Unlock()
	started = true
	return events, nil
}

func (m *Manager) SendMessage(ctx context.Context, input string) ([]protocol.Event, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	command, argument := "", ""
	if strings.HasPrefix(input, "/") {
		command, argument = parseSlash(input)
	}
	rotation := command == "new" || (command == "resume" && strings.TrimSpace(argument) != "")
	title := "Message"
	if command != "" {
		title = "/" + command
	}
	turn, startedEvents, err := m.beginTurn(ctx, title, rotation)
	if err != nil {
		return nil, err
	}
	if err := turn.ctx.Err(); err != nil {
		completed, returnErr := m.finishTurn(turn, nil, err)
		return append(startedEvents, completed...), returnErr
	}
	m.mu.Lock()
	einoSession := m.einoSession
	einoRunner := m.deps.EinoRunner
	authorizationProvider := m.deps.AuthorizationContextProvider
	m.mu.Unlock()
	events := []protocol.Event{protocol.NewEvent(protocol.EventUserMessage, einoSession.ID, input, nil)}
	runCtx := turn.ctx
	if strings.HasPrefix(input, "/") && (!m.deps.Capabilities.AllowsSlashCommand(command) || command == "new") {
		result := m.handleSlash(runCtx, turn, einoSession.ID, input)
		completed, returnErr := m.finishTurnResult(turn, result.persisted, result.events, result.err)
		return append(startedEvents, completed...), returnErr
	}
	if authorizationProvider != nil {
		authorization, err := authorizationProvider.authorizationContext(runCtx, einoSession.ID)
		if err != nil {
			events = append(events, protocol.NewEvent(protocol.EventError, einoSession.ID, m.authorizationFailureMessage(err), nil))
			completed, returnErr := m.finishTurnResult(turn, nil, events, err)
			return append(startedEvents, completed...), returnErr
		}
		runCtx, err = protocol.WithAuthorizationContext(runCtx, authorization)
		if err != nil {
			events = append(events, protocol.NewEvent(protocol.EventError, einoSession.ID, m.authorizationFailureMessage(err), nil))
			completed, returnErr := m.finishTurnResult(turn, nil, events, err)
			return append(startedEvents, completed...), returnErr
		}
		if err := m.bindSessionAuthorization(runCtx, einoSession.ID, authorization); err != nil {
			events = append(events, protocol.NewEvent(protocol.EventError, einoSession.ID, m.authorizationFailureMessage(err), nil))
			completed, returnErr := m.finishTurnResult(turn, nil, events, err)
			return append(startedEvents, completed...), returnErr
		}
	}
	if strings.HasPrefix(input, "/") {
		result := m.handleSlash(runCtx, turn, einoSession.ID, input)
		completed, returnErr := m.finishTurnResult(turn, result.persisted, result.events, result.err)
		return append(startedEvents, completed...), returnErr
	}
	history := m.loadHistory(runCtx, einoSession.ID)
	if m.deps.SideEffects != nil {
		runCtx = withSideEffectSession(runCtx, einoSession.ID)
	}
	runnerEvents, err := einoRunner.Run(runCtx, EinoRunInput{SessionID: einoSession.ID, Message: input, History: history})
	events = append(events, runnerEvents...)
	if m.deps.SideEffects != nil {
		events = append(events, m.deps.SideEffects.PendingEvents(einoSession.ID)...)
	}
	if err != nil {
		if errors.Is(err, ErrSideEffectPending) {
			completed, returnErr := m.finishTurn(turn, events, nil)
			return append(startedEvents, completed...), returnErr
		}
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			events = append(events, protocol.NewEvent(protocol.EventError, einoSession.ID, err.Error(), nil))
		}
		completed, returnErr := m.finishTurn(turn, events, err)
		return append(startedEvents, completed...), returnErr
	}
	completed, returnErr := m.finishTurn(turn, events, nil)
	return append(startedEvents, completed...), returnErr
}

func (m *Manager) authorizationFailureMessage(err error) string {
	if m.deps.Capabilities.IsPermissioned() {
		return sessionAuthorizationErrorMessage
	}
	return err.Error()
}

func (m *Manager) Confirm(ctx context.Context, req protocol.ConfirmRequest, approved bool) ([]protocol.Event, error) {
	turn, startedEvents, err := m.beginTurn(ctx, "Confirmation", false)
	if err != nil {
		return nil, err
	}
	if err := turn.ctx.Err(); err != nil {
		completed, returnErr := m.finishTurn(turn, nil, err)
		return append(startedEvents, completed...), returnErr
	}
	m.mu.Lock()
	einoSessionID := m.einoSession.ID
	authorizationProvider := m.deps.AuthorizationContextProvider
	permissionedCapabilities := m.deps.Capabilities.IsPermissioned()
	m.mu.Unlock()
	if einoSessionID == "" {
		completed, returnErr := m.finishTurn(turn, m.runtimeError("runtime has not started"), fmt.Errorf("runtime has not started"))
		return append(startedEvents, completed...), returnErr
	}
	if m.deps.SideEffects != nil {
		confirmCtx := turn.ctx
		if approved && authorizationProvider != nil {
			authorization, err := authorizationProvider.authorizationContext(confirmCtx, einoSessionID)
			if err != nil {
				events := m.confirmBeforeConsumptionError(einoSessionID, req, err)
				completed, returnErr := m.finishTurn(turn, events, err)
				return append(startedEvents, completed...), returnErr
			}
			confirmCtx, err = protocol.WithAuthorizationContext(confirmCtx, authorization)
			if err != nil {
				events := m.confirmBeforeConsumptionError(einoSessionID, req, err)
				completed, returnErr := m.finishTurn(turn, events, err)
				return append(startedEvents, completed...), returnErr
			}
			if err := m.bindSessionAuthorization(confirmCtx, einoSessionID, authorization); err != nil {
				events := m.confirmBeforeConsumptionError(einoSessionID, req, err)
				completed, returnErr := m.finishTurn(turn, events, err)
				return append(startedEvents, completed...), returnErr
			}
			confirmCtx, err = m.withSessionAuthorizationExpectation(confirmCtx, einoSessionID, authorization)
			if err != nil {
				events := m.confirmBeforeConsumptionError(einoSessionID, req, err)
				completed, returnErr := m.finishTurn(turn, events, err)
				return append(startedEvents, completed...), returnErr
			}
		} else if approved && permissionedCapabilities {
			var err error
			confirmCtx, err = m.permissionedToolContext(confirmCtx, einoSessionID)
			if err != nil {
				events := m.confirmBeforeConsumptionError(einoSessionID, req, err)
				completed, returnErr := m.finishTurn(turn, events, err)
				return append(startedEvents, completed...), returnErr
			}
		}
		events := m.deps.SideEffects.Confirm(confirmCtx, einoSessionID, req, approved)
		completed, returnErr := m.finishTurn(turn, events, nil)
		return append(startedEvents, completed...), returnErr
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventError, einoSessionID, "confirm is not available without a side-effect bridge", nil)}
	completed, returnErr := m.finishTurn(turn, events, fmt.Errorf("side-effect bridge is not configured"))
	return append(startedEvents, completed...), returnErr
}

func (m *Manager) confirmBeforeConsumptionError(sessionID string, req protocol.ConfirmRequest, err error) []protocol.Event {
	message := err.Error()
	if m.deps.Capabilities.IsPermissioned() {
		message = sessionAuthorizationErrorMessage
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, message, nil)}
	events = append(events, m.deps.SideEffects.retryEvents(sessionID, req)...)
	return events
}

func (m *Manager) Interrupt(context.Context) ([]protocol.Event, error) {
	m.mu.Lock()
	einoSessionID := m.einoSession.ID
	turn := m.activeTurn
	m.mu.Unlock()
	if einoSessionID == "" {
		return m.emitAndReturn(m.runtimeError("runtime has not started")), nil
	}
	if turn == nil {
		return m.persistEmitAndReturn([]protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, einoSessionID, "no active task", nil)}), nil
	}
	turn.cancel()
	events := []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, einoSessionID, "interrupt requested", map[string]string{"task_id": turn.id})}
	return m.persistEmitAndReturn(events), nil
}

func (m *Manager) StopTask(_ context.Context, taskID string) ([]protocol.Event, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("task id is required")
	}
	m.mu.Lock()
	einoSessionID := m.einoSession.ID
	turn := m.activeTurn
	m.mu.Unlock()
	if einoSessionID == "" {
		return nil, fmt.Errorf("runtime has not started")
	}
	if turn == nil || turn.id != taskID {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, taskID)
	}
	turn.cancel()
	events := []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, einoSessionID, "task stop requested", map[string]string{"task_id": taskID})}
	return m.persistEmitAndReturn(events), nil
}

func (m *Manager) WorkspaceStatus(ctx context.Context) (repository.Status, error) {
	if m.deps.Capabilities.IsPermissioned() {
		return repository.Status{}, nil
	}
	if m.deps.Versions == nil {
		return repository.Status{}, fmt.Errorf("runtime versions repository is not configured")
	}
	return m.deps.Versions.Status(ctx)
}

func (m *Manager) RunnerInfo(ctx context.Context) (RunnerInfo, error) {
	m.mu.Lock()
	einoRunner := m.deps.EinoRunner
	m.mu.Unlock()

	info := RunnerInfo{
		ConfiguredMode: RunnerModeEino,
		ActiveMode:     RunnerModeEino,
		EinoAvailable:  einoRunner != nil,
	}
	if m.deps.Capabilities.IsPermissioned() {
		return info, nil
	}
	if einoRunner == nil {
		return info, nil
	}
	tools, err := einoRunner.ToolInventory(ctx)
	if err != nil {
		return RunnerInfo{}, err
	}
	info.Tools = tools
	return info, nil
}

func (m *Manager) newEinoSession(ctx context.Context, resumeID string) protocol.SessionInfo {
	sessionID := strings.TrimSpace(resumeID)
	resumed := true
	if sessionID == "" {
		if m.deps.NewSessionID != nil {
			sessionID = m.deps.NewSessionID()
		} else {
			sessionID = "sess_" + time.Now().UTC().Format("20060102T150405.000000000")
		}
		resumed = false
	}
	info := protocol.SessionInfo{
		ID:        sessionID,
		CreatedAt: time.Now().UTC(),
		Resumed:   resumed,
	}
	if m.deps.Capabilities.IsPermissioned() {
		return info
	}
	status := repository.Status{}
	if m.deps.Versions != nil {
		status, _ = m.deps.Versions.Status(ctx)
	}
	kagMode := ""
	if m.deps.Knowledge != nil {
		kagMode = string(m.deps.Knowledge.Mode())
	}
	info.Workspace = m.deps.Workspace
	info.Branch = status.Branch
	info.Dirty = status.Dirty
	info.KAGMode = kagMode
	return info
}

func (m *Manager) Subscribe(fn EventSubscriber) func() {
	if fn == nil {
		return func() {}
	}
	m.mu.Lock()
	id := m.nextSubID
	m.nextSubID++
	m.subscribers[id] = fn
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		delete(m.subscribers, id)
		m.mu.Unlock()
	}
}

func (m *Manager) SessionID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.einoSession.ID != "" {
		return m.einoSession.ID
	}
	return ""
}

func (m *Manager) Workspace() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deps.Capabilities.IsPermissioned() {
		return ""
	}
	return m.deps.Workspace
}

func (m *Manager) CurrentSessionInfo(ctx context.Context) protocol.SessionInfo {
	m.mu.Lock()
	einoSession := m.einoSession
	m.mu.Unlock()
	if einoSession.ID != "" {
		if m.deps.Capabilities.IsPermissioned() {
			return permissionedSessionInfo(einoSession)
		}
		return m.refreshEinoSessionInfo(ctx, einoSession)
	}
	if m.deps.Capabilities.IsPermissioned() {
		return protocol.SessionInfo{}
	}
	return protocol.SessionInfo{Workspace: m.deps.Workspace}
}

func (m *Manager) refreshEinoSessionInfo(ctx context.Context, info protocol.SessionInfo) protocol.SessionInfo {
	if m.deps.Capabilities.IsPermissioned() {
		return permissionedSessionInfo(info)
	}
	if m.deps.Versions == nil {
		return info
	}
	status, err := m.deps.Versions.Status(ctx)
	if err != nil {
		return info
	}
	info.Branch = status.Branch
	info.Dirty = status.Dirty
	return info
}

func permissionedSessionInfo(info protocol.SessionInfo) protocol.SessionInfo {
	return protocol.SessionInfo{
		ID:        info.ID,
		CreatedAt: info.CreatedAt,
		Resumed:   info.Resumed,
	}
}

func (m *Manager) persistEmitAndReturn(events []protocol.Event) []protocol.Event {
	m.commitMu.Lock()
	m.mu.Lock()
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	m.persist(events)
	dispatch := m.enqueueNotifications(nil, subscribers, events)
	m.commitMu.Unlock()
	if dispatch {
		m.drainNotifications()
	}
	return events
}

func (m *Manager) persist(events []protocol.Event) {
	if m.deps.Sessions == nil {
		return
	}
	for _, event := range events {
		_ = m.deps.Sessions.Append(context.Background(), event)
	}
}

func (m *Manager) loadHistory(ctx context.Context, sessionID string) []protocol.Event {
	if m.deps.Sessions == nil || sessionID == "" {
		return nil
	}
	events, err := m.deps.Sessions.Load(ctx, sessionID)
	if err != nil {
		return nil
	}
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok || authorization.SessionID != sessionID {
		authorization = protocol.AuthorizationContext{}
	}
	events = m.filterPersistedEvents(ctx, authorization, events)
	filtered := events[:0]
	for _, event := range events {
		switch event.Type {
		case protocol.EventTaskStarted, protocol.EventTaskProgress, protocol.EventTaskComplete:
			continue
		default:
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func (m *Manager) emitAndReturn(events []protocol.Event) []protocol.Event {
	m.emit(events)
	return events
}

func (m *Manager) emit(events []protocol.Event) {
	if len(events) == 0 {
		return
	}
	m.mu.Lock()
	subscribers := m.subscribersLocked()
	m.mu.Unlock()
	m.publishNotifications(nil, subscribers, events)
}

func (m *Manager) runtimeError(message string) []protocol.Event {
	return []protocol.Event{protocol.NewEvent(protocol.EventError, m.SessionID(), message, nil)}
}

func (m *Manager) currentStatus(message string) []protocol.Event {
	return []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, m.SessionID(), message, nil)}
}
