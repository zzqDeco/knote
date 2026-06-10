package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

type Runtime interface {
	Start(ctx context.Context, opts StartOptions) ([]protocol.Event, error)
	SendMessage(ctx context.Context, input string) []protocol.Event
	Confirm(ctx context.Context, req protocol.ConfirmRequest, approved bool) []protocol.Event
	Interrupt(ctx context.Context) []protocol.Event
	StopTask(ctx context.Context, taskID string) []protocol.Event
	WorkspaceStatus(ctx context.Context) (repository.Status, error)
	RunnerInfo(ctx context.Context) (RunnerInfo, error)
	Subscribe(fn EventSubscriber) func()

	SessionID() string
	Workspace() string
	CurrentSessionInfo(ctx context.Context) protocol.SessionInfo
}

type Dependencies struct {
	Workspace     string
	Config        repository.Config
	SettingsYAML  string
	Sessions      repository.Sessions
	Versions      repository.Versions
	WorkspaceRepo repository.Workspace
	Knowledge     versioned.Service
	RunnerMode    RunnerMode
	EinoRunner    EinoRunner
	SideEffects   *SideEffectBridge
	ToolExecutor  ToolExecutor
	NewSessionID  func() string
}

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

type EventSubscriber func([]protocol.Event)

type Manager struct {
	mu          sync.Mutex
	deps        Dependencies
	einoSession protocol.SessionInfo
	subscribers map[int]EventSubscriber
	nextSubID   int
}

var _ Runtime = (*Manager)(nil)

func New(deps Dependencies) *Manager {
	deps.RunnerMode = RunnerModeEino
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
	if m.deps.EinoRunner == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("Eino-only runtime requires an Eino runner")
	}
	if m.deps.Sessions == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("Eino-only runtime requires session storage")
	}
	if err := m.deps.EinoRunner.Ready(ctx); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	info, loaded := m.newEinoSessionLocked(ctx, opts.ResumeID)
	m.einoSession = info
	m.mu.Unlock()
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, info.ID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, info.ID, "session ready", info),
	}
	m.persist(events)
	if info.Resumed {
		events = append(loaded, events...)
	}
	m.emit(events)
	return events, nil
}

func (m *Manager) SendMessage(ctx context.Context, input string) []protocol.Event {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	m.mu.Lock()
	einoSession := m.einoSession
	einoRunner := m.deps.EinoRunner
	m.mu.Unlock()
	if einoSession.ID == "" {
		return m.emitAndReturn(m.runtimeError("runtime has not started"))
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventUserMessage, einoSession.ID, input, nil)}
	if strings.HasPrefix(input, "/") {
		return m.handleSlash(ctx, einoSession.ID, input)
	}
	history := m.loadHistory(ctx, einoSession.ID)
	runCtx := ctx
	if m.deps.SideEffects != nil {
		runCtx = withSideEffectSession(ctx, einoSession.ID)
	}
	runnerEvents, err := einoRunner.Run(runCtx, EinoRunInput{SessionID: einoSession.ID, Message: input, History: history})
	events = append(events, runnerEvents...)
	if m.deps.SideEffects != nil {
		events = append(events, m.deps.SideEffects.PendingEvents(einoSession.ID)...)
	}
	if err != nil {
		if errors.Is(err, ErrSideEffectPending) {
			return m.persistEmitAndReturn(events)
		}
		events = append(events, protocol.NewEvent(protocol.EventError, einoSession.ID, err.Error(), nil))
		return m.persistEmitAndReturn(events)
	}
	return m.persistEmitAndReturn(events)
}

func (m *Manager) Confirm(ctx context.Context, req protocol.ConfirmRequest, approved bool) []protocol.Event {
	m.mu.Lock()
	einoSessionID := m.einoSession.ID
	m.mu.Unlock()
	if einoSessionID == "" {
		return m.emitAndReturn(m.runtimeError("runtime has not started"))
	}
	if m.deps.SideEffects != nil {
		return m.persistEmitAndReturn(m.deps.SideEffects.Confirm(ctx, einoSessionID, req, approved))
	}
	return m.persistEmitAndReturn([]protocol.Event{protocol.NewEvent(protocol.EventError, einoSessionID, "confirm is not available without a side-effect bridge", nil)})
}

func (m *Manager) Interrupt(context.Context) []protocol.Event {
	m.mu.Lock()
	einoSessionID := m.einoSession.ID
	m.mu.Unlock()
	if einoSessionID != "" {
		return m.persistEmitAndReturn([]protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, einoSessionID, "interrupt requested; Eino runner has no active streaming controller yet", nil)})
	}
	return m.emitAndReturn(m.runtimeError("runtime has not started"))
}

func (m *Manager) StopTask(_ context.Context, taskID string) []protocol.Event {
	if taskID == "" {
		return m.emitAndReturn(m.runtimeError("task id is required"))
	}
	m.mu.Lock()
	einoSessionID := m.einoSession.ID
	m.mu.Unlock()
	if einoSessionID != "" {
		return m.persistEmitAndReturn([]protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, einoSessionID, fmt.Sprintf("task stop requested for %s; Eino runner has no background task controller yet", taskID), nil)})
	}
	return m.emitAndReturn(m.runtimeError("runtime has not started"))
}

func (m *Manager) WorkspaceStatus(ctx context.Context) (repository.Status, error) {
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

func (m *Manager) newEinoSessionLocked(ctx context.Context, resumeID string) (protocol.SessionInfo, []protocol.Event) {
	sessionID := strings.TrimSpace(resumeID)
	resumed := true
	var loaded []protocol.Event
	if sessionID == "" {
		if m.deps.NewSessionID != nil {
			sessionID = m.deps.NewSessionID()
		} else {
			sessionID = "sess_" + time.Now().UTC().Format("20060102T150405.000000000")
		}
		resumed = false
	} else if m.deps.Sessions != nil {
		loaded, _ = m.deps.Sessions.Load(ctx, sessionID)
	}
	status := repository.Status{}
	if m.deps.Versions != nil {
		status, _ = m.deps.Versions.Status(ctx)
	}
	kagMode := ""
	if m.deps.Knowledge != nil {
		kagMode = string(m.deps.Knowledge.Mode())
	}
	return protocol.SessionInfo{
		ID:        sessionID,
		Workspace: m.deps.Workspace,
		Branch:    status.Branch,
		Dirty:     status.Dirty,
		KAGMode:   kagMode,
		CreatedAt: time.Now().UTC(),
		Resumed:   resumed,
	}, loaded
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
	return m.deps.Workspace
}

func (m *Manager) CurrentSessionInfo(ctx context.Context) protocol.SessionInfo {
	m.mu.Lock()
	einoSession := m.einoSession
	m.mu.Unlock()
	if einoSession.ID != "" {
		return m.refreshEinoSessionInfo(ctx, einoSession)
	}
	return protocol.SessionInfo{Workspace: m.deps.Workspace}
}

func (m *Manager) refreshEinoSessionInfo(ctx context.Context, info protocol.SessionInfo) protocol.SessionInfo {
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

func (m *Manager) persistEmitAndReturn(events []protocol.Event) []protocol.Event {
	m.persist(events)
	m.emit(events)
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
	return events
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
	subscribers := make([]EventSubscriber, 0, len(m.subscribers))
	for _, fn := range m.subscribers {
		subscribers = append(subscribers, fn)
	}
	m.mu.Unlock()
	for _, fn := range subscribers {
		fn(append([]protocol.Event(nil), events...))
	}
}

func (m *Manager) runtimeError(message string) []protocol.Event {
	return []protocol.Event{protocol.NewEvent(protocol.EventError, m.SessionID(), message, nil)}
}

func (m *Manager) currentStatus(message string) []protocol.Event {
	return []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, m.SessionID(), message, nil)}
}
