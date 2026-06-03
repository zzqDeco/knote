package runtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/zzqDeco/knote/internal/agent"
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
	NewSessionID  func() string
}

type StartOptions struct {
	ResumeID string
}

type RunnerMode string

const (
	RunnerModeDirect RunnerMode = "direct"
	RunnerModeEino   RunnerMode = "eino"
)

type EinoRunner interface {
	ToolInventory(ctx context.Context) ([]RunnerToolInfo, error)
	Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error)
}

type EinoRunInput struct {
	SessionID string
	Message   string
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

type EventSubscriber func([]protocol.Event)

type Manager struct {
	mu          sync.Mutex
	deps        Dependencies
	agent       *agent.Agent
	subscribers map[int]EventSubscriber
	nextSubID   int
}

var _ Runtime = (*Manager)(nil)

func New(deps Dependencies) *Manager {
	if deps.RunnerMode == "" {
		deps.RunnerMode = RunnerModeDirect
	}
	return &Manager{
		deps:        deps,
		subscribers: map[int]EventSubscriber{},
	}
}

func (m *Manager) Start(ctx context.Context, opts StartOptions) ([]protocol.Event, error) {
	m.mu.Lock()
	if m.agent != nil {
		sessionID := m.agent.SessionID()
		m.mu.Unlock()
		events := []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, sessionID, "runtime already started", nil)}
		m.emit(events)
		return events, nil
	}
	if m.deps.RunnerMode == RunnerModeEino {
		m.mu.Unlock()
		if m.deps.EinoRunner == nil {
			return nil, fmt.Errorf("eino runner mode requires an Eino runner")
		}
		return nil, fmt.Errorf("eino runner mode is scaffolded but not enabled for production turns")
	}
	deps := agent.Dependencies{
		Workspace:     m.deps.Workspace,
		ResumeID:      opts.ResumeID,
		Config:        m.deps.Config,
		SettingsYAML:  m.deps.SettingsYAML,
		Sessions:      m.deps.Sessions,
		Versions:      m.deps.Versions,
		WorkspaceRepo: m.deps.WorkspaceRepo,
		Knowledge:     m.deps.Knowledge,
		NewSessionID:  m.deps.NewSessionID,
	}
	runner, events, err := agent.New(ctx, deps)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.agent = runner
	m.mu.Unlock()
	m.emit(events)
	return events, nil
}

func (m *Manager) SendMessage(ctx context.Context, input string) []protocol.Event {
	m.mu.Lock()
	runner := m.agent
	m.mu.Unlock()
	if runner == nil {
		return m.emitAndReturn(m.runtimeError("runtime has not started"))
	}
	return m.emitAndReturn(runner.Handle(ctx, input))
}

func (m *Manager) Confirm(ctx context.Context, req protocol.ConfirmRequest, approved bool) []protocol.Event {
	m.mu.Lock()
	runner := m.agent
	m.mu.Unlock()
	if runner == nil {
		return m.emitAndReturn(m.runtimeError("runtime has not started"))
	}
	return m.emitAndReturn(runner.Confirm(ctx, req, approved))
}

func (m *Manager) Interrupt(context.Context) []protocol.Event {
	return m.emitAndReturn(m.currentStatus("interrupt requested; direct runner has no active streaming turn"))
}

func (m *Manager) StopTask(_ context.Context, taskID string) []protocol.Event {
	if taskID == "" {
		return m.emitAndReturn(m.runtimeError("task id is required"))
	}
	return m.emitAndReturn(m.currentStatus(fmt.Sprintf("task stop requested for %s; direct runner has no background task controller", taskID)))
}

func (m *Manager) WorkspaceStatus(ctx context.Context) (repository.Status, error) {
	if m.deps.Versions == nil {
		return repository.Status{}, fmt.Errorf("runtime versions repository is not configured")
	}
	return m.deps.Versions.Status(ctx)
}

func (m *Manager) RunnerInfo(ctx context.Context) (RunnerInfo, error) {
	m.mu.Lock()
	configured := m.deps.RunnerMode
	active := RunnerModeDirect
	einoRunner := m.deps.EinoRunner
	if m.agent == nil && configured == RunnerModeEino {
		active = RunnerModeEino
	}
	m.mu.Unlock()

	info := RunnerInfo{
		ConfiguredMode: configured,
		ActiveMode:     active,
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
	if m.agent == nil {
		return ""
	}
	return m.agent.SessionID()
}

func (m *Manager) Workspace() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agent == nil {
		return m.deps.Workspace
	}
	return m.agent.Workspace()
}

func (m *Manager) CurrentSessionInfo(ctx context.Context) protocol.SessionInfo {
	m.mu.Lock()
	runner := m.agent
	m.mu.Unlock()
	if runner == nil {
		return protocol.SessionInfo{Workspace: m.deps.Workspace}
	}
	return runner.CurrentSessionInfo(ctx)
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
