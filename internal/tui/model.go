package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

type overlayMode string

const quitDrainTimeout = 2 * time.Second

const (
	overlayNone       overlayMode = ""
	overlayConfirm    overlayMode = "confirm"
	overlayTasks      overlayMode = "tasks"
	overlayVersions   overlayMode = "versions"
	overlayDiff       overlayMode = "diff"
	overlayDetails    overlayMode = "details"
	overlaySettings   overlayMode = "settings"
	overlayGovernance overlayMode = "governance"
	overlayHelp       overlayMode = "help"
)

type Model struct {
	runtime         runtime.Runtime
	viewport        viewport.Model
	overlayViewport viewport.Model
	composer        textinput.Model
	events          []protocol.Event
	history         []string
	historyIndex    int
	historyDraft    string
	width           int
	height          int
	status          string
	overlay         string
	overlayMode     overlayMode
	pendingConfirm  *protocol.ConfirmRequest
	runtimeEvents   *runtimeEventBridge
	unsubscribe     func()
	nextCommandID   uint64
	latestRotation  uint64
	latestResult    uint64
	statusInfo      protocol.SessionInfo
	nextStatusID    uint64
	appliedStatusID uint64
	quitPending     bool
	interruptDone   bool
	quitTaskIDs     map[string]struct{}
	ready           bool
	err             error
}

type runtimeResultMsg struct {
	commandID uint64
	kind      runtimeCommandKind
	input     string
	confirm   *protocol.ConfirmRequest
	err       error
}

type interruptResultMsg struct {
	quit     bool
	timedOut bool
	taskIDs  []string
	err      error
}

type quitDrainTimeoutMsg struct{}

type statusRefreshMsg struct {
	requestID uint64
	sessionID string
	info      protocol.SessionInfo
}

type runtimeCommandKind string

const (
	runtimeCommandSend    runtimeCommandKind = "send"
	runtimeCommandConfirm runtimeCommandKind = "confirm"
)

func New(rt runtime.Runtime, initial []protocol.Event) Model {
	composer := textinput.New()
	composer.Placeholder = "Ask, /build, /governance, /tasks, /help"
	composer.Prompt = "> "
	composer.Focus()
	composer.CharLimit = 4096
	composer.Width = 80

	vp := viewport.New(80, 20)
	ov := viewport.New(80, 1)
	m := Model{
		viewport:        vp,
		overlayViewport: ov,
		composer:        composer,
		events:          initial,
		historyIndex:    0,
		status:          "session unknown · branch unknown · dirty unknown · tasks 0 · kag unknown",
		nextStatusID:    1,
		ready:           true,
	}
	m.setRuntime(rt)
	m.historyIndex = len(m.history)
	m.status = m.deriveStatus()
	m.refreshOverlay()
	m.refreshViewport()
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.runtimeEvents.waitCmd(),
		statusRefreshCmd(m.runtime, m.nextStatusID, m.runtime.SessionID()),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case runtimeResultMsg:
		m.applyRuntimeResult(msg)
		return m, m.nextStatusRefreshCmd()
	case interruptResultMsg:
		m.err = msg.err
		if !msg.quit {
			return m, nil
		}
		m.interruptDone = true
		m.trackInterruptedTasks(msg.taskIDs)
		if msg.timedOut || m.shouldQuit() {
			return m, tea.Quit
		}
		return m, quitDrainTimeoutCmd()
	case quitDrainTimeoutMsg:
		if m.quitPending {
			return m, tea.Quit
		}
		return m, nil
	case statusRefreshMsg:
		if msg.requestID < m.appliedStatusID || msg.sessionID != m.runtime.SessionID() {
			return m, nil
		}
		if msg.info.ID != "" && msg.info.ID != msg.sessionID {
			return m, nil
		}
		m.appliedStatusID = msg.requestID
		m.statusInfo = msg.info
		m.status = m.deriveStatus()
		return m, nil
	case runtimeEventsMsg:
		m.applyEvents(msg.events)
		m.observeQuitTerminals(msg.events)
		if m.shouldQuit() {
			return m, tea.Quit
		}
		if needsStatusRefresh(msg.events) {
			return m, tea.Batch(m.runtimeEvents.waitCmd(), m.nextStatusRefreshCmd())
		}
		return m, m.runtimeEvents.waitCmd()
	case runtimeBridgeClosedMsg:
		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resize()
		m.refreshOverlay()
		m.refreshViewport()
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.beginQuit()
			return m, interruptCmd(m.runtime, true)
		}
		if m.pendingConfirm != nil {
			switch msg.String() {
			case "enter", "y", "Y":
				req := *m.pendingConfirm
				m.pendingConfirm = nil
				m.closeOverlay()
				return m, confirmCmd(m.runtime, m.nextRuntimeCommand(false), req, true)
			case "esc", "n", "N":
				req := *m.pendingConfirm
				m.pendingConfirm = nil
				m.closeOverlay()
				return m, confirmCmd(m.runtime, m.nextRuntimeCommand(false), req, false)
			default:
				return m, nil
			}
		}
		switch msg.String() {
		case "esc":
			if m.overlayMode != overlayNone {
				m.overlayMode = overlayNone
				m.overlay = ""
				m.refreshOverlay()
				m.resize()
				m.refreshViewport()
				return m, nil
			}
			return m, interruptCmd(m.runtime, false)
		case "pgup", "pgdown", "ctrl+u", "ctrl+d":
			if m.overlayMode != overlayNone {
				var cmd tea.Cmd
				m.overlayViewport, cmd = m.overlayViewport.Update(msg)
				return m, cmd
			}
		case "up":
			if m.overlayMode != overlayNone {
				var cmd tea.Cmd
				m.overlayViewport, cmd = m.overlayViewport.Update(msg)
				return m, cmd
			}
			if m.previousHistory() {
				return m, nil
			}
		case "down":
			if m.overlayMode != overlayNone {
				var cmd tea.Cmd
				m.overlayViewport, cmd = m.overlayViewport.Update(msg)
				return m, cmd
			}
			if m.nextHistory() {
				return m, nil
			}
		case "enter":
			value := strings.TrimSpace(m.composer.Value())
			if value == "" {
				break
			}
			if m.overlayMode != overlayNone {
				m.closeOverlay()
			}
			m.composer.SetValue("")
			m.pushHistory(value)
			rotation := isSessionRotationCommand(value)
			return m, sendMessageCmd(m.runtime, m.nextRuntimeCommand(rotation), value)
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)
	m.composer, cmd = m.composer.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func interruptCmd(rt runtime.Runtime, quit bool) tea.Cmd {
	return func() tea.Msg {
		if !quit {
			events, err := rt.Interrupt(context.Background())
			return interruptResultMsg{taskIDs: interruptTaskIDs(events), err: err}
		}
		result := make(chan interruptResultMsg, 1)
		go func() {
			events, err := rt.Interrupt(context.Background())
			result <- interruptResultMsg{quit: true, taskIDs: interruptTaskIDs(events), err: err}
		}()
		select {
		case msg := <-result:
			return msg
		case <-time.After(quitDrainTimeout):
			return interruptResultMsg{quit: true, timedOut: true, err: context.DeadlineExceeded}
		}
	}
}

func quitDrainTimeoutCmd() tea.Cmd {
	return func() tea.Msg {
		time.Sleep(quitDrainTimeout)
		return quitDrainTimeoutMsg{}
	}
}

func statusRefreshCmd(rt runtime.Runtime, requestID uint64, sessionID string) tea.Cmd {
	return func() tea.Msg {
		return statusRefreshMsg{
			requestID: requestID,
			sessionID: sessionID,
			info:      rt.CurrentSessionInfo(context.Background()),
		}
	}
}

func sendMessageCmd(rt runtime.Runtime, commandID uint64, input string) tea.Cmd {
	return func() tea.Msg {
		_, err := rt.SendMessage(context.Background(), input)
		return runtimeResultMsg{commandID: commandID, kind: runtimeCommandSend, input: input, err: err}
	}
}

func confirmCmd(rt runtime.Runtime, commandID uint64, req protocol.ConfirmRequest, approved bool) tea.Cmd {
	return func() tea.Msg {
		_, err := rt.Confirm(context.Background(), req, approved)
		return runtimeResultMsg{commandID: commandID, kind: runtimeCommandConfirm, confirm: &req, err: err}
	}
}

func (m *Model) setRuntime(rt runtime.Runtime) {
	if m.unsubscribe != nil {
		m.unsubscribe()
	}
	m.runtime = rt
	m.runtimeEvents, m.unsubscribe = subscribeRuntimeEvents(rt)
}

func (m *Model) nextRuntimeCommand(rotation bool) uint64 {
	m.nextCommandID++
	if rotation {
		m.latestRotation = m.nextCommandID
	}
	return m.nextCommandID
}

func (m *Model) nextStatusRefreshCmd() tea.Cmd {
	m.nextStatusID++
	return statusRefreshCmd(m.runtime, m.nextStatusID, m.runtime.SessionID())
}

func needsStatusRefresh(events []protocol.Event) bool {
	for _, event := range events {
		switch event.Type {
		case protocol.EventGatewayReady, protocol.EventSessionInfo, protocol.EventVersionChanged,
			protocol.EventBuildComplete, protocol.EventToolComplete:
			return true
		}
	}
	return false
}

func isSessionRotationCommand(input string) bool {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return false
	}
	return fields[0] == "/new" || (fields[0] == "/resume" && len(fields) > 1)
}

func (m *Model) beginQuit() {
	m.quitPending = true
	m.interruptDone = false
	m.quitTaskIDs = map[string]struct{}{}
	for taskID, status := range currentTaskStatuses(m.events) {
		if status == protocol.TaskPending || status == protocol.TaskRunning {
			m.quitTaskIDs[taskID] = struct{}{}
		}
	}
}

func (m *Model) trackInterruptedTasks(taskIDs []string) {
	if m.quitTaskIDs == nil {
		m.quitTaskIDs = map[string]struct{}{}
	}
	statuses := currentTaskStatuses(m.events)
	for _, taskID := range taskIDs {
		status, known := statuses[taskID]
		if known && status != protocol.TaskPending && status != protocol.TaskRunning {
			continue
		}
		m.quitTaskIDs[taskID] = struct{}{}
	}
}

func (m *Model) observeQuitTerminals(events []protocol.Event) {
	if !m.quitPending {
		return
	}
	for _, event := range events {
		if event.Type != protocol.EventTaskComplete {
			continue
		}
		for _, task := range tasksFromEvent(event) {
			delete(m.quitTaskIDs, task.ID)
		}
	}
}

func (m Model) shouldQuit() bool {
	return m.quitPending && m.interruptDone && len(m.quitTaskIDs) == 0
}

func interruptTaskIDs(events []protocol.Event) []string {
	seen := map[string]struct{}{}
	var taskIDs []string
	for _, event := range events {
		if event.Type != protocol.EventStatusUpdate {
			continue
		}
		data, err := json.Marshal(event.Payload)
		if err != nil {
			continue
		}
		var payload struct {
			TaskID string `json:"task_id"`
		}
		if json.Unmarshal(data, &payload) != nil || strings.TrimSpace(payload.TaskID) == "" {
			continue
		}
		if _, ok := seen[payload.TaskID]; ok {
			continue
		}
		seen[payload.TaskID] = struct{}{}
		taskIDs = append(taskIDs, payload.TaskID)
	}
	return taskIDs
}

func currentTaskStatuses(events []protocol.Event) map[string]protocol.TaskStatus {
	statuses := map[string]protocol.TaskStatus{}
	for _, event := range events {
		for _, task := range tasksFromEvent(event) {
			statuses[task.ID] = task.Status
		}
	}
	return statuses
}

func (m *Model) closeOverlay() {
	m.overlayMode = overlayNone
	m.overlay = ""
	m.refreshOverlay()
	m.resize()
	m.refreshViewport()
}

func (m Model) View() string {
	if !m.ready {
		return "starting knote..."
	}
	width := max(80, m.width)
	transcript := transcriptStyle.Width(width - 2).Height(max(5, m.viewport.Height)).Render(m.viewport.View())
	prompt := promptStyle.Width(width - 2).Height(m.overlayHeight()).Render(m.overlayView())
	composer := composerStyle.Width(width - 2).Render(m.composer.View())
	status := statusStyle.Width(width - 2).Render(m.status)
	return lipgloss.JoinVertical(lipgloss.Left, transcript, prompt, composer, status)
}

func (m *Model) resize() {
	m.composer.Width = max(20, m.width-4)
	m.viewport.Width = max(20, m.width)
	m.overlayViewport.Width = max(20, m.width-4)
	m.overlayViewport.Height = m.overlayHeight()
	m.viewport.Height = max(5, m.height-m.overlayHeight()-5)
}

func (m Model) overlayHeight() int {
	if m.overlayMode == overlayNone {
		return 1
	}
	if m.height <= 0 {
		return 8
	}
	return min(12, max(3, m.height/3))
}

func (m *Model) refreshViewport() {
	m.viewport.SetContent(renderTranscript(m.events))
	m.viewport.GotoBottom()
}

func (m *Model) refreshOverlay() {
	m.overlayViewport.Width = max(20, m.width-4)
	m.overlayViewport.Height = m.overlayHeight()
	m.overlayViewport.SetContent(m.overlay)
	m.overlayViewport.GotoTop()
}

func (m *Model) applyEvents(events []protocol.Event) {
	m.events = append(m.events, events...)
	cleared := hasClearEvent(events)
	if cleared {
		m.pendingConfirm = nil
		m.overlayMode = overlayNone
		m.overlay = ""
	} else {
		if req := confirmFromEvents(events); req != nil {
			m.pendingConfirm = req
		}
		if m.pendingConfirm != nil {
			m.overlayMode = overlayConfirm
			m.overlay = renderConfirmation(*m.pendingConfirm)
		} else if mode, overlay := overlayFromEvents(events); strings.TrimSpace(overlay) != "" {
			m.overlayMode = mode
			m.overlay = overlay
		} else if closesOverlay(events) {
			m.overlayMode = overlayNone
			m.overlay = ""
		}
	}
	m.status = m.deriveStatus()
	m.resize()
	m.refreshOverlay()
	m.refreshViewport()
}

func closesOverlay(events []protocol.Event) bool {
	for _, event := range events {
		switch event.Type {
		case protocol.EventAssistantDone, protocol.EventToolComplete, protocol.EventToolError,
			protocol.EventBuildComplete, protocol.EventError, protocol.EventViewClear:
			return true
		}
	}
	return false
}

func (m *Model) applyRuntimeResult(result runtimeResultMsg) {
	if result.commandID < m.latestRotation || result.commandID < m.latestResult {
		return
	}
	m.latestResult = result.commandID
	if result.err == nil {
		return
	}
	m.err = result.err
	if !errors.Is(result.err, runtime.ErrTurnBusy) &&
		!errors.Is(result.err, runtime.ErrTurnNotStarted) &&
		!errors.Is(result.err, runtime.ErrConfirmationNotExecuted) {
		return
	}
	switch result.kind {
	case runtimeCommandSend:
		if strings.TrimSpace(m.composer.Value()) == "" {
			m.setComposerValue(result.input)
		}
	case runtimeCommandConfirm:
		if result.confirm != nil && m.pendingConfirm == nil {
			m.restoreConfirmation(*result.confirm)
		}
	}
}

func (m *Model) restoreConfirmation(req protocol.ConfirmRequest) {
	m.pendingConfirm = &req
	m.overlayMode = overlayConfirm
	m.overlay = renderConfirmation(req)
	m.resize()
	m.refreshOverlay()
	m.refreshViewport()
}

func (m *Model) pushHistory(value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if len(m.history) == 0 || m.history[len(m.history)-1] != value {
		m.history = append(m.history, value)
	}
	m.historyIndex = len(m.history)
	m.historyDraft = ""
}

func (m *Model) previousHistory() bool {
	if len(m.history) == 0 {
		return false
	}
	if m.historyIndex >= len(m.history) {
		m.historyDraft = m.composer.Value()
		m.historyIndex = len(m.history) - 1
	} else if m.historyIndex > 0 {
		m.historyIndex--
	}
	m.setComposerValue(m.history[m.historyIndex])
	return true
}

func (m *Model) nextHistory() bool {
	if len(m.history) == 0 || m.historyIndex >= len(m.history) {
		return false
	}
	if m.historyIndex < len(m.history)-1 {
		m.historyIndex++
		m.setComposerValue(m.history[m.historyIndex])
		return true
	}
	m.historyIndex = len(m.history)
	m.setComposerValue(m.historyDraft)
	return true
}

func (m *Model) setComposerValue(value string) {
	m.composer.SetValue(value)
	m.composer.CursorEnd()
}

func (m Model) overlayView() string {
	if strings.TrimSpace(m.overlay) != "" {
		return m.overlayViewport.View()
	}
	return " "
}

func (m Model) deriveStatus() string {
	branch := "unknown"
	dirty := "unknown"
	kagMode := "unknown"
	tasks := map[string]protocol.TaskStatus{}
	for _, event := range m.events {
		if event.Type == protocol.EventSessionInfo {
			data, _ := json.Marshal(event.Payload)
			var info protocol.SessionInfo
			if err := json.Unmarshal(data, &info); err == nil {
				if info.Branch != "" {
					branch = info.Branch
				}
				dirty = fmt.Sprint(info.Dirty)
				if info.KAGMode != "" {
					kagMode = info.KAGMode
				}
			}
		}
		for _, task := range tasksFromEvent(event) {
			tasks[task.ID] = task.Status
		}
	}
	activeTasks := 0
	for _, status := range tasks {
		if status == protocol.TaskPending || status == protocol.TaskRunning {
			activeTasks++
		}
	}
	if m.statusInfo.ID == "" || m.runtime == nil || m.statusInfo.ID == m.runtime.SessionID() {
		if m.statusInfo.Branch != "" {
			branch = m.statusInfo.Branch
		}
		if m.statusInfo.ID != "" {
			dirty = fmt.Sprint(m.statusInfo.Dirty)
		}
		if m.statusInfo.KAGMode != "" {
			kagMode = m.statusInfo.KAGMode
		}
	}
	sessionID := ""
	if m.runtime != nil {
		sessionID = m.runtime.SessionID()
	}
	return fmt.Sprintf("session %s · branch %s · dirty %s · tasks %d · kag %s", sessionID, branch, dirty, activeTasks, kagMode)
}

func renderTranscript(events []protocol.Event) string {
	events = visibleEvents(events)
	if len(events) == 0 {
		return "knote ready"
	}
	var b strings.Builder
	for _, event := range events {
		switch event.Type {
		case protocol.EventUserMessage:
			fmt.Fprintf(&b, "user\n  %s\n\n", event.Message)
		case protocol.EventAssistantStart:
			fmt.Fprintf(&b, "assistant\n  %s\n\n", event.Message)
		case protocol.EventAssistantDone:
			fmt.Fprintf(&b, "assistant\n%s\n\n", indent(event.Message))
		case protocol.EventToolStart, protocol.EventToolProgress, protocol.EventToolComplete, protocol.EventToolError:
			fmt.Fprintf(&b, "tool %s\n  %s\n\n", event.Type, event.Message)
		case protocol.EventBuildStart, protocol.EventBuildProgress, protocol.EventBuildComplete:
			fmt.Fprintf(&b, "build\n  %s\n\n", event.Message)
		case protocol.EventVersionChanged, protocol.EventVersionDiff:
			fmt.Fprintf(&b, "version\n%s\n\n", indent(event.Message))
		case protocol.EventTaskStarted, protocol.EventTaskProgress, protocol.EventTaskComplete:
			fmt.Fprintf(&b, "task\n  %s\n\n", event.Message)
		case protocol.EventStatusUpdate:
			fmt.Fprintf(&b, "status\n%s\n\n", indent(event.Message))
		case protocol.EventViewClear:
			continue
		case protocol.EventError:
			fmt.Fprintf(&b, "error\n  %s\n\n", event.Message)
		default:
			if strings.TrimSpace(event.Message) != "" {
				fmt.Fprintf(&b, "%s\n  %s\n\n", event.Type, event.Message)
			}
		}
	}
	if strings.TrimSpace(b.String()) == "" {
		return "knote ready"
	}
	return b.String()
}

func overlayFromEvents(events []protocol.Event) (overlayMode, string) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		switch event.Type {
		case protocol.EventVersionDiff:
			return overlayDiff, "diff\n" + event.Message
		case protocol.EventVersionChanged:
			return overlayVersions, "versions\n" + event.Message
		case protocol.EventTaskProgress:
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return overlayTasks, "tasks\n" + string(data)
		case protocol.EventConfirmRequest:
			if req := confirmFromEvent(event); req != nil {
				return overlayConfirm, renderConfirmation(*req)
			}
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return overlayConfirm, "confirm\n" + string(data)
		case protocol.EventApprovalRequest:
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return overlayConfirm, "approval\n" + string(data)
		case protocol.EventAssistantDone:
			switch eventOverlay(event.Payload) {
			case "governance":
				return overlayGovernance, event.Message
			case "details":
				return overlayDetails, event.Message
			case "settings":
				return overlaySettings, event.Message
			case "help":
				return overlayHelp, event.Message
			}
		}
	}
	return overlayNone, ""
}

func renderConfirmation(req protocol.ConfirmRequest) string {
	return fmt.Sprintf("%s\n\n%s\n\nCommand: %s\n\nEnter/y: %s · n/Esc: %s", req.Title, req.Summary, req.Command, req.ApproveText, req.RejectText)
}

func visibleEvents(events []protocol.Event) []protocol.Event {
	cut := -1
	currentSessionID := ""
	for i, event := range events {
		if event.Type == protocol.EventViewClear {
			cut = i
		}
		if event.Type == protocol.EventSessionInfo && event.SessionID != "" {
			currentSessionID = event.SessionID
		}
	}
	if cut < 0 {
		return events
	}
	visible := make([]protocol.Event, 0, len(events)-cut-1)
	for _, event := range events[cut+1:] {
		if currentSessionID != "" && event.SessionID != "" && event.SessionID != currentSessionID {
			continue
		}
		if event.Type == protocol.EventTaskComplete {
			tasks := tasksFromEvent(event)
			if len(tasks) == 1 && tasks[0].Title == "/clear" {
				continue
			}
		}
		visible = append(visible, event)
	}
	return visible
}

func hasClearEvent(events []protocol.Event) bool {
	for _, event := range events {
		if event.Type == protocol.EventViewClear {
			return true
		}
	}
	return false
}

func eventOverlay(payload any) string {
	switch value := payload.(type) {
	case map[string]string:
		return value["overlay"]
	case map[string]any:
		if overlay, ok := value["overlay"].(string); ok {
			return overlay
		}
	default:
		data, err := json.Marshal(payload)
		if err != nil {
			return ""
		}
		var out map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			return ""
		}
		if overlay, ok := out["overlay"].(string); ok {
			return overlay
		}
	}
	return ""
}

func tasksFromEvent(event protocol.Event) []protocol.Task {
	switch event.Type {
	case protocol.EventTaskStarted, protocol.EventTaskProgress, protocol.EventTaskComplete:
	default:
		return nil
	}
	data, err := json.Marshal(event.Payload)
	if err != nil {
		return nil
	}
	var task protocol.Task
	if err := json.Unmarshal(data, &task); err == nil && task.ID != "" {
		return []protocol.Task{task}
	}
	var tasks []protocol.Task
	if err := json.Unmarshal(data, &tasks); err == nil {
		return tasks
	}
	return nil
}

func confirmFromEvents(events []protocol.Event) *protocol.ConfirmRequest {
	for i := len(events) - 1; i >= 0; i-- {
		if req := confirmFromEvent(events[i]); req != nil {
			return req
		}
		switch events[i].Type {
		case protocol.EventTaskStarted, protocol.EventTaskProgress, protocol.EventTaskComplete,
			protocol.EventGatewayReady, protocol.EventSessionInfo, protocol.EventStatusUpdate:
			continue
		case protocol.EventAssistantDone, protocol.EventToolComplete, protocol.EventToolError,
			protocol.EventBuildComplete, protocol.EventError, protocol.EventViewClear:
			return nil
		}
	}
	return nil
}

func confirmFromEvent(event protocol.Event) *protocol.ConfirmRequest {
	if event.Type != protocol.EventConfirmRequest {
		return nil
	}
	switch payload := event.Payload.(type) {
	case protocol.ConfirmRequest:
		return &payload
	case *protocol.ConfirmRequest:
		return payload
	default:
		data, err := json.Marshal(payload)
		if err != nil {
			return nil
		}
		var req protocol.ConfirmRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return nil
		}
		if req.RequestID == "" {
			return nil
		}
		return &req
	}
}

func indent(text string) string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		out = append(out, "  "+line)
	}
	return strings.Join(out, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var (
	transcriptStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			Padding(0, 1)
	promptStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			Padding(0, 1)
	composerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			Padding(0, 1)
	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Padding(0, 1)
)
