package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

type overlayMode string

const (
	overlayNone     overlayMode = ""
	overlayConfirm  overlayMode = "confirm"
	overlayTasks    overlayMode = "tasks"
	overlayVersions overlayMode = "versions"
	overlayDiff     overlayMode = "diff"
	overlayDetails  overlayMode = "details"
	overlaySettings overlayMode = "settings"
	overlayHelp     overlayMode = "help"
)

type Model struct {
	runtime         *runtime.Runtime
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
	ready           bool
	err             error
}

func New(rt *runtime.Runtime, initial []protocol.Event) Model {
	composer := textinput.New()
	composer.Placeholder = "Ask, /build, /diff, /versions, /tasks, /help"
	composer.Prompt = "> "
	composer.Focus()
	composer.CharLimit = 4096
	composer.Width = 80

	vp := viewport.New(80, 20)
	ov := viewport.New(80, 1)
	m := Model{
		runtime:         rt,
		viewport:        vp,
		overlayViewport: ov,
		composer:        composer,
		events:          initial,
		historyIndex:    0,
		status:          "session unknown · branch unknown · dirty unknown · tasks 0 · kag unknown",
		ready:           true,
	}
	m.historyIndex = len(m.history)
	m.status = m.deriveStatus()
	m.refreshOverlay()
	m.refreshViewport()
	return m
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resize()
		m.refreshOverlay()
		m.refreshViewport()
	case tea.KeyMsg:
		if m.pendingConfirm != nil {
			switch msg.String() {
			case "enter", "y", "Y":
				events := m.runtime.Confirm(context.Background(), *m.pendingConfirm, true)
				m.pendingConfirm = nil
				m.applyEvents(events)
				return m, nil
			case "esc", "n", "N":
				events := m.runtime.Confirm(context.Background(), *m.pendingConfirm, false)
				m.pendingConfirm = nil
				m.applyEvents(events)
				return m, nil
			default:
				return m, nil
			}
		}
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.overlayMode != overlayNone {
				m.overlayMode = overlayNone
				m.overlay = ""
				m.refreshOverlay()
				m.resize()
				m.refreshViewport()
				return m, nil
			}
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
			m.composer.SetValue("")
			m.pushHistory(value)
			events := m.runtime.Handle(context.Background(), value)
			m.applyEvents(events)
			m.refreshViewport()
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)
	m.composer, cmd = m.composer.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
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
	if hasClearEvent(events) {
		m.pendingConfirm = nil
		m.overlayMode = overlayNone
		m.overlay = ""
	}
	if req := confirmFromEvents(events); req != nil {
		m.pendingConfirm = req
	}
	if mode, overlay := overlayFromEvents(events); strings.TrimSpace(overlay) != "" {
		m.overlayMode = mode
		m.overlay = overlay
	} else if len(events) > 0 {
		m.overlayMode = overlayNone
		m.overlay = ""
	}
	m.status = m.deriveStatus()
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
	if m.runtime != nil {
		info := m.runtime.CurrentSessionInfo(context.Background())
		if info.Branch != "" {
			branch = info.Branch
		}
		dirty = fmt.Sprint(info.Dirty)
		if info.KAGMode != "" {
			kagMode = info.KAGMode
		}
	}
	return fmt.Sprintf("session %s · branch %s · dirty %s · tasks %d · kag %s", m.runtime.SessionID(), branch, dirty, activeTasks, kagMode)
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
				return overlayConfirm, fmt.Sprintf("%s\n\n%s\n\nCommand: %s\n\nEnter/y: %s · n/Esc: %s", req.Title, req.Summary, req.Command, req.ApproveText, req.RejectText)
			}
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return overlayConfirm, "confirm\n" + string(data)
		case protocol.EventApprovalRequest:
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return overlayConfirm, "approval\n" + string(data)
		case protocol.EventAssistantDone:
			switch eventOverlay(event.Payload) {
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

func visibleEvents(events []protocol.Event) []protocol.Event {
	cut := -1
	for i, event := range events {
		if event.Type == protocol.EventViewClear {
			cut = i
		}
	}
	if cut < 0 {
		return events
	}
	return events[cut+1:]
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
