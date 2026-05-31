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

type Model struct {
	runtime        *runtime.Runtime
	viewport       viewport.Model
	composer       textinput.Model
	events         []protocol.Event
	width          int
	height         int
	status         string
	overlay        string
	pendingConfirm *protocol.ConfirmRequest
	ready          bool
	err            error
}

func New(rt *runtime.Runtime, initial []protocol.Event) Model {
	composer := textinput.New()
	composer.Placeholder = "Ask, /build, /diff, /versions, /tasks, /help"
	composer.Prompt = "> "
	composer.Focus()
	composer.CharLimit = 4096
	composer.Width = 80

	vp := viewport.New(80, 20)
	m := Model{
		runtime:  rt,
		viewport: vp,
		composer: composer,
		events:   initial,
		status:   "model local · branch unknown · dirty unknown · task idle",
		ready:    true,
	}
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
		m.composer.Width = max(20, msg.Width-4)
		m.viewport.Width = max(20, msg.Width)
		m.viewport.Height = max(5, msg.Height-6)
		m.refreshViewport()
	case tea.KeyMsg:
		if m.pendingConfirm != nil {
			switch msg.String() {
			case "enter", "y", "Y":
				events := m.runtime.Confirm(context.Background(), *m.pendingConfirm, true)
				m.pendingConfirm = nil
				m.events = append(m.events, events...)
				m.status = m.deriveStatus()
				m.overlay = overlayFromEvents(events)
				m.refreshViewport()
				return m, nil
			case "esc", "n", "N":
				events := m.runtime.Confirm(context.Background(), *m.pendingConfirm, false)
				m.pendingConfirm = nil
				m.events = append(m.events, events...)
				m.status = m.deriveStatus()
				m.overlay = overlayFromEvents(events)
				m.refreshViewport()
				return m, nil
			}
		}
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "enter":
			value := strings.TrimSpace(m.composer.Value())
			if value == "" {
				break
			}
			m.composer.SetValue("")
			events := m.runtime.Handle(context.Background(), value)
			m.events = append(m.events, events...)
			m.status = m.deriveStatus()
			m.pendingConfirm = confirmFromEvents(events)
			m.overlay = overlayFromEvents(events)
			m.refreshViewport()
		case "esc":
			m.overlay = ""
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
	prompt := promptStyle.Width(width - 2).Render(m.overlayView())
	composer := composerStyle.Width(width - 2).Render(m.composer.View())
	status := statusStyle.Width(width - 2).Render(m.status)
	return lipgloss.JoinVertical(lipgloss.Left, transcript, prompt, composer, status)
}

func (m *Model) refreshViewport() {
	m.viewport.SetContent(renderTranscript(m.events))
	m.viewport.GotoBottom()
}

func (m Model) overlayView() string {
	if strings.TrimSpace(m.overlay) != "" {
		return m.overlay
	}
	return "prompt overlay: approvals, confirmations, pickers, and pagers appear here"
}

func (m Model) deriveStatus() string {
	branch := "unknown"
	dirty := "unknown"
	for _, event := range m.events {
		if event.Type == protocol.EventSessionInfo {
			data, _ := json.Marshal(event.Payload)
			var info protocol.SessionInfo
			if err := json.Unmarshal(data, &info); err == nil {
				if info.Branch != "" {
					branch = info.Branch
				}
				dirty = fmt.Sprint(info.Dirty)
			}
		}
	}
	return fmt.Sprintf("model local · branch %s · dirty %s · session %s", branch, dirty, m.runtime.SessionID())
}

func renderTranscript(events []protocol.Event) string {
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
		case protocol.EventError:
			fmt.Fprintf(&b, "error\n  %s\n\n", event.Message)
		default:
			if strings.TrimSpace(event.Message) != "" {
				fmt.Fprintf(&b, "%s\n  %s\n\n", event.Type, event.Message)
			}
		}
	}
	return b.String()
}

func overlayFromEvents(events []protocol.Event) string {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		switch event.Type {
		case protocol.EventVersionDiff:
			return "diff pager\n" + event.Message
		case protocol.EventVersionChanged:
			return "versions\n" + event.Message
		case protocol.EventTaskProgress:
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return "tasks\n" + string(data)
		case protocol.EventConfirmRequest:
			if req := confirmFromEvent(event); req != nil {
				return fmt.Sprintf("%s\n\n%s\n\nCommand: %s\n\nEnter/y: %s · n/Esc: %s", req.Title, req.Summary, req.Command, req.ApproveText, req.RejectText)
			}
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return "confirm\n" + string(data)
		case protocol.EventApprovalRequest:
			data, _ := json.MarshalIndent(event.Payload, "", "  ")
			return "approval\n" + string(data)
		}
	}
	return ""
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
