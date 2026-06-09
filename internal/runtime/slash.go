package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func (m *Manager) handleSlash(ctx context.Context, sessionID string, input string) []protocol.Event {
	userEvent := protocol.NewEvent(protocol.EventUserMessage, sessionID, input, nil)
	cmd, arg := parseSlash(input)
	switch cmd {
	case "new":
		m.persist([]protocol.Event{userEvent})
		events := append([]protocol.Event{userEvent}, m.newSession(ctx)...)
		m.emit(events)
		return events
	case "resume":
		m.persist([]protocol.Event{userEvent})
		events := append([]protocol.Event{userEvent}, m.resumeSession(ctx, sessionID, arg)...)
		m.emit(events)
		return events
	default:
		events := append([]protocol.Event{userEvent}, markSlashEvents(m.routeSlash(ctx, sessionID, cmd, arg))...)
		return m.persistEmitAndReturn(events)
	}
}

func (m *Manager) routeSlash(ctx context.Context, sessionID string, cmd string, arg string) []protocol.Event {
	switch cmd {
	case "build":
		return m.invokeTool(ctx, sessionID, tools.NameBuild, "{}")
	case "eval":
		return m.invokeTool(ctx, sessionID, tools.NameEval, "{}")
	case "diff":
		return m.invokeTool(ctx, sessionID, tools.NameDiff, jsonArgs(map[string]any{"ref": strings.TrimSpace(arg)}))
	case "versions":
		return m.invokeTool(ctx, sessionID, tools.NameVersions, jsonArgs(map[string]any{"limit": 20}))
	case "commit":
		return m.invokeTool(ctx, sessionID, tools.NameCommit, jsonArgs(map[string]any{"message": strings.TrimSpace(arg)}))
	case "release":
		tag := strings.TrimSpace(arg)
		if tag == "" {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "tag is required", nil)}
		}
		return m.invokeTool(ctx, sessionID, tools.NameRelease, jsonArgs(map[string]any{"tag": tag}))
	case "checkout":
		ref := strings.TrimSpace(arg)
		if ref == "" {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "ref is required", nil)}
		}
		return m.invokeTool(ctx, sessionID, tools.NameCheckout, jsonArgs(map[string]any{"ref": ref, "allow_dirty": true}))
	case "status":
		return m.status(sessionID, ctx)
	case "tasks":
		return []protocol.Event{protocol.NewEvent(protocol.EventTaskProgress, sessionID, "tasks", []protocol.Task{})}
	case "clear":
		return []protocol.Event{protocol.NewEvent(protocol.EventViewClear, sessionID, "view cleared", nil)}
	case "details":
		return m.details(ctx, sessionID)
	case "settings":
		return m.settings(sessionID)
	case "model":
		return m.modelInfo(sessionID)
	case "help":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, helpText, map[string]string{"overlay": "help"})}
	case "exit":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, "Use Ctrl+C to exit.", nil)}
	case "":
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "command is required", nil)}
	default:
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "unknown command: "+cmd, nil)}
	}
}

func (m *Manager) invokeTool(ctx context.Context, sessionID string, toolName string, argumentsInJSON string) []protocol.Event {
	if m.deps.ToolExecutor == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "Eino tool executor is not configured", map[string]string{"tool": toolName})}
	}
	runCtx := withSideEffectSession(ctx, sessionID)
	events, err := m.deps.ToolExecutor.Invoke(runCtx, sessionID, toolName, argumentsInJSON)
	if m.deps.SideEffects != nil {
		events = append(events, m.deps.SideEffects.PendingEvents(sessionID)...)
	}
	if err == nil || errors.Is(err, ErrSideEffectPending) {
		return events
	}
	if !hasErrorEvent(events) {
		events = append(events, protocol.NewEvent(protocol.EventError, sessionID, err.Error(), map[string]string{"tool": toolName}))
	}
	return events
}

func (m *Manager) newSession(ctx context.Context) []protocol.Event {
	m.mu.Lock()
	info, _ := m.newEinoSessionLocked(ctx, "")
	m.einoSession = info
	m.mu.Unlock()
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, info.ID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, info.ID, "session ready", info),
		protocol.NewEvent(protocol.EventViewClear, info.ID, "new session", nil),
	}
	m.persist(events)
	return events
}

func (m *Manager) resumeSession(ctx context.Context, currentSessionID string, sessionID string) []protocol.Event {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return m.sessionList(ctx, currentSessionID)
	}
	if m.deps.Sessions == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, "session storage is not configured", nil)}
	}
	loaded, err := m.deps.Sessions.Load(ctx, sessionID)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, "resume failed: "+err.Error(), nil)}
	}
	status := repository.Status{}
	if m.deps.Versions != nil {
		status, _ = m.deps.Versions.Status(ctx)
	}
	kagMode := ""
	if m.deps.Knowledge != nil {
		kagMode = string(m.deps.Knowledge.Mode())
	}
	info := protocol.SessionInfo{
		ID:        sessionID,
		Workspace: m.deps.Workspace,
		Branch:    status.Branch,
		Dirty:     status.Dirty,
		KAGMode:   kagMode,
		CreatedAt: time.Now().UTC(),
		Resumed:   true,
	}
	m.mu.Lock()
	m.einoSession = info
	m.mu.Unlock()
	infoEvent := protocol.NewEvent(protocol.EventSessionInfo, sessionID, "session resumed", info)
	m.persist([]protocol.Event{infoEvent})
	events := make([]protocol.Event, 0, len(loaded)+2)
	events = append(events, protocol.NewEvent(protocol.EventViewClear, sessionID, "resume session", nil))
	events = append(events, loaded...)
	events = append(events, infoEvent)
	return events
}

func (m *Manager) sessionList(ctx context.Context, sessionID string) []protocol.Event {
	if m.deps.Sessions == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "session storage is not configured", nil)}
	}
	summaries, err := m.deps.Sessions.List(ctx, 10)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "list sessions failed: "+err.Error(), nil)}
	}
	if len(summaries) == 0 {
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, "No saved sessions.", map[string]any{"overlay": "details", "sessions": summaries})}
	}
	var b strings.Builder
	b.WriteString("Recent sessions\n")
	for _, summary := range summaries {
		when := "no events"
		if !summary.LastEventAt.IsZero() {
			when = summary.LastEventAt.Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "- %s  events=%d  last=%s\n", summary.ID, summary.EventCount, when)
	}
	b.WriteString("\nUse /resume <session-id> to restore one.")
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, b.String(), map[string]any{"overlay": "details", "sessions": summaries})}
}

func (m *Manager) status(sessionID string, ctx context.Context) []protocol.Event {
	if m.deps.Versions == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "versions repository is not configured", nil)}
	}
	status, err := m.deps.Versions.Status(ctx)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, err.Error(), nil)}
	}
	message := strings.TrimSpace(status.Raw)
	if message == "" {
		message = fmt.Sprintf("branch=%s dirty=%t", firstNonEmpty(status.Branch, "unknown"), status.Dirty)
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, sessionID, message, status)}
}

func (m *Manager) details(ctx context.Context, sessionID string) []protocol.Event {
	status := repository.Status{}
	if m.deps.Versions != nil {
		status, _ = m.deps.Versions.Status(ctx)
	}
	manifestPath := filepath.Join(m.deps.Workspace, "artifacts", "manifest.json")
	manifestStatus := "missing"
	var manifest protocol.ArtifactManifest
	if m.deps.WorkspaceRepo != nil {
		if readManifest, err := m.deps.WorkspaceRepo.ReadManifest(ctx); err == nil {
			manifest = readManifest
			manifestStatus = fmt.Sprintf("version=%d documents=%d chunks=%d entities=%d relations=%d claims=%d summaries=%d",
				manifest.Version,
				manifest.DocumentCount,
				manifest.ChunkCount,
				manifest.EntityCount,
				manifest.RelationCount,
				manifest.ClaimCount,
				manifest.SummaryCount,
			)
		}
	}
	text := strings.Join([]string{
		"Workspace details",
		"workspace: " + m.deps.Workspace,
		"session: " + sessionID,
		"branch: " + firstNonEmpty(status.Branch, "unknown"),
		fmt.Sprintf("dirty: %t", status.Dirty),
		"artifact_manifest: " + relDisplay(m.deps.Workspace, manifestPath),
		"artifact_manifest_status: " + manifestStatus,
		"kag_mode: " + m.kagMode(),
		"kag_host: " + firstNonEmpty(m.deps.Config.KAG.Host, "unset"),
		"kag_config: " + relDisplay(m.deps.Workspace, m.deps.Config.KAG.ConfigPath),
		"kag_runtime_dir: " + relDisplay(m.deps.Workspace, m.deps.Config.KAG.RuntimeDir),
	}, "\n")
	payload := map[string]any{
		"overlay":           "details",
		"workspace":         m.deps.Workspace,
		"session_id":        sessionID,
		"branch":            status.Branch,
		"dirty":             status.Dirty,
		"kag_mode":          m.kagMode(),
		"artifact_manifest": manifest,
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, text, payload)}
}

func (m *Manager) settings(sessionID string) []protocol.Event {
	text := m.deps.SettingsYAML
	if strings.TrimSpace(text) == "" {
		text = renderSettings(m.deps.Config)
	}
	text = "Effective settings\n" + redactYAMLSecrets(text)
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, text, map[string]string{"overlay": "settings"})}
}

func (m *Manager) modelInfo(sessionID string) []protocol.Event {
	names := make([]string, 0, len(m.deps.Config.Models))
	for name := range m.deps.Config.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("Model profiles\n")
	if len(names) == 0 {
		b.WriteString("- none configured\n")
	}
	for _, name := range names {
		profile := m.deps.Config.Models[name]
		fmt.Fprintf(&b, "- %s: provider=%s model=%s", name, firstNonEmpty(profile.Provider, "unset"), firstNonEmpty(profile.Model, "unset"))
		if strings.TrimSpace(profile.BaseURL) != "" {
			fmt.Fprintf(&b, " base_url=%s", profile.BaseURL)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "\nsource: %s\nkag_mode: %s\nkag_host: %s", relDisplay(m.deps.Workspace, filepath.Join(m.deps.Workspace, ".knote", "config.yaml")), m.kagMode(), firstNonEmpty(m.deps.Config.KAG.Host, "unset"))
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, b.String(), map[string]string{"overlay": "settings"})}
}

func (m *Manager) kagMode() string {
	if m.deps.Knowledge == nil {
		return "unknown"
	}
	mode := m.deps.Knowledge.Mode()
	if mode == "" {
		return "unknown"
	}
	return string(mode)
}

func parseSlash(input string) (string, string) {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return "", ""
	}
	cmd := strings.TrimPrefix(fields[0], "/")
	return cmd, strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
}

func jsonArgs(values map[string]any) string {
	data, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func markSlashEvents(events []protocol.Event) []protocol.Event {
	for i := range events {
		if events[i].Type == protocol.EventAssistantDone {
			events[i].Payload = payloadWithSource(events[i].Payload, "slash")
		}
	}
	return events
}

func payloadWithSource(payload any, source string) any {
	switch value := payload.(type) {
	case nil:
		return map[string]string{"source": source}
	case map[string]string:
		out := make(map[string]string, len(value)+1)
		for key, item := range value {
			out[key] = item
		}
		out["source"] = source
		return out
	case map[string]any:
		out := make(map[string]any, len(value)+1)
		for key, item := range value {
			out[key] = item
		}
		out["source"] = source
		return out
	default:
		return map[string]any{"source": source, "value": payload}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func relDisplay(workspace, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "unset"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(workspace, path)
	}
	rel, err := filepath.Rel(workspace, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return filepath.ToSlash(rel)
}

func renderSettings(cfg repository.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "workspace: %s\n", cfg.Workspace)
	fmt.Fprintf(&b, "permissions:\n")
	fmt.Fprintf(&b, "  build_default: %s\n", cfg.Permissions.BuildDefault)
	fmt.Fprintf(&b, "  git_default: %s\n", cfg.Permissions.GitDefault)
	fmt.Fprintf(&b, "kag:\n")
	fmt.Fprintf(&b, "  adapter_path: %s\n", cfg.KAG.AdapterPath)
	fmt.Fprintf(&b, "  host: %s\n", cfg.KAG.Host)
	fmt.Fprintf(&b, "  fake: %t\n", cfg.KAG.Fake)
	fmt.Fprintf(&b, "  config_path: %s\n", cfg.KAG.ConfigPath)
	fmt.Fprintf(&b, "  project_id: %s\n", cfg.KAG.ProjectID)
	fmt.Fprintf(&b, "  namespace: %s\n", cfg.KAG.Namespace)
	fmt.Fprintf(&b, "  language: %s\n", cfg.KAG.Language)
	fmt.Fprintf(&b, "  runtime_dir: %s\n", cfg.KAG.RuntimeDir)
	fmt.Fprintf(&b, "models:\n")
	names := make([]string, 0, len(cfg.Models))
	for name := range cfg.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		profile := cfg.Models[name]
		fmt.Fprintf(&b, "  %s:\n", name)
		fmt.Fprintf(&b, "    provider: %s\n", profile.Provider)
		fmt.Fprintf(&b, "    model: %s\n", profile.Model)
		if strings.TrimSpace(profile.BaseURL) != "" {
			fmt.Fprintf(&b, "    base_url: %s\n", profile.BaseURL)
		}
	}
	return b.String()
}

func redactYAMLSecrets(text string) string {
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, ":") {
			lines = append(lines, line)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[0]))
		if strings.Contains(key, "key") || strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password") {
			prefix := line[:strings.Index(line, ":")+1]
			lines = append(lines, prefix+" REDACTED")
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

const helpText = `Commands:
/build      build knowledge artifacts
/diff       show artifact/git diff
/versions   show git versions
/commit     commit current knowledge version
/release    tag a release version
/checkout   checkout a version or branch
/eval       run a basic evaluation
/tasks      show runtime tasks
/status     show git status
/clear      clear the current TUI transcript view
/new        start a new session
/resume     list recent sessions, or /resume <session-id>
/details    show workspace/session/KAG details
/settings   show effective read-only settings
/model      show read-only model profile details
/exit       exit from the TUI with Ctrl+C
/help       show this help
`
