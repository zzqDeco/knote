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

type slashResult struct {
	events    []protocol.Event
	persisted []protocol.Event
	err       error
}

func (m *Manager) handleSlash(ctx context.Context, turn *activeTurn, sessionID string, input string) slashResult {
	userEvent := protocol.NewEvent(protocol.EventUserMessage, sessionID, input, nil)
	cmd, arg := parseSlash(input)
	if !m.deps.Capabilities.AllowsSlashCommand(cmd) {
		events := []protocol.Event{
			userEvent,
			protocol.NewEvent(protocol.EventError, sessionID, permissionedCommandUnavailableMessage, nil),
		}
		return slashResult{events: events, persisted: events, err: fmt.Errorf("slash command is unavailable")}
	}
	switch cmd {
	case "new":
		newSessionEvents := m.newSession(ctx, turn, sessionID)
		events := append([]protocol.Event{userEvent}, newSessionEvents...)
		result := slashResult{events: events, persisted: newSessionEvents}
		if hasErrorEvent(events) {
			result.err = fmt.Errorf("new session failed")
		}
		return result
	case "resume":
		if strings.TrimSpace(arg) == "" {
			events := append([]protocol.Event{userEvent}, m.sessionList(ctx, sessionID)...)
			result := slashResult{events: events, persisted: events}
			if hasErrorEvent(events) {
				result.err = fmt.Errorf("list sessions failed")
			}
			return result
		}
		events, persisted := m.resumeSession(ctx, turn, sessionID, arg)
		events = append([]protocol.Event{userEvent}, events...)
		persisted = append([]protocol.Event{userEvent}, persisted...)
		result := slashResult{events: events, persisted: persisted}
		if hasErrorEvent(events) {
			result.err = fmt.Errorf("resume session failed")
		}
		return result
	default:
		events := append([]protocol.Event{userEvent}, markSlashEvents(m.routeSlash(ctx, sessionID, cmd, arg))...)
		result := slashResult{events: events, persisted: events}
		if hasErrorEvent(events) {
			result.err = fmt.Errorf("slash command failed")
		}
		return result
	}
}

func (m *Manager) routeSlash(ctx context.Context, sessionID string, cmd string, arg string) []protocol.Event {
	switch cmd {
	case "build":
		return m.invokeTool(ctx, sessionID, tools.NameBuild, "{}")
	case "eval":
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "eval is unavailable until authorized explain is implemented", nil)}
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
		allowDirty := false
		if !m.deps.Capabilities.IsPermissioned() && m.deps.Versions != nil {
			if status, err := m.deps.Versions.Status(ctx); err == nil {
				allowDirty = status.Dirty
			}
		}
		return m.invokeTool(ctx, sessionID, tools.NameCheckout, jsonArgs(map[string]any{"ref": ref, "allow_dirty": allowDirty}))
	case "status":
		return m.status(sessionID, ctx)
	case "tasks":
		return []protocol.Event{protocol.NewEvent(protocol.EventTaskProgress, sessionID, "tasks", []protocol.Task{})}
	case "governance":
		return m.governanceView(ctx, sessionID)
	case "clear":
		return []protocol.Event{protocol.NewEvent(protocol.EventViewClear, sessionID, "view cleared", nil)}
	case "details":
		return m.details(ctx, sessionID)
	case "settings":
		return m.settings(sessionID)
	case "model":
		return m.modelInfo(sessionID)
	case "help":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, sessionID, helpTextFor(m.deps.Capabilities), map[string]string{"overlay": "help"})}
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
	runCtx := ctx
	if m.deps.Capabilities.IsPermissioned() {
		var err error
		runCtx, err = m.permissionedToolContext(ctx, sessionID)
		if err != nil {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, sessionAuthorizationErrorMessage, nil)}
		}
	}
	runCtx = withSideEffectSession(runCtx, sessionID)
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

func (m *Manager) permissionedToolContext(ctx context.Context, sessionID string) (context.Context, error) {
	if authorization, ok := protocol.AuthorizationContextFrom(ctx); ok {
		if authorization.SessionID != sessionID {
			return nil, sessionAuthorizationError()
		}
		return ctx, nil
	}
	if m.deps.AuthorizationContextProvider == nil {
		return nil, sessionAuthorizationError()
	}
	authorization, err := m.deps.AuthorizationContextProvider.authorizationContext(ctx, sessionID)
	if err != nil {
		return nil, sessionAuthorizationError()
	}
	runCtx, err := protocol.WithAuthorizationContext(ctx, authorization)
	if err != nil {
		return nil, sessionAuthorizationError()
	}
	if err := m.bindSessionAuthorization(ctx, sessionID, authorization); err != nil {
		return nil, sessionAuthorizationError()
	}
	return runCtx, nil
}

func (m *Manager) newSession(ctx context.Context, turn *activeTurn, currentSessionID string) []protocol.Event {
	info := m.newEinoSession(ctx, "")
	if !m.rotateSession(turn, info, nil) {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, "new session cancelled", nil)}
	}
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, info.ID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, info.ID, "session ready", info),
		protocol.NewEvent(protocol.EventViewClear, info.ID, "new session", nil),
	}
	return events
}

func (m *Manager) resumeSession(ctx context.Context, turn *activeTurn, currentSessionID string, sessionID string) ([]protocol.Event, []protocol.Event) {
	sessionID = strings.TrimSpace(sessionID)
	if m.deps.Sessions == nil {
		events := []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, "session storage is not configured", nil)}
		return events, events
	}
	var resumeAuthorization *protocol.AuthorizationContext
	if m.deps.Capabilities.IsPermissioned() && m.deps.AuthorizationContextProvider == nil {
		events := []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, permissionedResumeErrorMessage, nil)}
		return events, events
	}
	if m.deps.AuthorizationContextProvider != nil {
		authorization, err := m.authorizeSessionResume(ctx, sessionID)
		if err != nil {
			events := []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, permissionedResumeErrorMessage, nil)}
			return events, events
		}
		resumeAuthorization = &authorization
	}
	loaded, err := m.deps.Sessions.Load(ctx, sessionID)
	if err != nil {
		if resumeAuthorization != nil {
			events := []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, permissionedResumeErrorMessage, nil)}
			return events, events
		}
		events := []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, "resume failed: "+err.Error(), nil)}
		return events, events
	}
	authorization := protocol.AuthorizationContext{}
	if resumeAuthorization != nil {
		authorization = *resumeAuthorization
	}
	loaded = m.filterPersistedEvents(ctx, authorization, loaded)
	loaded = withoutTaskLifecycleID(loaded, turn.id)
	info := m.newEinoSession(ctx, sessionID)
	var binding *authorizationBinding
	if resumeAuthorization == nil {
		binding = nil
	} else {
		value := newAuthorizationBinding(*resumeAuthorization)
		binding = &value
	}
	if !m.rotateSession(turn, info, binding) {
		events := []protocol.Event{protocol.NewEvent(protocol.EventError, currentSessionID, "resume cancelled", nil)}
		return events, events
	}
	infoEvent := protocol.NewEvent(protocol.EventSessionInfo, sessionID, "session resumed", info)
	events := make([]protocol.Event, 0, len(loaded)+2)
	events = append(events, protocol.NewEvent(protocol.EventViewClear, sessionID, "resume session", nil))
	events = append(events, loaded...)
	events = append(events, infoEvent)
	return events, []protocol.Event{infoEvent}
}

func withoutTaskLifecycleID(events []protocol.Event, taskID string) []protocol.Event {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return events
	}
	filtered := make([]protocol.Event, 0, len(events))
	for _, event := range events {
		switch event.Type {
		case protocol.EventTaskStarted, protocol.EventTaskProgress, protocol.EventTaskComplete:
			data, err := json.Marshal(event.Payload)
			if err == nil {
				var task protocol.Task
				if json.Unmarshal(data, &task) == nil && task.ID == taskID {
					continue
				}
			}
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func (m *Manager) sessionList(ctx context.Context, sessionID string) []protocol.Event {
	if m.deps.Sessions == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "session storage is not configured", nil)}
	}
	var summaries []repository.SessionSummary
	if !m.deps.Capabilities.IsPermissioned() && m.deps.AuthorizationContextProvider == nil {
		var err error
		summaries, err = m.deps.Sessions.List(ctx, 10)
		if err != nil {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "list sessions failed: "+err.Error(), nil)}
		}
	} else {
		if m.deps.AuthorizationContextProvider == nil {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, sessionAuthorizationErrorMessage, nil)}
		}
		if _, ok := protocol.AuthorizationContextFrom(ctx); !ok {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, sessionAuthorizationErrorMessage, nil)}
		}
		permissioned, ok := m.deps.Sessions.(repository.PermissionedSessions)
		if !ok {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, sessionAuthorizationErrorMessage, nil)}
		}
		envelopes, err := permissioned.ListAuthorization(ctx)
		if err != nil {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "list sessions failed", nil)}
		}
		for _, envelope := range envelopes {
			targetAuthorization, err := m.deps.AuthorizationContextProvider.authorizationContext(ctx, envelope.SessionID)
			if err != nil || envelope.ValidateFor(targetAuthorization) != nil {
				continue
			}
			events, err := m.deps.Sessions.Load(ctx, envelope.SessionID)
			if err != nil {
				continue
			}
			events = m.filterPersistedEvents(ctx, targetAuthorization, events)
			summary := repository.SessionSummary{ID: envelope.SessionID, EventCount: len(events)}
			if len(events) > 0 {
				summary.LastEventAt = events[len(events)-1].CreatedAt.UTC()
				summary.UpdatedAt = summary.LastEventAt
			}
			summaries = append(summaries, summary)
		}
		sort.Slice(summaries, func(i, j int) bool {
			if !summaries[i].UpdatedAt.Equal(summaries[j].UpdatedAt) {
				return summaries[i].UpdatedAt.After(summaries[j].UpdatedAt)
			}
			return summaries[i].ID > summaries[j].ID
		})
		if len(summaries) > 10 {
			summaries = summaries[:10]
		}
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
	var bundleManifest protocol.ArtifactBundleManifest
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
		if reader, ok := m.deps.WorkspaceRepo.(interface {
			ReadCurrentArtifactManifest(context.Context) (protocol.ArtifactBundleManifest, error)
		}); ok {
			bundleManifest, _ = reader.ReadCurrentArtifactManifest(ctx)
		}
	}
	if bundleManifest.Version == protocol.ArtifactBundleManifestVersion {
		manifestPath = filepath.Join(
			m.deps.Workspace, "artifacts", "bundles", bundleManifest.ProjectionID, "manifest.json",
		)
		manifestStatus += fmt.Sprintf(" projection=%s namespace=%s authz=%s@%s",
			bundleManifest.ProjectionVersion, bundleManifest.Namespace,
			bundleManifest.AuthorizationObject, bundleManifest.AuthorizationVersion)
	}
	text := strings.Join([]string{
		"Workspace details",
		"workspace: " + m.deps.Workspace,
		"session: " + sessionID,
		"branch: " + firstNonEmpty(status.Branch, "unknown"),
		fmt.Sprintf("dirty: %t", status.Dirty),
		"artifact_manifest: " + relDisplay(m.deps.Workspace, manifestPath),
		"artifact_pointer: " + relDisplay(m.deps.Workspace, filepath.Join(m.deps.Workspace, "artifacts", "current.json")),
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
		"bundle_manifest":   bundleManifest,
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

const permissionedCommandUnavailableMessage = "command is unavailable in this session"

type slashHelpEntry struct {
	command     string
	description string
}

var slashHelpEntries = []slashHelpEntry{
	{command: "build", description: "build knowledge artifacts"},
	{command: "diff", description: "show artifact/git diff"},
	{command: "versions", description: "show git versions"},
	{command: "commit", description: "commit current knowledge version"},
	{command: "release", description: "tag a release version"},
	{command: "checkout", description: "checkout a version or branch"},
	{command: "tasks", description: "show runtime tasks"},
	{command: "governance", description: "show authorized governance status"},
	{command: "status", description: "show git status"},
	{command: "clear", description: "clear the current TUI transcript view"},
	{command: "new", description: "start a new session"},
	{command: "resume", description: "list recent sessions, or /resume <session-id>"},
	{command: "details", description: "show workspace/session/KAG details"},
	{command: "settings", description: "show effective read-only settings"},
	{command: "model", description: "show read-only model profile details"},
	{command: "exit", description: "exit from the TUI with Ctrl+C"},
	{command: "help", description: "show this help"},
}

func helpTextFor(profile SessionCapabilityProfile) string {
	var b strings.Builder
	b.WriteString("Commands:\n")
	for _, entry := range slashHelpEntries {
		if !profile.AllowsSlashCommand(entry.command) {
			continue
		}
		fmt.Fprintf(&b, "/%-11s%s\n", entry.command, entry.description)
	}
	return b.String()
}
