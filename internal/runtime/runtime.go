package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/config"
	"github.com/zzqDeco/knote/internal/gitstore"
	"github.com/zzqDeco/knote/internal/knowledge"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
	"github.com/zzqDeco/knote/internal/session"
	"gopkg.in/yaml.v3"
)

type Runtime struct {
	workspace            string
	sessionID            string
	cfg                  config.Config
	store                session.Store
	git                  gitstore.Store
	kag                  kag.Client
	repo                 local.Store
	knowledge            knowledge.Service
	tasks                map[string]protocol.Task
	confirmMu            sync.Mutex
	pendingConfirmations map[string]protocol.ConfirmRequest
}

type Options struct {
	Workspace string
	ResumeID  string
}

func New(ctx context.Context, opts Options) (*Runtime, []protocol.Event, error) {
	workspace, err := filepath.Abs(firstNonEmpty(opts.Workspace, "."))
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.LoadOrDefault(workspace)
	if err != nil {
		return nil, nil, err
	}
	if os.Getenv("KNOTE_KAG_FAKE") == "1" {
		cfg.KAG.Fake = true
	}
	if err := config.Ensure(workspace, cfg); err != nil {
		return nil, nil, err
	}
	sessionID := opts.ResumeID
	resumed := true
	if strings.TrimSpace(sessionID) == "" {
		sessionID = session.NewID()
		resumed = false
	}
	repo := local.New(workspace)
	kagClient := kag.Client{
		AdapterPath: cfg.KAG.AdapterPath,
		Workspace:   workspace,
		Host:        cfg.KAG.Host,
		Fake:        cfg.KAG.Fake,
		ConfigPath:  cfg.KAG.ConfigPath,
		ProjectID:   cfg.KAG.ProjectID,
		Namespace:   cfg.KAG.Namespace,
		Language:    cfg.KAG.Language,
		RuntimeDir:  cfg.KAG.RuntimeDir,
	}
	mode := knowledge.ModeReal
	if cfg.KAG.Fake {
		mode = knowledge.ModeFake
	}
	r := &Runtime{
		workspace:            workspace,
		sessionID:            sessionID,
		cfg:                  cfg,
		store:                session.NewStore(workspace),
		git:                  gitstore.Store{Workspace: workspace},
		kag:                  kagClient,
		repo:                 repo,
		knowledge:            knowledge.New(knowledge.Options{Workspace: workspace, Repo: repo, Backend: kagClient, Mode: mode}),
		tasks:                map[string]protocol.Task{},
		pendingConfirmations: map[string]protocol.ConfirmRequest{},
	}
	var loaded []protocol.Event
	if resumed {
		loaded, _ = r.store.Load(sessionID)
	}
	info := r.sessionInfo(ctx, resumed)
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, sessionID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, sessionID, "session ready", info),
	}
	for _, event := range events {
		_ = r.store.Append(event)
	}
	if resumed {
		events = append(loaded, events...)
	}
	return r, events, nil
}

func (r *Runtime) SessionID() string { return r.sessionID }
func (r *Runtime) Workspace() string { return r.workspace }

func (r *Runtime) CurrentSessionInfo(ctx context.Context) protocol.SessionInfo {
	return r.sessionInfo(ctx, false)
}

func (r *Runtime) sessionInfo(ctx context.Context, resumed bool) protocol.SessionInfo {
	return protocol.SessionInfo{
		ID:        r.sessionID,
		Workspace: r.workspace,
		Branch:    r.git.Branch(ctx),
		Dirty:     r.git.Dirty(ctx),
		KAGMode:   r.kagMode(),
		CreatedAt: time.Now().UTC(),
		Resumed:   resumed,
	}
}

func (r *Runtime) Handle(ctx context.Context, input string) []protocol.Event {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventUserMessage, r.sessionID, input, nil)}
	if strings.HasPrefix(input, "/") {
		cmd, arg := parseSlash(input)
		if cmd == "new" {
			r.persist(events)
			return append(events, r.newSession(ctx)...)
		}
		if cmd == "resume" && strings.TrimSpace(arg) != "" {
			r.persist(events)
			return append(events, r.resumeSession(ctx, arg)...)
		}
		events = append(events, r.handleSlash(ctx, input)...)
	} else {
		events = append(events, r.query(ctx, input)...)
	}
	r.persist(events)
	return events
}

func (r *Runtime) handleSlash(ctx context.Context, input string) []protocol.Event {
	cmd, arg := parseSlash(input)
	switch cmd {
	case "build":
		return r.confirmRequest("build", input, "Build knowledge artifacts", "Scan sources, call KAG, and write artifacts into artifacts/.")
	case "status":
		return r.status(ctx)
	case "diff":
		return r.diff(ctx, arg)
	case "versions":
		return r.versions(ctx)
	case "tasks":
		return r.taskList()
	case "commit":
		return r.confirmRequest("commit", input, "Commit knowledge version", "Stage only .knote/config.yaml, sources/, artifacts/, and evals/, then create a Git commit.")
	case "release":
		if err := r.releasePreflight(ctx); err != nil {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
		}
		return r.confirmRequest("release", input, "Release knowledge version", "Create an annotated Git tag after clean-workspace and eval gates pass.")
	case "checkout":
		if strings.TrimSpace(arg) == "" {
			return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, "ref is required", nil)}
		}
		summary := "Run git checkout for the requested ref."
		if r.git.Dirty(ctx) {
			summary = "Workspace is dirty. Confirm checkout only if these local changes should remain in the working tree."
		}
		return r.confirmRequest("checkout", input, "Checkout knowledge version", summary)
	case "eval":
		return r.confirmRequest("eval", input, "Run evaluation", "Run KAG explain/eval against current artifacts.")
	case "help":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, helpText, map[string]string{"overlay": "help"})}
	case "clear":
		return r.clearView()
	case "resume":
		return r.sessionList()
	case "details":
		return r.details(ctx)
	case "settings":
		return r.settings()
	case "model":
		return r.modelInfo()
	case "new":
		return r.newSession(ctx)
	case "exit":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, "Use Ctrl+C to exit.", nil)}
	default:
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, "unknown command: "+cmd, nil)}
	}
}

func (r *Runtime) clearView() []protocol.Event {
	return []protocol.Event{protocol.NewEvent(protocol.EventViewClear, r.sessionID, "view cleared", nil)}
}

func (r *Runtime) newSession(ctx context.Context) []protocol.Event {
	r.clearPendingConfirmations()
	r.sessionID = session.NewID()
	info := r.sessionInfo(ctx, false)
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, r.sessionID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, r.sessionID, "session ready", info),
		protocol.NewEvent(protocol.EventViewClear, r.sessionID, "new session", nil),
	}
	r.persist(events)
	return events
}

func (r *Runtime) resumeSession(ctx context.Context, sessionID string) []protocol.Event {
	sessionID = strings.TrimSpace(sessionID)
	loaded, err := r.store.Load(sessionID)
	if err != nil {
		events := []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, "resume failed: "+err.Error(), nil)}
		r.persist(events)
		return events
	}
	r.clearPendingConfirmations()
	r.sessionID = sessionID
	info := r.sessionInfo(ctx, true)
	infoEvent := protocol.NewEvent(protocol.EventSessionInfo, r.sessionID, "session resumed", info)
	r.persist([]protocol.Event{infoEvent})
	events := make([]protocol.Event, 0, len(loaded)+2)
	events = append(events, protocol.NewEvent(protocol.EventViewClear, r.sessionID, "resume session", nil))
	events = append(events, loaded...)
	events = append(events, infoEvent)
	return events
}

func (r *Runtime) sessionList() []protocol.Event {
	summaries, err := r.store.List(10)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, "list sessions failed: "+err.Error(), nil)}
	}
	if len(summaries) == 0 {
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, "No saved sessions.", map[string]any{"overlay": "details", "sessions": summaries})}
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
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, b.String(), map[string]any{"overlay": "details", "sessions": summaries})}
}

func (r *Runtime) details(ctx context.Context) []protocol.Event {
	branch := r.git.Branch(ctx)
	dirty := r.git.Dirty(ctx)
	manifestPath := filepath.Join(r.workspace, "artifacts", "manifest.json")
	manifestStatus := "missing"
	var manifest protocol.ArtifactManifest
	if data, err := os.ReadFile(manifestPath); err == nil {
		if err := json.Unmarshal(data, &manifest); err == nil {
			manifestStatus = fmt.Sprintf("version=%d documents=%d chunks=%d entities=%d relations=%d claims=%d summaries=%d",
				manifest.Version,
				manifest.DocumentCount,
				manifest.ChunkCount,
				manifest.EntityCount,
				manifest.RelationCount,
				manifest.ClaimCount,
				manifest.SummaryCount,
			)
		} else {
			manifestStatus = "invalid: " + err.Error()
		}
	}
	text := strings.Join([]string{
		"Workspace details",
		"workspace: " + r.workspace,
		"session: " + r.sessionID,
		"branch: " + firstNonEmpty(branch, "unknown"),
		fmt.Sprintf("dirty: %t", dirty),
		"artifact_manifest: " + relDisplay(r.workspace, manifestPath),
		"artifact_manifest_status: " + manifestStatus,
		"kag_mode: " + r.kagMode(),
		"kag_host: " + firstNonEmpty(r.cfg.KAG.Host, "unset"),
		"kag_config: " + relDisplay(r.workspace, r.cfg.KAG.ConfigPath),
		"kag_runtime_dir: " + relDisplay(r.workspace, r.cfg.KAG.RuntimeDir),
	}, "\n")
	payload := map[string]any{
		"overlay":           "details",
		"workspace":         r.workspace,
		"session_id":        r.sessionID,
		"branch":            branch,
		"dirty":             dirty,
		"kag_mode":          r.kagMode(),
		"artifact_manifest": manifest,
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, text, payload)}
}

func (r *Runtime) settings() []protocol.Event {
	data, err := yaml.Marshal(r.cfg)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	text := "Effective settings\n" + redactYAMLSecrets(string(data))
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, text, map[string]string{"overlay": "settings"})}
}

func (r *Runtime) modelInfo() []protocol.Event {
	names := make([]string, 0, len(r.cfg.Models))
	for name := range r.cfg.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("Model profiles\n")
	if len(names) == 0 {
		b.WriteString("- none configured\n")
	}
	for _, name := range names {
		profile := r.cfg.Models[name]
		fmt.Fprintf(&b, "- %s: provider=%s model=%s", name, firstNonEmpty(profile.Provider, "unset"), firstNonEmpty(profile.Model, "unset"))
		if strings.TrimSpace(profile.BaseURL) != "" {
			fmt.Fprintf(&b, " base_url=%s", profile.BaseURL)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "\nsource: %s\nkag_mode: %s\nkag_host: %s", relDisplay(r.workspace, filepath.Join(r.workspace, ".knote", "config.yaml")), r.kagMode(), firstNonEmpty(r.cfg.KAG.Host, "unset"))
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, b.String(), map[string]string{"overlay": "settings"})}
}

func (r *Runtime) Confirm(ctx context.Context, req protocol.ConfirmRequest, approved bool) []protocol.Event {
	pending, ok := r.consumePendingConfirmation(req)
	if !ok {
		events := []protocol.Event{
			protocol.NewEvent(protocol.EventError, r.sessionID, "confirmation is not pending or has already been used", map[string]string{"request_id": req.RequestID}),
		}
		r.persist(events)
		return events
	}
	if !approved {
		events := []protocol.Event{
			protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, "Cancelled: "+pending.Action, map[string]string{"request_id": pending.RequestID}),
		}
		r.persist(events)
		return events
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, r.sessionID, "Confirmed: "+pending.Action, map[string]string{"request_id": pending.RequestID})}
	switch pending.Action {
	case "build":
		events = append(events, r.build(ctx)...)
	case "commit":
		events = append(events, r.commit(ctx, slashArg(pending.Command))...)
	case "release":
		events = append(events, r.release(ctx, slashArg(pending.Command))...)
	case "checkout":
		events = append(events, r.checkout(ctx, slashArg(pending.Command))...)
	case "eval":
		events = append(events, r.eval(ctx)...)
	default:
		events = append(events, protocol.NewEvent(protocol.EventError, r.sessionID, "unknown confirmed action: "+pending.Action, nil))
	}
	r.persist(events)
	return events
}

func (r *Runtime) confirmRequest(action, command, title, summary string) []protocol.Event {
	req := protocol.ConfirmRequest{
		RequestID:   "confirm_" + time.Now().UTC().Format("20060102T150405.000000000"),
		Action:      action,
		Command:     command,
		Title:       title,
		Summary:     summary,
		ApproveText: "Approve once",
		RejectText:  "Cancel",
		CreatedAt:   time.Now().UTC(),
	}
	r.confirmMu.Lock()
	r.pendingConfirmations[req.RequestID] = req
	r.confirmMu.Unlock()
	return []protocol.Event{protocol.NewEvent(protocol.EventConfirmRequest, r.sessionID, title, req)}
}

func (r *Runtime) consumePendingConfirmation(req protocol.ConfirmRequest) (protocol.ConfirmRequest, bool) {
	r.confirmMu.Lock()
	defer r.confirmMu.Unlock()
	pending, ok := r.pendingConfirmations[req.RequestID]
	if !ok {
		return protocol.ConfirmRequest{}, false
	}
	if pending.Action != req.Action || pending.Command != req.Command {
		return protocol.ConfirmRequest{}, false
	}
	delete(r.pendingConfirmations, req.RequestID)
	return pending, true
}

func (r *Runtime) clearPendingConfirmations() {
	r.confirmMu.Lock()
	defer r.confirmMu.Unlock()
	r.pendingConfirmations = map[string]protocol.ConfirmRequest{}
}

func (r *Runtime) build(ctx context.Context) []protocol.Event {
	task := r.startTask("build", "Build knowledge artifacts", "Scan sources, run KAG adapter, and write artifacts.")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventBuildStart, r.sessionID, "build started", task),
		protocol.NewEvent(protocol.EventToolStart, r.sessionID, "KagBuild", map[string]string{"tool": "KagBuild"}),
	}
	result, err := r.knowledge.Build(ctx)
	if err != nil {
		task = r.finishTask(task.ID, protocol.TaskFailed, err.Error())
		events = append(events, protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil), protocol.NewEvent(protocol.EventTaskComplete, r.sessionID, "build failed", task))
		return events
	}
	if strings.TrimSpace(result.AdapterError) != "" {
		events = append(events, protocol.NewEvent(protocol.EventToolError, r.sessionID, result.AdapterError, map[string]string{"tool": "KagBuild"}))
	} else {
		events = append(events, protocol.NewEvent(protocol.EventToolProgress, r.sessionID, "KagBuild adapter complete", result.KAGData))
	}
	task = r.finishTask(task.ID, protocol.TaskCompleted, "artifacts written")
	events = append(events,
		protocol.NewEvent(protocol.EventToolComplete, r.sessionID, "KagBuild complete", map[string]any{"manifest": result.Manifest, "kag": result.KAGData}),
		protocol.NewEvent(protocol.EventBuildComplete, r.sessionID, "Build complete", result.Manifest),
		protocol.NewEvent(protocol.EventTaskComplete, r.sessionID, "build completed", task),
		protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, result.Report, nil),
	)
	return events
}

func (r *Runtime) query(ctx context.Context, question string) []protocol.Event {
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventAssistantStart, r.sessionID, "query started", nil),
		protocol.NewEvent(protocol.EventToolStart, r.sessionID, "KagQuery", map[string]string{"query": question}),
	}
	answer, err := r.knowledge.Query(ctx, question)
	if err != nil {
		return append(events, protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil))
	}
	if strings.TrimSpace(answer.AdapterError) != "" {
		events = append(events,
			protocol.NewEvent(protocol.EventToolError, r.sessionID, answer.AdapterError, map[string]string{"tool": "KagQuery"}),
			protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, answer.Answer, map[string]string{"uncertainty": answer.Uncertainty}),
		)
		return events
	}
	events = append(events,
		protocol.NewEvent(protocol.EventToolComplete, r.sessionID, "KagQuery complete", answer.Data),
		protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, answer.Answer, answer.Data),
	)
	return events
}

func (r *Runtime) status(ctx context.Context) []protocol.Event {
	out, err := r.git.Status(ctx)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventStatusUpdate, r.sessionID, strings.TrimSpace(out), nil)}
}

func (r *Runtime) diff(ctx context.Context, ref string) []protocol.Event {
	out, err := r.git.Diff(ctx, ref)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	if strings.TrimSpace(out) == "" {
		out = "No diff."
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionDiff, r.sessionID, out, nil)}
}

func (r *Runtime) versions(ctx context.Context) []protocol.Event {
	versions, err := r.git.Versions(ctx, 20)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, "No versions yet.", nil)}
	}
	if len(versions) == 0 {
		return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, "No versions yet.", versions)}
	}
	var b strings.Builder
	b.WriteString("Versions\n")
	for _, version := range versions {
		marker := " "
		if version.Current {
			marker = "*"
		}
		tagText := ""
		if len(version.Tags) > 0 {
			tagText = " tags=" + strings.Join(version.Tags, ",")
		}
		fmt.Fprintf(&b, "%s %s  %s  %s%s\n", marker, version.ShortHash, version.RelativeTime, version.Subject, tagText)
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, strings.TrimSpace(b.String()), versions)}
}

func (r *Runtime) commit(ctx context.Context, message string) []protocol.Event {
	if strings.TrimSpace(message) == "" {
		message = "knowledge: build " + time.Now().UTC().Format("20060102T150405Z")
	}
	out, err := r.git.Commit(ctx, message)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, firstNonEmpty(strings.TrimSpace(out), "Committed knowledge version."), map[string]string{"message": message})}
}

func (r *Runtime) release(ctx context.Context, tag string) []protocol.Event {
	if strings.TrimSpace(tag) == "" {
		tag = "v0.1.0"
	}
	if err := r.releasePreflight(ctx); err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	out, err := r.git.Tag(ctx, tag)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, firstNonEmpty(strings.TrimSpace(out), "Tagged "+tag), map[string]string{"tag": tag})}
}

func (r *Runtime) checkout(ctx context.Context, ref string) []protocol.Event {
	out, err := r.git.Checkout(ctx, ref, true)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, firstNonEmpty(strings.TrimSpace(out), "Checked out "+ref), map[string]string{"ref": ref})}
}

func (r *Runtime) eval(ctx context.Context) []protocol.Event {
	questions, err := r.repo.LoadQuestions(ctx)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventToolStart, r.sessionID, "KagExplain eval", map[string]any{"questions": len(questions)})}
	report, err := r.knowledge.Eval(ctx)
	if err != nil {
		return append(events, protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil))
	}
	for _, result := range report.Results {
		if result.AdapterError != "" {
			events = append(events, protocol.NewEvent(protocol.EventToolError, r.sessionID, result.AdapterError, map[string]string{"question_id": result.ID, "tool": "KagExplain"}))
			continue
		}
		events = append(events, protocol.NewEvent(protocol.EventToolComplete, r.sessionID, "KagExplain complete: "+result.ID, map[string]any{
			"answer":      result.Answer,
			"evidence":    result.Evidence,
			"explanation": result.Explanation,
			"uncertainty": result.Uncertainty,
			"mode":        result.Mode,
		}))
	}
	payload := map[string]any{
		"total":          report.Total,
		"adapter_errors": report.AdapterErrors,
		"report_path":    "evals/report.md",
	}
	message := report.ReportMarkdown
	if strings.TrimSpace(message) == "" {
		message = knowledge.RenderEvalReport(report)
	}
	events = append(events, protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, message, payload))
	if report.AdapterErrors > 0 {
		events = append(events, protocol.NewEvent(protocol.EventError, r.sessionID, "eval completed with adapter errors", payload))
	}
	return events
}

func (r *Runtime) releasePreflight(ctx context.Context) error {
	if r.git.Dirty(ctx) {
		return fmt.Errorf("release requires a clean workspace")
	}
	return r.repo.EvalGate(ctx)
}

func (r *Runtime) taskList() []protocol.Event {
	tasks := make([]protocol.Task, 0, len(r.tasks))
	for _, task := range r.tasks {
		tasks = append(tasks, task)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt.Before(tasks[j].CreatedAt) })
	return []protocol.Event{protocol.NewEvent(protocol.EventTaskProgress, r.sessionID, "tasks", tasks)}
}

func (r *Runtime) startTask(id, title, desc string) protocol.Task {
	task := protocol.Task{
		ID:          id + "_" + time.Now().UTC().Format("150405.000"),
		Title:       title,
		Description: desc,
		Status:      protocol.TaskRunning,
		Owner:       "runtime",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	r.tasks[task.ID] = task
	return task
}

func (r *Runtime) finishTask(id string, status protocol.TaskStatus, msg string) protocol.Task {
	task := r.tasks[id]
	task.Status = status
	task.Message = msg
	task.UpdatedAt = time.Now().UTC()
	r.tasks[id] = task
	return task
}

func (r *Runtime) persist(events []protocol.Event) {
	for _, event := range events {
		_ = r.store.Append(event)
	}
}

func localAnswer(workspace, question string) string {
	data, err := os.ReadFile(filepath.Join(workspace, "artifacts", "summaries.jsonl"))
	if err != nil || len(data) == 0 {
		return "当前知识版本中没有足够证据回答这个问题。请先运行 /build。"
	}
	return "结论\n" + strings.TrimSpace(string(data)) + "\n\n依据\n本回答来自 knote artifacts fallback。\n\n不确定性\n真实 KAG 查询未返回可用结果。"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func parseSlash(input string) (string, string) {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return "", ""
	}
	cmd := strings.TrimPrefix(fields[0], "/")
	return cmd, strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
}

func slashArg(input string) string {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
}

func (r *Runtime) kagMode() string {
	if r.cfg.KAG.Fake {
		return "fake"
	}
	return "real"
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
