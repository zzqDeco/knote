package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/artifact"
	"github.com/zzqDeco/knote/internal/config"
	"github.com/zzqDeco/knote/internal/gitstore"
	"github.com/zzqDeco/knote/internal/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/session"
)

type Runtime struct {
	workspace            string
	sessionID            string
	cfg                  config.Config
	store                session.Store
	git                  gitstore.Store
	kag                  kag.Client
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
	r := &Runtime{
		workspace: workspace,
		sessionID: sessionID,
		cfg:       cfg,
		store:     session.NewStore(workspace),
		git:       gitstore.Store{Workspace: workspace},
		kag: kag.Client{
			AdapterPath: cfg.KAG.AdapterPath,
			Workspace:   workspace,
			Host:        cfg.KAG.Host,
			Fake:        cfg.KAG.Fake,
			ConfigPath:  cfg.KAG.ConfigPath,
			ProjectID:   cfg.KAG.ProjectID,
			Namespace:   cfg.KAG.Namespace,
			Language:    cfg.KAG.Language,
			RuntimeDir:  cfg.KAG.RuntimeDir,
		},
		tasks:                map[string]protocol.Task{},
		pendingConfirmations: map[string]protocol.ConfirmRequest{},
	}
	info := protocol.SessionInfo{
		ID:        sessionID,
		Workspace: workspace,
		Branch:    r.git.Branch(ctx),
		Dirty:     r.git.Dirty(ctx),
		CreatedAt: time.Now().UTC(),
		Resumed:   resumed,
	}
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventGatewayReady, sessionID, "knote runtime ready", nil),
		protocol.NewEvent(protocol.EventSessionInfo, sessionID, "session ready", info),
	}
	for _, event := range events {
		_ = r.store.Append(event)
	}
	if resumed {
		if loaded, err := r.store.Load(sessionID); err == nil {
			events = append(loaded, events...)
		}
	}
	return r, events, nil
}

func (r *Runtime) SessionID() string { return r.sessionID }
func (r *Runtime) Workspace() string { return r.workspace }

func (r *Runtime) Handle(ctx context.Context, input string) []protocol.Event {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	events := []protocol.Event{protocol.NewEvent(protocol.EventUserMessage, r.sessionID, input, nil)}
	if strings.HasPrefix(input, "/") {
		events = append(events, r.handleSlash(ctx, input)...)
	} else {
		events = append(events, r.query(ctx, input)...)
	}
	r.persist(events)
	return events
}

func (r *Runtime) handleSlash(ctx context.Context, input string) []protocol.Event {
	fields := strings.Fields(input)
	cmd := strings.TrimPrefix(fields[0], "/")
	arg := strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
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
		return r.confirmRequest("commit", input, "Commit knowledge version", "Stage knote-tracked knowledge files and create a Git commit.")
	case "release":
		return r.confirmRequest("release", input, "Release knowledge version", "Create an annotated Git tag for the current version.")
	case "checkout":
		return r.confirmRequest("checkout", input, "Checkout knowledge version", "Run git checkout for the requested ref.")
	case "eval":
		return r.confirmRequest("eval", input, "Run evaluation", "Run KAG explain/eval against current artifacts.")
	case "help":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, helpText, nil)}
	case "clear", "new", "details", "settings", "model", "resume":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, "Command accepted: "+cmd, map[string]string{"status": "stubbed for MVP shell"})}
	case "exit":
		return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, "Use Ctrl+C to exit.", nil)}
	default:
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, "unknown command: "+cmd, nil)}
	}
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

func (r *Runtime) build(ctx context.Context) []protocol.Event {
	task := r.startTask("build", "Build knowledge artifacts", "Scan sources, run KAG adapter, and write artifacts.")
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventBuildStart, r.sessionID, "build started", task),
		protocol.NewEvent(protocol.EventToolStart, r.sessionID, "KagBuild", map[string]string{"tool": "KagBuild"}),
	}
	kagResp, err := r.kag.Build(ctx)
	if err != nil {
		events = append(events, protocol.NewEvent(protocol.EventToolError, r.sessionID, err.Error(), map[string]string{"tool": "KagBuild"}))
	} else {
		events = append(events, protocol.NewEvent(protocol.EventToolProgress, r.sessionID, "KagBuild adapter complete", kagResp.Data))
	}
	result, err := artifact.Builder{Workspace: r.workspace}.Build()
	if err != nil {
		task = r.finishTask(task.ID, protocol.TaskFailed, err.Error())
		events = append(events, protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil), protocol.NewEvent(protocol.EventTaskComplete, r.sessionID, "build failed", task))
		return events
	}
	if err := result.Write(r.workspace); err != nil {
		task = r.finishTask(task.ID, protocol.TaskFailed, err.Error())
		events = append(events, protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil), protocol.NewEvent(protocol.EventTaskComplete, r.sessionID, "build failed", task))
		return events
	}
	task = r.finishTask(task.ID, protocol.TaskCompleted, "artifacts written")
	events = append(events,
		protocol.NewEvent(protocol.EventToolComplete, r.sessionID, "KagBuild complete", map[string]any{"manifest": result.Manifest, "kag": kagResp.Data}),
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
	resp, err := r.kag.Query(ctx, question)
	if err != nil {
		answer := localAnswer(r.workspace, question)
		events = append(events,
			protocol.NewEvent(protocol.EventToolError, r.sessionID, err.Error(), map[string]string{"tool": "KagQuery"}),
			protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, answer, map[string]string{"uncertainty": "KAG unavailable; answered from local artifacts fallback"}),
		)
		return events
	}
	answer := fmt.Sprint(resp.Data["answer"])
	if strings.TrimSpace(answer) == "" || answer == "<nil>" {
		answer = localAnswer(r.workspace, question)
	}
	events = append(events,
		protocol.NewEvent(protocol.EventToolComplete, r.sessionID, "KagQuery complete", resp.Data),
		protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, answer, resp.Data),
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
	out, err := r.git.Log(ctx)
	if err != nil {
		out = "No versions yet."
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, strings.TrimSpace(out), nil)}
}

func (r *Runtime) commit(ctx context.Context, message string) []protocol.Event {
	if strings.TrimSpace(message) == "" {
		message = "knowledge: build " + time.Now().UTC().Format("20060102T150405Z")
	}
	out, err := r.git.Commit(ctx, message)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, strings.TrimSpace(out), map[string]string{"message": message})}
}

func (r *Runtime) release(ctx context.Context, tag string) []protocol.Event {
	if strings.TrimSpace(tag) == "" {
		tag = "v0.1.0"
	}
	out, err := r.git.Tag(ctx, tag)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, strings.TrimSpace(out), map[string]string{"tag": tag})}
}

func (r *Runtime) checkout(ctx context.Context, ref string) []protocol.Event {
	out, err := r.git.Checkout(ctx, ref)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventVersionChanged, r.sessionID, strings.TrimSpace(out), map[string]string{"ref": ref})}
}

func (r *Runtime) eval(ctx context.Context) []protocol.Event {
	resp, err := r.kag.Explain(ctx, "Evaluate current knowledge artifacts")
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, r.sessionID, err.Error(), nil)}
	}
	return []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, r.sessionID, "Eval complete", resp.Data)}
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

func slashArg(input string) string {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
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
/help       show this help
`
