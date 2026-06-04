package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var ErrSideEffectPending = errors.New("side-effect confirmation is pending")

type SideEffectExecutor func(context.Context, SideEffectRequest) ([]protocol.Event, error)

type SideEffectRequest struct {
	SessionID       string
	ToolName        string
	Action          string
	ArgumentsInJSON string
	Summary         string
	Execute         SideEffectExecutor
}

type SideEffectBridge struct {
	mu      sync.Mutex
	pending map[string]pendingSideEffect
}

type pendingSideEffect struct {
	request SideEffectRequest
	confirm protocol.ConfirmRequest
	emitted bool
}

func NewSideEffectBridge() *SideEffectBridge {
	return &SideEffectBridge{pending: map[string]pendingSideEffect{}}
}

func (b *SideEffectBridge) Request(ctx context.Context, req SideEffectRequest) error {
	if b == nil {
		return fmt.Errorf("side-effect bridge is not configured")
	}
	sessionID := strings.TrimSpace(sideEffectSessionID(ctx))
	if sessionID == "" {
		sessionID = strings.TrimSpace(req.SessionID)
	}
	if sessionID == "" {
		return fmt.Errorf("side-effect request requires a session id")
	}
	if strings.TrimSpace(req.ToolName) == "" {
		return fmt.Errorf("side-effect request requires a tool name")
	}
	if strings.TrimSpace(req.Action) == "" {
		return fmt.Errorf("side-effect request requires an action")
	}
	if req.Execute == nil {
		return fmt.Errorf("side-effect request %s has no executor", req.ToolName)
	}
	req.SessionID = sessionID
	req.ToolName = strings.TrimSpace(req.ToolName)
	req.Action = strings.TrimSpace(req.Action)
	req.ArgumentsInJSON = strings.TrimSpace(req.ArgumentsInJSON)
	req.Summary = strings.TrimSpace(req.Summary)
	confirm := protocol.ConfirmRequest{
		RequestID:   "eino_confirm_" + time.Now().UTC().Format("20060102T150405.000000000"),
		Action:      req.Action,
		Command:     sideEffectCommand(req),
		Title:       "Confirm Eino tool: " + req.ToolName,
		Summary:     sideEffectSummary(req),
		ApproveText: "Run tool once",
		RejectText:  "Cancel",
		CreatedAt:   time.Now().UTC(),
	}
	b.mu.Lock()
	b.pending[confirm.RequestID] = pendingSideEffect{request: req, confirm: confirm}
	b.mu.Unlock()
	return ErrSideEffectPending
}

func (b *SideEffectBridge) PendingEvents(sessionID string) []protocol.Event {
	if b == nil {
		return nil
	}
	sessionID = strings.TrimSpace(sessionID)
	b.mu.Lock()
	defer b.mu.Unlock()
	var events []protocol.Event
	for id, pending := range b.pending {
		if pending.emitted || pending.request.SessionID != sessionID {
			continue
		}
		pending.emitted = true
		b.pending[id] = pending
		events = append(events, protocol.NewEvent(protocol.EventConfirmRequest, sessionID, pending.confirm.Title, pending.confirm))
	}
	return events
}

func (b *SideEffectBridge) Confirm(ctx context.Context, sessionID string, req protocol.ConfirmRequest, approved bool) []protocol.Event {
	if b == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, "side-effect bridge is not configured", nil)}
	}
	pending, ok := b.consume(sessionID, req)
	if !ok {
		return []protocol.Event{
			protocol.NewEvent(protocol.EventError, sessionID, "confirmation is not pending or has already been used", map[string]string{"request_id": req.RequestID}),
		}
	}
	if !approved {
		return []protocol.Event{
			protocol.NewEvent(protocol.EventAssistantDone, sessionID, "Cancelled: "+pending.confirm.Action, map[string]string{"request_id": pending.confirm.RequestID}),
		}
	}
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventStatusUpdate, sessionID, "Confirmed: "+pending.confirm.Action, map[string]string{"request_id": pending.confirm.RequestID}),
	}
	executed, err := pending.request.Execute(ctx, pending.request)
	events = append(events, executed...)
	if err != nil && !hasErrorEvent(executed) {
		events = append(events, protocol.NewEvent(protocol.EventError, sessionID, err.Error(), map[string]string{
			"request_id": pending.confirm.RequestID,
			"tool":       pending.request.ToolName,
		}))
	}
	return events
}

func (b *SideEffectBridge) consume(sessionID string, req protocol.ConfirmRequest) (pendingSideEffect, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	pending, ok := b.pending[req.RequestID]
	if !ok || pending.request.SessionID != strings.TrimSpace(sessionID) {
		return pendingSideEffect{}, false
	}
	if pending.confirm.Action != req.Action || pending.confirm.Command != req.Command {
		return pendingSideEffect{}, false
	}
	delete(b.pending, req.RequestID)
	return pending, true
}

type sideEffectSessionKey struct{}

func withSideEffectSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sideEffectSessionKey{}, strings.TrimSpace(sessionID))
}

func sideEffectSessionID(ctx context.Context) string {
	value, _ := ctx.Value(sideEffectSessionKey{}).(string)
	return strings.TrimSpace(value)
}

func sideEffectCommand(req SideEffectRequest) string {
	args := strings.TrimSpace(req.ArgumentsInJSON)
	if args == "" {
		return req.ToolName
	}
	return req.ToolName + " " + args
}

func sideEffectSummary(req SideEffectRequest) string {
	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		summary = "Run " + req.ToolName + "."
	}
	args := strings.TrimSpace(req.ArgumentsInJSON)
	if args == "" {
		return summary
	}
	return summary + "\n\nArguments:\n" + args
}

func hasErrorEvent(events []protocol.Event) bool {
	for _, event := range events {
		if event.Type == protocol.EventError || event.Type == protocol.EventToolError {
			return true
		}
	}
	return false
}
