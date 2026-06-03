package eino

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

func TestRunnerInventoryAndSkeletonRun(t *testing.T) {
	runner := NewRunner(Options{
		Tools: []einotool.InvokableTool{
			fakeTool{name: "knote_query", desc: "Query knowledge."},
			fakeTool{name: "knote_diff", desc: "Diff knowledge."},
		},
		EnableStreaming: true,
	})
	tools, err := runner.ToolInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 || tools[0].Name != "knote_query" || tools[1].Name != "knote_diff" {
		t.Fatalf("unexpected tool inventory: %+v", tools)
	}
	if err := runner.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "requires a configured") {
		t.Fatalf("expected skeleton runner to be not ready, got %v", err)
	}
	if _, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "hello"}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected skeleton run error, got %v", err)
	}
}

func TestRunnerProjectsExecutorEvents(t *testing.T) {
	executor := &fakeExecutor{
		events: []*adk.AgentEvent{
			adk.EventFromMessage(schema.ToolMessage("tool output", "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
			adk.EventFromMessage(schema.AssistantMessage("assistant answer", nil), nil, schema.Assistant, ""),
		},
	}
	runner := NewRunner(Options{
		Executor: executor,
	})
	if err := runner.Ready(context.Background()); err != nil {
		t.Fatalf("runner should be ready: %v", err)
	}
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{
		SessionID: "s1",
		Message:   "question",
		History: []protocol.Event{
			protocol.NewEvent(protocol.EventUserMessage, "s1", "earlier question", nil),
			protocol.NewEvent(protocol.EventAssistantDone, "s1", "earlier answer", nil),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := messageContents(executor.messages); strings.Join(got, "|") != "earlier question|earlier answer|question" {
		t.Fatalf("runner did not preserve transcript history: %+v", got)
	}
	if !hasEvent(events, protocol.EventAssistantStart) {
		t.Fatalf("missing assistant start: %+v", events)
	}
	if !hasEvent(events, protocol.EventToolComplete) {
		t.Fatalf("missing tool complete: %+v", events)
	}
	if got := lastMessage(events, protocol.EventAssistantDone); got != "assistant answer" {
		t.Fatalf("unexpected assistant answer %q in %+v", got, events)
	}
}

func TestRunnerProjectsStreamingAndInterruptEvents(t *testing.T) {
	stream := schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("streamed answer", nil)})
	runner := NewRunner(Options{
		Executor: &fakeExecutor{
			events: []*adk.AgentEvent{
				adk.EventFromMessage(nil, stream, schema.Assistant, ""),
				{
					Action: &adk.AgentAction{
						Interrupted: &adk.InterruptInfo{
							InterruptContexts: []*adk.InterruptCtx{
								{ID: "agent:test", Info: "approval needed", IsRootCause: true},
							},
						},
					},
				},
			},
		},
	})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastMessage(events, protocol.EventAssistantDone); got != "streamed answer" {
		t.Fatalf("streaming assistant output was not projected: %q in %+v", got, events)
	}
	if got := lastMessage(events, protocol.EventApprovalRequest); got != "approval needed" {
		t.Fatalf("interrupt was not surfaced: %q in %+v", got, events)
	}
}

func TestRunnerKeepsPartialEventsOnExecutorError(t *testing.T) {
	runner := NewRunner(Options{
		Executor: &fakeExecutor{
			events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.AssistantMessage("partial answer", nil), nil, schema.Assistant, ""),
			},
			err: errors.New("runner failed"),
		},
	})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err == nil || !strings.Contains(err.Error(), "runner failed") {
		t.Fatalf("expected executor error, got %v", err)
	}
	if got := lastMessage(events, protocol.EventAssistantDone); got != "partial answer" {
		t.Fatalf("partial assistant output was not preserved: %q in %+v", got, events)
	}
}

func TestRunnerUsesStatusForNoResponseAndFiltersSlashHistory(t *testing.T) {
	executor := &fakeExecutor{}
	runner := NewRunner(Options{Executor: executor})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{
		SessionID: "s1",
		Message:   "question",
		History: []protocol.Event{
			protocol.NewEvent(protocol.EventUserMessage, "s1", "/build", nil),
			protocol.NewEvent(protocol.EventStatusUpdate, "s1", "Eino runner completed without response.", nil),
			protocol.NewEvent(protocol.EventAssistantDone, "s1", "real assistant answer", nil),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasEvent(events, protocol.EventAssistantDone) {
		t.Fatalf("no-response fallback must not be persisted as assistant output: %+v", events)
	}
	if got := lastMessage(events, protocol.EventStatusUpdate); got != "Eino runner completed without response." {
		t.Fatalf("missing no-response status event: %q in %+v", got, events)
	}
	if got := messageContents(executor.messages); strings.Join(got, "|") != "real assistant answer|question" {
		t.Fatalf("slash or status history leaked into ADK messages: %+v", got)
	}
}

func TestRunnerConfigCarriesADKSettings(t *testing.T) {
	runner := NewRunner(Options{EnableStreaming: true})
	cfg := runner.RunnerConfig(nil)
	if !cfg.EnableStreaming {
		t.Fatal("expected ADK runner config to preserve streaming option")
	}
	if cfg.Agent != nil {
		t.Fatalf("expected nil agent in skeleton config, got %T", cfg.Agent)
	}
	if created := runner.NewADKRunner(context.Background(), nil); created == nil {
		t.Fatal("expected ADK runner to be constructible from skeleton config")
	}
}

type fakeTool struct {
	name string
	desc string
}

func (t fakeTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name, Desc: t.desc}, nil
}

func (fakeTool) InvokableRun(context.Context, string, ...einotool.Option) (string, error) {
	return "{}", nil
}

type fakeExecutor struct {
	events   []*adk.AgentEvent
	messages []*schema.Message
	err      error
}

func (e *fakeExecutor) Run(_ context.Context, messages []*schema.Message) ([]*adk.AgentEvent, error) {
	e.messages = append([]*schema.Message(nil), messages...)
	return append([]*adk.AgentEvent(nil), e.events...), e.err
}

func hasEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func lastMessage(events []protocol.Event, eventType protocol.EventType) string {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == eventType {
			return events[i].Message
		}
	}
	return ""
}

func messageContents(messages []*schema.Message) []string {
	var out []string
	for _, message := range messages {
		if message != nil {
			out = append(out, message.Content)
		}
	}
	return out
}
