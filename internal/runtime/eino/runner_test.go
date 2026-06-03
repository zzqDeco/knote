package eino

import (
	"context"
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
	if _, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "hello"}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected skeleton run error, got %v", err)
	}
}

func TestRunnerProjectsExecutorEvents(t *testing.T) {
	runner := NewRunner(Options{
		Executor: fakeExecutor{
			events: []*adk.AgentEvent{
				adk.EventFromMessage(schema.ToolMessage("tool output", "call_1", schema.WithToolName("knote_query")), nil, schema.Tool, "knote_query"),
				adk.EventFromMessage(schema.AssistantMessage("assistant answer", nil), nil, schema.Assistant, ""),
			},
		},
	})
	events, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "question"})
	if err != nil {
		t.Fatal(err)
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
	events []*adk.AgentEvent
	err    error
}

func (e fakeExecutor) Query(context.Context, string) ([]*adk.AgentEvent, error) {
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
