package eino

import (
	"context"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

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
	if _, err := runner.Run(context.Background(), runtime.EinoRunInput{SessionID: "s1", Message: "hello"}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected skeleton run error, got %v", err)
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
