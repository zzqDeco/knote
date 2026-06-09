package tools

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestNewExposesExpectedInvokableTools(t *testing.T) {
	svc := &fakeService{}
	registry := ByName(svc)
	for _, name := range []string{
		NameBuild,
		NameQuery,
		NameExplain,
		NameEval,
		NameDiff,
		NameVersions,
		NameCommit,
		NameRelease,
		NameCheckout,
	} {
		tool, ok := registry[name]
		if !ok {
			t.Fatalf("missing tool %s", name)
		}
		info, err := tool.Info(context.Background())
		if err != nil {
			t.Fatalf("%s Info failed: %v", name, err)
		}
		if info.Name != name || strings.TrimSpace(info.Desc) == "" {
			t.Fatalf("unexpected info for %s: %+v", name, info)
		}
	}
}

func TestToolsCallVersionedServiceAndReturnJSON(t *testing.T) {
	svc := &fakeService{}
	var gated []SideEffectRequest
	registry := ByNameWithOptions(Options{
		Service: svc,
		SideEffectGate: func(_ context.Context, req SideEffectRequest) error {
			gated = append(gated, req)
			return nil
		},
	})

	runJSON(t, registry[NameBuild], `{}`)
	if !svc.buildCalled {
		t.Fatal("build was not called")
	}

	query := runJSON(t, registry[NameQuery], `{"question":"what is knote?"}`)
	if query["answer"] != "query: what is knote?" || svc.queryQuestion != "what is knote?" {
		t.Fatalf("unexpected query result=%+v question=%q", query, svc.queryQuestion)
	}

	explain := runJSON(t, registry[NameExplain], `{"question":"why?"}`)
	if explain["answer"] != "explain: why?" || svc.explainQuestion != "why?" {
		t.Fatalf("unexpected explain result=%+v question=%q", explain, svc.explainQuestion)
	}

	eval := runJSON(t, registry[NameEval], `{}`)
	if eval["total"].(float64) != 1 || !svc.evalCalled {
		t.Fatalf("unexpected eval result=%+v called=%t", eval, svc.evalCalled)
	}

	diff := runJSON(t, registry[NameDiff], `{"ref":"HEAD~1"}`)
	if diff["diff"] != "diff against HEAD~1" || svc.diffRef != "HEAD~1" {
		t.Fatalf("unexpected diff result=%+v ref=%q", diff, svc.diffRef)
	}

	versions := runJSON(t, registry[NameVersions], `{"limit":3}`)
	list, ok := versions["versions"].([]any)
	if !ok || len(list) != 1 || svc.versionsLimit != 3 {
		t.Fatalf("unexpected versions result=%+v limit=%d", versions, svc.versionsLimit)
	}
	first := list[0].(map[string]any)
	if first["short_hash"] != "abc123" {
		t.Fatalf("versions result should use snake_case keys: %+v", first)
	}

	commit := runJSON(t, registry[NameCommit], `{"message":"knowledge update"}`)
	if commit["hash"] != "commit123" || svc.commitMessage != "knowledge update" {
		t.Fatalf("unexpected commit result=%+v message=%q", commit, svc.commitMessage)
	}

	release := runJSON(t, registry[NameRelease], `{"tag":"v0.1.1"}`)
	if release["tag"] != "v0.1.1" || svc.releaseTag != "v0.1.1" {
		t.Fatalf("unexpected release result=%+v tag=%q", release, svc.releaseTag)
	}

	checkout := runJSON(t, registry[NameCheckout], `{"ref":"dev","allow_dirty":true}`)
	if checkout["ref"] != "dev" || checkout["allow_dirty"] != true || svc.checkoutRef != "dev" || !svc.checkoutOpts.AllowDirty {
		t.Fatalf("unexpected checkout result=%+v ref=%q opts=%+v", checkout, svc.checkoutRef, svc.checkoutOpts)
	}
	if got, want := len(gated), 5; got != want {
		t.Fatalf("side-effect gate calls = %d, want %d: %+v", got, want, gated)
	}
	for _, action := range []string{"build", "eval", "commit", "release", "checkout"} {
		if !hasGateAction(gated, action) {
			t.Fatalf("missing side-effect gate action %s in %+v", action, gated)
		}
	}
}

func TestToolsRejectMalformedUnknownAndMissingArguments(t *testing.T) {
	registry := ByName(&fakeService{})
	for _, tc := range []struct {
		name string
		args string
	}{
		{name: NameBuild, args: `not-json`},
		{name: NameBuild, args: `{} {}`},
		{name: NameQuery, args: `{"question":"x","extra":1}`},
		{name: NameQuery, args: `{"question":""}`},
		{name: NameRelease, args: `{"tag":""}`},
		{name: NameCheckout, args: `{"ref":""}`},
	} {
		if _, err := registry[tc.name].InvokableRun(context.Background(), tc.args); err == nil {
			t.Fatalf("%s accepted invalid args %s", tc.name, tc.args)
		}
	}
}

func TestMutatingToolsRequireSideEffectGate(t *testing.T) {
	svc := &fakeService{}
	registry := ByName(svc)
	for _, tc := range []struct {
		name string
		args string
	}{
		{name: NameBuild, args: `{}`},
		{name: NameEval, args: `{}`},
		{name: NameCommit, args: `{"message":"knowledge update"}`},
		{name: NameRelease, args: `{"tag":"v0.1.1"}`},
		{name: NameCheckout, args: `{"ref":"dev","allow_dirty":true}`},
	} {
		_, err := registry[tc.name].InvokableRun(context.Background(), tc.args)
		if err == nil || !strings.Contains(err.Error(), "requires runtime confirmation") {
			t.Fatalf("%s did not require side-effect gate, err=%v", tc.name, err)
		}
	}
	if svc.buildCalled || svc.evalCalled || svc.commitMessage != "" || svc.releaseTag != "" || svc.checkoutRef != "" {
		t.Fatalf("mutating tool called service without gate: %+v", svc)
	}
}

func TestEinoToolsPackageImportBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list eino tools imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/runtime",
		"/internal/tui",
		"/internal/knowledge/" + "kag",
		"/internal/repository/" + "local",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("eino tools imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

func runJSON(t *testing.T, tool einotool.InvokableTool, args string) map[string]any {
	t.Helper()
	out, err := tool.InvokableRun(context.Background(), args)
	if err != nil {
		t.Fatalf("InvokableRun failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("tool returned invalid JSON %q: %v", out, err)
	}
	return decoded
}

func hasGateAction(requests []SideEffectRequest, action string) bool {
	for _, req := range requests {
		if req.Action == action {
			return true
		}
	}
	return false
}

type fakeService struct {
	buildCalled     bool
	queryQuestion   string
	explainQuestion string
	evalCalled      bool
	diffRef         string
	versionsLimit   int
	commitMessage   string
	releaseTag      string
	checkoutRef     string
	checkoutOpts    repository.CheckoutOptions
}

func (s *fakeService) Build(context.Context) (versioned.BuildResult, error) {
	s.buildCalled = true
	return versioned.BuildResult{
		Manifest: protocol.ArtifactManifest{Version: 1, DocumentCount: 1},
		Report:   "build report",
		KAGData:  map[string]any{"mode": "fake"},
	}, nil
}

func (s *fakeService) Query(_ context.Context, question string) (versioned.Answer, error) {
	s.queryQuestion = question
	return versioned.Answer{
		Answer:   "query: " + question,
		Evidence: []string{"source"},
		Mode:     "fake",
	}, nil
}

func (s *fakeService) Explain(_ context.Context, question string) (versioned.Explanation, error) {
	s.explainQuestion = question
	return versioned.Answer{
		Answer:      "explain: " + question,
		Evidence:    []string{"source"},
		Uncertainty: "low",
		Mode:        "fake",
		Data:        map[string]any{"explanation": "because"},
	}, nil
}

func (s *fakeService) Eval(context.Context) (repository.EvalReport, error) {
	s.evalCalled = true
	return repository.EvalReport{
		Results:       []repository.EvalResult{{ID: "smoke", Question: "q", Answer: "a"}},
		Total:         1,
		KnowledgeHash: "hash",
	}, nil
}

func (s *fakeService) Diff(_ context.Context, ref string) (string, error) {
	s.diffRef = ref
	return "diff against " + ref, nil
}

func (s *fakeService) Versions(_ context.Context, limit int) ([]repository.Version, error) {
	s.versionsLimit = limit
	return []repository.Version{{Hash: "abc123", ShortHash: "abc123", Subject: "initial", RelativeTime: "now", Current: true}}, nil
}

func (s *fakeService) Commit(_ context.Context, message string) (repository.CommitResult, error) {
	s.commitMessage = message
	return repository.CommitResult{Hash: "commit123", Summary: "committed"}, nil
}

func (s *fakeService) Release(_ context.Context, tag string) error {
	s.releaseTag = tag
	return nil
}

func (s *fakeService) Checkout(_ context.Context, ref string, opts repository.CheckoutOptions) error {
	s.checkoutRef = ref
	s.checkoutOpts = opts
	return nil
}

func (*fakeService) Status(context.Context) (repository.Status, error) {
	return repository.Status{}, nil
}

func (*fakeService) Mode() versioned.Mode {
	return versioned.ModeFake
}
