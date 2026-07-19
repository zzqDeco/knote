package tools

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

var _ AuthorizationGate = (*authz.ToolAuthorizationGate)(nil)

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
	var checkoutSummary string
	for _, req := range gated {
		if req.Action == "checkout" {
			checkoutSummary = req.Summary
		}
	}
	if !strings.Contains(checkoutSummary, "Workspace is dirty") || !strings.Contains(checkoutSummary, "local changes should remain") {
		t.Fatalf("dirty checkout confirmation did not explain preservation risk: %q", checkoutSummary)
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

func TestPermissionedQueryAuthorizationCannotComeFromToolJSON(t *testing.T) {
	svc := &fakeService{}
	callbackCalls := 0
	registry := ByNameWithOptions(Options{
		Service: svc,
		PermissionedQuery: func(context.Context, protocol.QueryRequest) (PermissionedQueryResult, error) {
			callbackCalls++
			return PermissionedQueryResult{}, nil
		},
	})

	_, err := registry[NameQuery].InvokableRun(context.Background(), `{
		"question":"what is knote?",
		"authorization":{"principal_id":"tool-controlled"}
	}`)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("tool-supplied authorization should be rejected, err=%v", err)
	}
	if callbackCalls != 0 || svc.queryCalls != 0 {
		t.Fatalf("rejected tool authorization reached query path: callback=%d legacy=%d", callbackCalls, svc.queryCalls)
	}
}

func TestPermissionedQueryRequiresTrustedAuthorizationContext(t *testing.T) {
	svc := &fakeService{}
	callbackCalls := 0
	registry := ByNameWithOptions(Options{
		Service: svc,
		PermissionedQuery: func(context.Context, protocol.QueryRequest) (PermissionedQueryResult, error) {
			callbackCalls++
			return PermissionedQueryResult{}, nil
		},
	})

	for _, name := range []string{NameQuery, NameExplain} {
		_, err := registry[name].InvokableRun(context.Background(), `{"question":"why?"}`)
		if err == nil || !strings.Contains(err.Error(), "trusted authorization context") {
			t.Fatalf("%s should fail closed without trusted authorization, err=%v", name, err)
		}
	}
	if callbackCalls != 0 || svc.queryCalls != 0 || svc.explainCalls != 0 {
		t.Fatalf("missing authorization reached a query path: callback=%d query=%d explain=%d", callbackCalls, svc.queryCalls, svc.explainCalls)
	}
}

func TestQueryAndExplainUsePermissionedCallback(t *testing.T) {
	svc := &fakeService{}
	authorization := toolTestAuthorization()
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	evidence := protocol.EvidencePackage{
		Version:         protocol.SecurityContractVersion,
		TenantID:        authorization.TenantID,
		KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID:     authorization.PrincipalID,
		RequestID:       authorization.RequestID,
	}
	var requests []protocol.QueryRequest
	registry := ByNameWithOptions(Options{
		Service: svc,
		PermissionedQuery: func(_ context.Context, req protocol.QueryRequest) (PermissionedQueryResult, error) {
			requests = append(requests, req)
			return PermissionedQueryResult{
				Answer:          "permissioned: " + req.Question,
				Mode:            "authorized",
				EvidencePackage: evidence,
			}, nil
		},
	})

	for _, tc := range []struct {
		name     string
		question string
	}{
		{name: NameQuery, question: "what is knote?"},
		{name: NameExplain, question: "why?"},
	} {
		result := runJSONWithContext(t, ctx, registry[tc.name], `{"question":"`+tc.question+`"}`)
		if result["answer"] != "permissioned: "+tc.question || result["mode"] != "authorized" {
			t.Fatalf("unexpected %s result: %+v", tc.name, result)
		}
		packageJSON, ok := result["evidence_package"].(map[string]any)
		if !ok || packageJSON["tenant_id"] != authorization.TenantID || packageJSON["request_id"] != authorization.RequestID {
			t.Fatalf("%s did not return structured evidence package: %+v", tc.name, result)
		}
	}
	if len(requests) != 2 {
		t.Fatalf("permissioned callback calls = %d, want 2", len(requests))
	}
	for _, req := range requests {
		if req.Authorization != authorization {
			t.Fatalf("callback authorization = %+v, want trusted context %+v", req.Authorization, authorization)
		}
	}
	if svc.queryCalls != 0 || svc.explainCalls != 0 {
		t.Fatalf("permissioned tools called legacy service: query=%d explain=%d", svc.queryCalls, svc.explainCalls)
	}
}

func TestAuthorizationDecoratorGatesQueryAndExplainResults(t *testing.T) {
	svc := &fakeService{}
	authorization := toolTestAuthorization()
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	gate := &recordingAuthorizationGate{
		digest: "tool_manifest_00000000000000000000000000000001",
		obligations: map[string]protocol.ToolReturnObligation{
			NameQuery:   protocol.ToolReturnEvidence,
			NameExplain: protocol.ToolReturnEvidence,
		},
	}
	evidence := protocol.EvidencePackage{
		Version:         protocol.SecurityContractVersion,
		TenantID:        authorization.TenantID,
		KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID:     authorization.PrincipalID,
		RequestID:       authorization.RequestID,
	}
	registry := ByNameWithOptions(Options{
		Service:           svc,
		AuthorizationGate: gate,
		PermissionedQuery: func(_ context.Context, req protocol.QueryRequest) (PermissionedQueryResult, error) {
			return PermissionedQueryResult{
				Answer:          "permissioned: " + req.Question,
				Mode:            "authorized",
				EvidencePackage: evidence,
			}, nil
		},
	})

	for _, tc := range []struct {
		name     string
		question string
	}{
		{name: NameQuery, question: "what is knote?"},
		{name: NameExplain, question: "why?"},
	} {
		result := runJSONWithContext(t, ctx, registry[tc.name], `{"question":"`+tc.question+`"}`)
		if result["answer"] != "permissioned: "+tc.question {
			t.Fatalf("unexpected %s result: %+v", tc.name, result)
		}
		authorizationJSON, ok := result["tool_authorization"].(map[string]any)
		if !ok || authorizationJSON["manifest_digest"] != gate.digest {
			t.Fatalf("%s result lacks the authorization envelope: %+v", tc.name, result)
		}
		invocationJSON, ok := authorizationJSON["invocation"].(map[string]any)
		if !ok || invocationJSON["tool_name"] != tc.name {
			t.Fatalf("%s envelope does not identify the invocation: %+v", tc.name, authorizationJSON)
		}
	}
	if got, want := strings.Join(gate.invocationCalls, ","), NameQuery+","+NameExplain; got != want {
		t.Fatalf("invocation gate calls = %q, want %q", got, want)
	}
	if len(gate.evidenceCalls) != 2 {
		t.Fatalf("evidence result gate calls = %d, want 2", len(gate.evidenceCalls))
	}
	for _, result := range gate.evidenceCalls {
		if result.TenantID != authorization.TenantID || result.RequestID != authorization.RequestID {
			t.Fatalf("result gate received the wrong evidence package: %+v", result)
		}
	}
}

func TestAuthorizationDecoratorExposesManifestDigest(t *testing.T) {
	const digest = "tool_manifest_00000000000000000000000000000002"
	gate := &recordingAuthorizationGate{digest: digest}
	for name, tool := range ByNameWithOptions(Options{Service: &fakeService{}, AuthorizationGate: gate}) {
		marker, ok := tool.(interface {
			ToolAuthorizationManifestDigest() string
		})
		if !ok {
			t.Fatalf("%s is missing the tool authorization marker", name)
		}
		if got := marker.ToolAuthorizationManifestDigest(); got != digest {
			t.Fatalf("%s manifest digest = %q, want %q", name, got, digest)
		}
	}
	if _, ok := ByName(&fakeService{})[NameQuery].(interface {
		ToolAuthorizationManifestDigest() string
	}); ok {
		t.Fatal("tool without an authorization gate was unexpectedly decorated")
	}
}

func TestAuthorizationDecoratorRequiresTrustedContext(t *testing.T) {
	svc := &fakeService{}
	gate := &recordingAuthorizationGate{
		digest: "tool_manifest_00000000000000000000000000000003",
		obligations: map[string]protocol.ToolReturnObligation{
			NameQuery: protocol.ToolReturnEvidence,
		},
	}
	tool := ByNameWithOptions(Options{Service: svc, AuthorizationGate: gate})[NameQuery]

	output, err := tool.InvokableRun(context.Background(), `{"question":"restricted"}`)
	if output != "" || err == nil || err.Error() != "tool authorization denied" {
		t.Fatalf("missing trusted context output=%q err=%v", output, err)
	}
	if len(gate.invocationCalls) != 0 || svc.queryCalls != 0 {
		t.Fatalf("missing trusted context reached authorization or content: gate=%d query=%d", len(gate.invocationCalls), svc.queryCalls)
	}
}

func TestAuthorizationDecoratorPreGatesBuildAndGitSideEffects(t *testing.T) {
	ctx, err := protocol.WithAuthorizationContext(context.Background(), toolTestAuthorization())
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	for _, tc := range []struct {
		name string
		args string
	}{
		{name: NameBuild, args: `{}`},
		{name: NameCommit, args: `{"message":"restricted update"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeService{}
			confirmationCalls := 0
			gate := &recordingAuthorizationGate{
				digest:          "tool_manifest_00000000000000000000000000000004",
				denyInvocations: map[string]bool{tc.name: true},
			}
			tool := ByNameWithOptions(Options{
				Service:           svc,
				AuthorizationGate: gate,
				SideEffectGate: func(context.Context, SideEffectRequest) error {
					confirmationCalls++
					return nil
				},
			})[tc.name]

			output, err := tool.InvokableRun(ctx, tc.args)
			if output != "" || err == nil || err.Error() != "tool authorization denied" {
				t.Fatalf("denied side effect output=%q err=%v", output, err)
			}
			if confirmationCalls != 0 {
				t.Fatalf("authorization denial reached confirmation %d times", confirmationCalls)
			}
			if svc.buildCalled || svc.commitMessage != "" {
				t.Fatalf("authorization denial reached side effects: %+v", svc)
			}
			if got := strings.Join(gate.invocationCalls, ","); got != tc.name {
				t.Fatalf("invocation gate calls = %q, want %q", got, tc.name)
			}
		})
	}
}

func TestAuthorizationDecoratorPreservesSideEffectPendingError(t *testing.T) {
	wantErr := errors.New("side effect pending")
	svc := &fakeService{}
	gate := &recordingAuthorizationGate{
		digest: "tool_manifest_00000000000000000000000000000005",
		obligations: map[string]protocol.ToolReturnObligation{
			NameBuild: protocol.ToolReturnNone,
		},
	}
	ctx, err := protocol.WithAuthorizationContext(context.Background(), toolTestAuthorization())
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	tool := ByNameWithOptions(Options{
		Service:           svc,
		AuthorizationGate: gate,
		SideEffectGate: func(context.Context, SideEffectRequest) error {
			return wantErr
		},
	})[NameBuild]

	output, err := tool.InvokableRun(ctx, `{}`)
	if output != "" || !errors.Is(err, wantErr) {
		t.Fatalf("pending side effect output=%q err=%v, want %v", output, err, wantErr)
	}
	if svc.buildCalled || len(gate.contentFreeCalls) != 0 {
		t.Fatalf("pending side effect reached action or result gate: service=%+v result_calls=%d", svc, len(gate.contentFreeCalls))
	}
}

func TestAuthorizationDecoratorSuppressesDeniedResultPayload(t *testing.T) {
	const secret = "private result payload"
	authorization := toolTestAuthorization()
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	gate := &recordingAuthorizationGate{
		digest:     "tool_manifest_00000000000000000000000000000006",
		denyResult: true,
		obligations: map[string]protocol.ToolReturnObligation{
			NameQuery: protocol.ToolReturnEvidence,
		},
	}
	callbackCalls := 0
	tool := ByNameWithOptions(Options{
		Service:           &fakeService{},
		AuthorizationGate: gate,
		PermissionedQuery: func(context.Context, protocol.QueryRequest) (PermissionedQueryResult, error) {
			callbackCalls++
			return PermissionedQueryResult{
				Answer: secret,
				EvidencePackage: protocol.EvidencePackage{
					Version: protocol.SecurityContractVersion, TenantID: authorization.TenantID,
					KnowledgeBaseID: authorization.KnowledgeBaseID, PrincipalID: authorization.PrincipalID,
					RequestID: authorization.RequestID,
				},
			}, nil
		},
	})[NameQuery]

	output, err := tool.InvokableRun(ctx, `{"question":"restricted"}`)
	if output != "" || err == nil || err.Error() != "tool authorization denied" {
		t.Fatalf("denied result output=%q err=%v", output, err)
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), secret) {
		t.Fatalf("denied result leaked protected payload: %v", err)
	}
	if callbackCalls != 1 || len(gate.evidenceCalls) != 1 {
		t.Fatalf("result path calls callback=%d result_gate=%d", callbackCalls, len(gate.evidenceCalls))
	}
}

func TestAuthorizationDecoratorFailsClosedForMalformedResourceOutput(t *testing.T) {
	svc := &fakeService{}
	gate := &recordingAuthorizationGate{
		digest: "tool_manifest_00000000000000000000000000000007",
		obligations: map[string]protocol.ToolReturnObligation{
			NameQuery: protocol.ToolReturnResources,
		},
	}
	ctx, err := protocol.WithAuthorizationContext(context.Background(), toolTestAuthorization())
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	tool := ByNameWithOptions(Options{Service: svc, AuthorizationGate: gate})[NameQuery]

	output, err := tool.InvokableRun(ctx, `{"question":"where are the resources?"}`)
	if output != "" || err == nil || err.Error() != "tool authorization denied" {
		t.Fatalf("malformed resource result output=%q err=%v", output, err)
	}
	if svc.queryCalls != 1 || len(gate.resourceCalls) != 0 {
		t.Fatalf("malformed typed result calls query=%d resource_gate=%d", svc.queryCalls, len(gate.resourceCalls))
	}
}

func TestPermissionedCallbackErrorsDoNotFallBackToLegacyService(t *testing.T) {
	svc := &fakeService{}
	ctx, err := protocol.WithAuthorizationContext(context.Background(), toolTestAuthorization())
	if err != nil {
		t.Fatalf("bind authorization context: %v", err)
	}
	wantErr := errors.New("permission denied")
	registry := ByNameWithOptions(Options{
		Service: svc,
		PermissionedQuery: func(context.Context, protocol.QueryRequest) (PermissionedQueryResult, error) {
			return PermissionedQueryResult{}, wantErr
		},
	})

	for _, name := range []string{NameQuery, NameExplain} {
		_, err := registry[name].InvokableRun(ctx, `{"question":"restricted"}`)
		if !errors.Is(err, wantErr) {
			t.Fatalf("%s error = %v, want %v", name, err, wantErr)
		}
	}
	if svc.queryCalls != 0 || svc.explainCalls != 0 {
		t.Fatalf("callback error fell back to legacy service: query=%d explain=%d", svc.queryCalls, svc.explainCalls)
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
	return runJSONWithContext(t, context.Background(), tool, args)
}

func runJSONWithContext(t *testing.T, ctx context.Context, tool einotool.InvokableTool, args string) map[string]any {
	t.Helper()
	out, err := tool.InvokableRun(ctx, args)
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
	queryCalls      int
	queryQuestion   string
	explainCalls    int
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
	s.queryCalls++
	s.queryQuestion = question
	return versioned.Answer{
		Answer:   "query: " + question,
		Evidence: []string{"source"},
		Mode:     "fake",
	}, nil
}

func (s *fakeService) Explain(_ context.Context, question string) (versioned.Explanation, error) {
	s.explainCalls++
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

func toolTestAuthorization() protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:                   protocol.SecurityContractVersion,
		TenantID:                  "local",
		KnowledgeBaseID:           "default",
		PrincipalID:               "local-user",
		SessionID:                 "session-1",
		RequestID:                 "request-1",
		AgentID:                   "agent-1",
		TaskID:                    "task-1",
		DelegationWatermark:       "delegation-v1",
		AgentTaskScopeFingerprint: "scope_00000000000000000000000000000001",
		AuthorizationModelID:      "local-v1",
		IdentityWatermark:         "identity-v1",
		ACLWatermark:              "acl-v1",
		Consistency:               protocol.ConsistencyHigherConsistency,
	}
}

type recordingAuthorizationGate struct {
	digest           string
	obligations      map[string]protocol.ToolReturnObligation
	denyInvocations  map[string]bool
	denyResult       bool
	invocationCalls  []string
	evidenceCalls    []protocol.EvidencePackage
	resourceCalls    [][]protocol.ProtectedResourceBinding
	contentFreeCalls []string
}

func (g *recordingAuthorizationGate) ManifestDigest() string {
	return g.digest
}

func (g *recordingAuthorizationGate) AuthorizeInvocation(
	_ context.Context,
	_ protocol.AuthorizationContext,
	toolName string,
) (protocol.ToolInvocationAuthorization, error) {
	g.invocationCalls = append(g.invocationCalls, toolName)
	if g.denyInvocations[toolName] {
		return protocol.ToolInvocationAuthorization{}, errors.New("private invocation denial")
	}
	obligation, ok := g.obligations[toolName]
	if !ok {
		return protocol.ToolInvocationAuthorization{}, errors.New("unregistered tool")
	}
	return protocol.ToolInvocationAuthorization{
		Version:          protocol.ToolAuthorizationContractVersion,
		CorrelationID:    "correlation-" + toolName,
		ToolName:         toolName,
		ReturnObligation: obligation,
	}, nil
}

func (g *recordingAuthorizationGate) AuthorizeEvidenceResult(
	_ context.Context,
	_ protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	evidence protocol.EvidencePackage,
) (protocol.ToolAuthorizationEnvelope, error) {
	g.evidenceCalls = append(g.evidenceCalls, evidence)
	if g.denyResult {
		return protocol.ToolAuthorizationEnvelope{}, errors.New("private result denial")
	}
	return g.envelope(invocation), nil
}

func (g *recordingAuthorizationGate) AuthorizeResourceResult(
	_ context.Context,
	_ protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	resources []protocol.ProtectedResourceBinding,
) (protocol.ToolAuthorizationEnvelope, error) {
	g.resourceCalls = append(g.resourceCalls, append([]protocol.ProtectedResourceBinding(nil), resources...))
	if g.denyResult {
		return protocol.ToolAuthorizationEnvelope{}, errors.New("private resource denial")
	}
	return g.envelope(invocation), nil
}

func (g *recordingAuthorizationGate) AuthorizeContentFreeResult(
	_ context.Context,
	_ protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
) (protocol.ToolAuthorizationEnvelope, error) {
	g.contentFreeCalls = append(g.contentFreeCalls, invocation.ToolName)
	if g.denyResult {
		return protocol.ToolAuthorizationEnvelope{}, errors.New("private content-free denial")
	}
	return g.envelope(invocation), nil
}

func (g *recordingAuthorizationGate) envelope(invocation protocol.ToolInvocationAuthorization) protocol.ToolAuthorizationEnvelope {
	return protocol.ToolAuthorizationEnvelope{
		Version:        protocol.ToolAuthorizationContractVersion,
		ManifestDigest: g.digest,
		Invocation:     invocation,
		Result: protocol.ToolResultAuthorization{
			Version:          protocol.ToolAuthorizationContractVersion,
			CorrelationID:    invocation.CorrelationID,
			ToolName:         invocation.ToolName,
			ReturnObligation: invocation.ReturnObligation,
		},
	}
}
