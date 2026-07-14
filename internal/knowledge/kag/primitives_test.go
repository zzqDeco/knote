package kag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	localrepo "github.com/zzqDeco/knote/internal/repository/local"
)

const (
	testResourceA        protocol.ResourceID = "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testResourceB        protocol.ResourceID = "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fakeIntroID          protocol.ResourceID = "res_00000000000000000000000000000001"
	fakeDeniedID         protocol.ResourceID = "res_00000000000000000000000000000002"
	fakeLocalID          protocol.ResourceID = "res_00000000000000000000000000000004"
	fakeFrontierDeniedID protocol.ResourceID = "res_00000000000000000000000000000005"
)

func TestPrimitiveClientActualFakeAdapterRoundTrip(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	client := Client{
		AdapterPath: filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   repoRoot,
		Fake:        true,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())

	retrieved, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testFakeAuthorizationContext(), Query: "What is knote?", Limit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	intro := candidateByID(t, retrieved.Candidates, fakeIntroID)
	if candidateByID(t, retrieved.Candidates, fakeDeniedID).Resource.ResourceID != fakeDeniedID {
		t.Fatal("fake fixture must expose a candidate for authorization filtering")
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testFakeAuthorizationContext(), Frontier: []CandidateHandle{intro}, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	local := candidateByID(t, expanded.Candidates, fakeLocalID)
	if candidateByID(t, expanded.Candidates, fakeFrontierDeniedID).Resource.ResourceID != fakeFrontierDeniedID {
		t.Fatal("fake fixture must expose a frontier candidate for per-hop filtering")
	}

	generated, err := client.Generate(context.Background(), GenerateRequest{
		Authorization: testFakeAuthorizationContext(),
		Question:      "What is knote?",
		Evidence: []AuthorizedEvidence{
			{Resource: intro.Resource, Content: "knote is local-first.", CitationHandle: "cite-intro"},
			{Resource: local.Resource, Content: "Its runtime can authorize graph stages before generation.", CitationHandle: "cite-local"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []protocol.ResourceID{fakeDeniedID, fakeFrontierDeniedID} {
		if bytes.Contains(data, []byte(denied)) {
			t.Fatalf("denied resource %s reached generation output: %s", denied, data)
		}
	}
}

func TestPrimitiveClientActualRealAdapterPermissionedRoundTrip(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
	graphObjectID, err := protocol.NewGraphObjectID(resource.Versions.Projection, resource.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	provider := writePrimitiveProvider(t, workspace, `
import os

class Provider:
    def retrieve(self, request):
        return {"candidates": [{"graph_object_id": os.environ["KNOTE_TEST_GRAPH_ID"], "score": 0.9}]}

    def generate(self, request):
        if [item["content"] for item in request["evidence"]] != ["allowed body"]:
            raise RuntimeError("unexpected evidence")
        return {"answer": "authorized real answer"}

def create(context):
    return Provider()
`)
	client := Client{
		AdapterPath:          filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:            workspace,
		Fake:                 false,
		PermissionedProvider: provider,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	t.Setenv("KNOTE_KAG_PERMISSIONED_PROVIDER", "invalid_provider:create")
	t.Setenv("KNOTE_TEST_GRAPH_ID", string(graphObjectID))
	candidate := CandidateHandle{Resource: resource, Score: 0.9}
	evidence := AuthorizedEvidence{
		Resource: candidate.Resource, Content: "allowed body", CitationHandle: "citation-1",
	}

	retrieved, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if retrieved.Mode != "real" || len(retrieved.Candidates) != 1 || retrieved.Candidates[0].Resource != resource {
		t.Fatalf("unexpected real retrieve result: %+v", retrieved)
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testAuthorizationContext(), Frontier: []CandidateHandle{candidate}, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if expanded.Mode != "real" || len(expanded.Candidates) != 0 || len(expanded.Expansions) != 0 {
		t.Fatalf("unexpected empty real expansion result: %+v", expanded)
	}

	generated, err := client.Generate(context.Background(), GenerateRequest{
		Authorization: testAuthorizationContext(), Question: "knote", Evidence: []AuthorizedEvidence{evidence},
	})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Mode != "real" || generated.Answer != "authorized real answer" || len(generated.Citations) != 1 {
		t.Fatalf("unexpected real generation result: %+v", generated)
	}
}

func TestPrimitiveClientActualRealAdapterReturnsTypedProviderUnavailable(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	writePrimitiveGraphContract(t, workspace)
	client := Client{
		AdapterPath: filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   workspace,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	t.Setenv("KNOTE_KAG_PERMISSIONED_PROVIDER", "")
	_, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, ErrPrimitiveUnavailable) || !IsPrimitiveUnavailable(err) {
		t.Fatalf("provider-unavailable error = %T %v", err, err)
	}
}

func TestPrimitiveClientActualRealAdapterRejectsOversizedProviderScore(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
	graphObjectID, err := protocol.NewGraphObjectID(resource.Versions.Projection, resource.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	provider := writePrimitiveProvider(t, workspace, `
import os
class Provider:
    def retrieve(self, request):
        return {"candidates": [{"graph_object_id": os.environ["KNOTE_TEST_GRAPH_ID"], "score": 10**309}]}
def create(context):
    return Provider()
`)
	client := Client{
		AdapterPath:          filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:            workspace,
		PermissionedProvider: provider,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	t.Setenv("KNOTE_TEST_GRAPH_ID", string(graphObjectID))

	_, err = client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, ErrInvalidPrimitiveResponse) || !IsInvalidPrimitiveResponse(err) {
		t.Fatalf("oversized provider score error = %T %v", err, err)
	}
}

func TestPrimitiveClientActualRealProviderHonorsContextDeadline(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	writePrimitiveGraphContract(t, workspace)
	provider := writePrimitiveProvider(t, workspace, `
import time
class Provider:
    def retrieve(self, request):
        time.sleep(5)
        return {"candidates": []}
def create(context):
    return Provider()
`)
	client := Client{
		AdapterPath:          filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:            workspace,
		PermissionedProvider: provider,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := client.Retrieve(ctx, RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("actual provider deadline error = %T %v", err, err)
	}
}

func TestPrimitiveClientActualRealProviderStopsAfterCancellation(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	writePrimitiveGraphContract(t, workspace)
	provider := writePrimitiveProvider(t, workspace, `
import os
import subprocess
import sys
import time
class Provider:
    def retrieve(self, request):
        if hasattr(os, "setsid"):
            try:
                os.setsid()
            except OSError:
                pass
        subprocess.Popen([
            sys.executable,
            "-c",
            "import os,time; time.sleep(0.25); open(os.environ['KNOTE_PROVIDER_COMPLETED'], 'w', encoding='utf-8').write('completed')",
        ], close_fds=True)
        with open(os.environ["KNOTE_PROVIDER_STARTED"], "w", encoding="utf-8") as stream:
            stream.write("started")
        time.sleep(5)
        return {"candidates": []}
def create(context):
    return Provider()
`)
	started := filepath.Join(workspace, "provider-started")
	completed := filepath.Join(workspace, "provider-completed")
	t.Setenv("KNOTE_PROVIDER_STARTED", started)
	t.Setenv("KNOTE_PROVIDER_COMPLETED", completed)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	client := Client{
		AdapterPath:          filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:            workspace,
		PermissionedProvider: provider,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Retrieve(ctx, RetrieveRequest{
			Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
		})
		result <- err
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("provider did not start before cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("actual provider cancellation error = %T %v", err, err)
	}
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(completed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("provider completed side effects after cancellation: %v", err)
	}
}

func TestPrimitiveClientActualRealAdapterRejectsMissingGraphContractBeforeKAGSetup(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	client := Client{
		AdapterPath: filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   t.TempDir(),
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	_, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, ErrInvalidGraphBinding) {
		t.Fatalf("missing graph contract error = %T %v", err, err)
	}
}

func TestPrimitiveClientRoundTrip(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, `
import hashlib, json, sys
req = json.loads(sys.stdin.readline())
method = req["method"]
params = req["params"]
a = "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
b = "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
def resource(resource_id):
    return {"resource_id": resource_id, "type": "document", "tenant_id": "local", "knowledge_base_id": "default", "authz_object": "document:" + resource_id, "authorization_resource_id": resource_id, "content_digest": "sha256:" + hashlib.sha256(b"allowed body").hexdigest(), "versions": {"source": "source-v1", "content": "content-v1", "acl": "acl-v1", "index": "index-v1", "graph": "graph-v1", "projection": "projection-v1"}, "serving_state": "serving"}
candidate = {"resource": resource(a), "score": 0.9}
if method == "kag.retrieve":
    data = {"mode": "fake", "candidates": [candidate]}
elif method == "kag.expand":
    target = {"resource": resource(b), "score": 0.8}
    data = {"mode": "fake", "candidates": [target], "expansions": [{"from_resource_id": params["frontier"][0]["resource"]["resource_id"], "to_resource_id": b, "hop": 1}]}
elif method == "kag.generate":
    evidence = params["evidence"]
    ids = [item["resource"]["resource_id"] for item in evidence]
    data = {"mode": "fake", "answer": "authorized answer", "citations": [{"handle": evidence[0]["citation_handle"], "resource_id": ids[0]}], "evidence_resource_ids": ids, "trace": {"resource_ids": ids, "count": len(ids)}}
else:
    raise RuntimeError(method)
print(json.dumps({"id": req["id"], "type": "result", "data": data}))
`)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}

	retrieved, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(retrieved.Candidates) != 1 || retrieved.Candidates[0].Resource.ResourceID != testResourceA {
		t.Fatalf("unexpected retrieve result: %#v", retrieved)
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testAuthorizationContext(), Frontier: retrieved.Candidates, Limit: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded.Expansions) != 1 || expanded.Expansions[0].ToResourceID != testResourceB {
		t.Fatalf("unexpected expand result: %#v", expanded)
	}

	generated, err := client.Generate(context.Background(), GenerateRequest{
		Authorization: testAuthorizationContext(),
		Question:      "knote",
		Evidence: []AuthorizedEvidence{{
			Resource: testPrimitiveResource(testResourceA), Content: "allowed body", CitationHandle: "citation-1",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Answer != "authorized answer" || len(generated.Citations) != 1 {
		t.Fatalf("unexpected generate result: %#v", generated)
	}
}

func TestExpandRejectsForeignFrontierSource(t *testing.T) {
	req := ExpandRequest{
		Authorization: testAuthorizationContext(),
		Frontier:      []CandidateHandle{{Resource: testPrimitiveResource(testResourceA), Score: 0.9}},
		Limit:         10,
	}
	result := ExpandResult{
		Mode:       "fake",
		Candidates: []CandidateHandle{{Resource: testPrimitiveResource(testResourceB), Score: 0.8}},
		Expansions: []ExpansionHandle{{FromResourceID: testResourceB, ToResourceID: testResourceB, Hop: 1}},
	}
	if err := result.ValidateFor(req); err == nil {
		t.Fatal("foreign frontier source should fail")
	}
}

func TestPrimitiveRequestsRequireTrustedAuthorizationBeforeAdapterExecution(t *testing.T) {
	candidate := CandidateHandle{Resource: testPrimitiveResource(testResourceA), Score: 0.9}
	evidence := AuthorizedEvidence{
		Resource: candidate.Resource, Content: "allowed body", CitationHandle: "citation-1",
	}
	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "retrieve",
			call: func() error {
				_, err := (Client{}).Retrieve(context.Background(), RetrieveRequest{Query: "knote", Limit: 10})
				return err
			},
		},
		{
			name: "expand",
			call: func() error {
				_, err := (Client{}).Expand(context.Background(), ExpandRequest{
					Frontier: []CandidateHandle{candidate}, Limit: 10,
				})
				return err
			},
		},
		{
			name: "generate",
			call: func() error {
				_, err := (Client{}).Generate(context.Background(), GenerateRequest{
					Question: "knote", Evidence: []AuthorizedEvidence{evidence},
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), "authorization:") {
				t.Fatalf("request should fail authorization validation before adapter execution, got %v", err)
			}
		})
	}
}

func TestPrimitiveResourceScopeFailsClosed(t *testing.T) {
	auth := testAuthorizationContext()
	foreignTenant := testPrimitiveResource(testResourceA)
	foreignTenant.TenantID = "other-tenant"
	foreignKnowledgeBase := testPrimitiveResource(testResourceA)
	foreignKnowledgeBase.KnowledgeBaseID = "other-kb"

	for name, resource := range map[string]protocol.ResourceHandle{
		"foreign tenant":         foreignTenant,
		"foreign knowledge base": foreignKnowledgeBase,
	} {
		t.Run("retrieve candidate "+name, func(t *testing.T) {
			result := RetrieveResult{
				Mode: "fake", Candidates: []CandidateHandle{{Resource: resource, Score: 0.9}},
			}
			if err := result.ValidateFor(RetrieveRequest{
				Authorization: auth, Query: "knote", Limit: 10,
			}); err == nil {
				t.Fatal("out-of-scope retrieve candidate should fail")
			}
		})

		t.Run("expand frontier "+name, func(t *testing.T) {
			req := ExpandRequest{
				Authorization: auth,
				Frontier:      []CandidateHandle{{Resource: resource, Score: 0.9}},
				Limit:         10,
			}
			if err := req.Validate(); err == nil {
				t.Fatal("out-of-scope authorized frontier should fail")
			}
		})

		t.Run("expand candidate "+name, func(t *testing.T) {
			frontier := testPrimitiveResource(testResourceA)
			target := resource
			target.ResourceID = testResourceB
			target.AuthorizationResourceID = testResourceB
			target.AuthorizationID = "document:" + string(testResourceB)
			result := ExpandResult{
				Mode:       "fake",
				Candidates: []CandidateHandle{{Resource: target, Score: 0.8}},
				Expansions: []ExpansionHandle{{FromResourceID: testResourceA, ToResourceID: testResourceB, Hop: 1}},
			}
			if err := result.ValidateFor(ExpandRequest{
				Authorization: auth,
				Frontier:      []CandidateHandle{{Resource: frontier, Score: 0.9}},
				Limit:         10,
			}); err == nil {
				t.Fatal("out-of-scope expansion candidate should fail")
			}
		})

		t.Run("generate evidence "+name, func(t *testing.T) {
			req := GenerateRequest{
				Authorization: auth,
				Question:      "knote",
				Evidence: []AuthorizedEvidence{{
					Resource: resource, Content: "allowed body", CitationHandle: "citation-1",
				}},
			}
			if err := req.Validate(); err == nil {
				t.Fatal("out-of-scope generation evidence should fail")
			}
		})
	}
}

func TestExpandBindsCandidatesToAuthorizedFrontierProjection(t *testing.T) {
	frontier := testPrimitiveResource(testResourceA)
	target := testPrimitiveResource(testResourceB)
	target.Versions.Projection = "projection-v2"
	req := ExpandRequest{
		Authorization: testAuthorizationContext(),
		Frontier:      []CandidateHandle{{Resource: frontier, Score: 0.9}},
		Limit:         10,
	}
	result := ExpandResult{
		Mode:       "fake",
		Candidates: []CandidateHandle{{Resource: target, Score: 0.8}},
		Expansions: []ExpansionHandle{{FromResourceID: testResourceA, ToResourceID: testResourceB, Hop: 1}},
	}
	if err := result.ValidateFor(req); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Fatalf("cross-projection expansion candidate should fail, got %v", err)
	}
}

func TestPrimitiveRequestsRejectMixedProjectionSets(t *testing.T) {
	auth := testAuthorizationContext()
	first := testPrimitiveResource(testResourceA)
	second := testPrimitiveResource(testResourceB)
	second.Versions.Projection = "projection-v2"

	retrieve := RetrieveResult{
		Mode: "fake",
		Candidates: []CandidateHandle{
			{Resource: first, Score: 0.9},
			{Resource: second, Score: 0.8},
		},
	}
	if err := retrieve.ValidateFor(RetrieveRequest{
		Authorization: auth, Query: "knote", Limit: 10,
	}); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Fatalf("mixed-projection retrieve candidates should fail, got %v", err)
	}

	expand := ExpandRequest{
		Authorization: auth,
		Frontier: []CandidateHandle{
			{Resource: first, Score: 0.9},
			{Resource: second, Score: 0.8},
		},
		Limit: 10,
	}
	if err := expand.Validate(); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Fatalf("mixed-projection expansion frontier should fail, got %v", err)
	}

	generate := GenerateRequest{
		Authorization: auth,
		Question:      "knote",
		Evidence: []AuthorizedEvidence{
			{Resource: first, Content: "allowed body", CitationHandle: "citation-1"},
			{Resource: second, Content: "allowed body", CitationHandle: "citation-2"},
		},
	}
	if err := generate.Validate(); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Fatalf("mixed-projection generation evidence should fail, got %v", err)
	}
}

func TestPrimitiveDecodeRejectsUnknownLeakFields(t *testing.T) {
	resource, err := structParams(testPrimitiveResource(testResourceA))
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Type: "result", Data: map[string]any{
		"mode": "fake",
		"candidates": []any{map[string]any{
			"resource": resource,
			"score":    0.9,
			"body":     "protected body must not be silently discarded",
		}},
	}}
	if _, err := decodePrimitive[RetrieveResult](response); err == nil {
		t.Fatal("unknown candidate body should fail strict primitive decoding")
	}
}

func TestPrimitiveDecodeRejectsNonResultFrame(t *testing.T) {
	response := Response{Type: "progress", Data: map[string]any{
		"mode":       "fake",
		"candidates": []any{},
	}}
	if _, err := decodePrimitive[RetrieveResult](response); err == nil {
		t.Fatal("progress data must not decode as a terminal primitive result")
	}
}

func TestPrimitiveClientRejectsTopLevelLeakFields(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, `
import hashlib, json, sys
req = json.loads(sys.stdin.readline())
resource_id = "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
resource = {"resource_id": resource_id, "type": "document", "tenant_id": "local", "knowledge_base_id": "default", "authz_object": "document:" + resource_id, "authorization_resource_id": resource_id, "content_digest": "sha256:" + hashlib.sha256(b"allowed body").hexdigest(), "versions": {"source": "source-v1", "content": "content-v1", "acl": "acl-v1", "index": "index-v1", "graph": "graph-v1", "projection": "projection-v1"}, "serving_state": "serving"}
data = {"mode": "fake", "candidates": [{"resource": resource, "score": 0.9}]}
print(json.dumps({"id": req["id"], "type": "result", "message": "protected body", "debug": {"trace": "protected body"}, "data": data}))
`)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}

	if _, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 40,
	}); err == nil {
		t.Fatal("primitive result with top-level leak fields should fail strict frame decoding")
	}
}

func TestPrimitiveDecodeRejectsTopLevelMessage(t *testing.T) {
	var response Response
	if err := json.Unmarshal([]byte(`{"id":"req","type":"result","message":"protected body","data":{"mode":"fake","candidates":[]}}`), &response); err != nil {
		t.Fatal(err)
	}
	if _, err := decodePrimitive[RetrieveResult](response); err == nil {
		t.Fatal("primitive result with a non-empty top-level message should fail strict frame decoding")
	}
}

func TestPrimitiveDecodeRejectsTrailingJSON(t *testing.T) {
	response := Response{
		Type: "result",
		raw:  []byte(`{"id":"req","type":"result","data":{"mode":"fake","candidates":[]}} {"leak":true}`),
	}
	if _, err := decodePrimitive[RetrieveResult](response); err == nil {
		t.Fatal("trailing JSON must fail strict primitive decoding")
	}
}

func TestGenerateRejectsForeignCitationAndTrace(t *testing.T) {
	req := GenerateRequest{
		Authorization: testAuthorizationContext(),
		Question:      "knote",
		Evidence: []AuthorizedEvidence{{
			Resource: testPrimitiveResource(testResourceA), Content: "allowed body", CitationHandle: "citation-1",
		}},
	}
	result := GenerateResult{
		Mode:                "fake",
		Answer:              "injected answer",
		Citations:           []CitationHandle{{Handle: "citation-foreign", ResourceID: testResourceB}},
		EvidenceResourceIDs: []protocol.ResourceID{testResourceB},
		Trace:               GenerationTrace{ResourceIDs: []protocol.ResourceID{testResourceB}, Count: 1},
	}
	if err := result.ValidateFor(req); err == nil {
		t.Fatal("foreign generation references should fail")
	}
}

func TestPrimitiveClientReturnsTypedUnsupportedError(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, `
import json, sys
req = json.loads(sys.stdin.readline())
print(json.dumps({"id": req["id"], "type": "error", "code": "unsupported_primitive", "error": "real primitive is unavailable"}))
`)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}

	_, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if err == nil {
		t.Fatal("unsupported primitive should fail")
	}
	if !errors.Is(err, ErrUnsupportedPrimitive) || !IsUnsupportedPrimitive(err) {
		t.Fatalf("expected typed unsupported primitive error, got %T: %v", err, err)
	}
}

func TestPrimitiveClientReturnsTypedInvalidPrimitiveResponseError(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, `
import json, sys
req = json.loads(sys.stdin.readline())
print(json.dumps({"id": req["id"], "type": "error", "code": "invalid_primitive_response", "error": "permissioned primitive provider returned an invalid response"}))
`)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}

	_, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, ErrInvalidPrimitiveResponse) || !IsInvalidPrimitiveResponse(err) {
		t.Fatalf("expected typed invalid primitive response error, got %T: %v", err, err)
	}
}

func TestPrimitiveResultsRequireMode(t *testing.T) {
	result := RetrieveResult{}
	if err := result.ValidateFor(RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	}); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("missing primitive mode should fail, got %v", err)
	}
}

func TestPrimitiveClientCancellationReturnsContextError(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, "import time\ntime.sleep(5)\n")
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := client.Retrieve(ctx, RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %T: %v", err, err)
	}
}

func TestPrimitiveClientDeadlineReturnsContextError(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, "import time\ntime.sleep(5)\n")
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := client.Retrieve(ctx, RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %T: %v", err, err)
	}
}

func TestPrimitiveClientContextErrorWinsAfterAdapterError(t *testing.T) {
	workspace := t.TempDir()
	adapter := writePrimitiveAdapter(t, workspace, `
import json, sys, time
req = json.loads(sys.stdin.readline())
print(json.dumps({"id": req["id"], "type": "error", "code": "unsupported_primitive", "error": "early adapter error"}), flush=True)
time.sleep(5)
`)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	client := Client{AdapterPath: adapter, Workspace: workspace}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := client.Retrieve(ctx, RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "knote", Limit: 10,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("context deadline should take precedence over an early adapter error, got %T: %v", err, err)
	}
}

func TestPrimitiveRequestsFailClosedBeforeAdapterExecution(t *testing.T) {
	client := Client{}
	if _, err := client.Retrieve(context.Background(), RetrieveRequest{
		Authorization: testAuthorizationContext(), Query: "", Limit: 10,
	}); err == nil {
		t.Fatal("empty query should fail")
	}
	if _, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testAuthorizationContext(), Limit: 10,
	}); err == nil {
		t.Fatal("empty authorized frontier should fail")
	}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Authorization: testAuthorizationContext(), Question: "knote",
	}); err == nil {
		t.Fatal("empty authorized evidence should fail")
	}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Authorization: testAuthorizationContext(),
		Question:      "knote",
		Evidence: []AuthorizedEvidence{{
			Resource: testPrimitiveResource(testResourceA), Content: "wrong body", CitationHandle: "citation-1",
		}},
	}); err == nil {
		t.Fatal("evidence body not bound to its resource digest should fail before adapter execution")
	}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Authorization: testAuthorizationContext(),
		Question:      "knote",
		Evidence: []AuthorizedEvidence{
			{Resource: testPrimitiveResource(testResourceA), Content: "allowed body", CitationHandle: "citation-1"},
			{Resource: testPrimitiveResource(testResourceB), Content: "allowed body", CitationHandle: "citation-1"},
		},
	}); err == nil {
		t.Fatal("duplicate citation handles should fail before adapter execution")
	}
}

func testPrimitiveResource(resourceID protocol.ResourceID) protocol.ResourceHandle {
	return protocol.ResourceHandle{
		ResourceID: resourceID, Type: protocol.ResourceDocument, TenantID: "local", KnowledgeBaseID: "default",
		AuthorizationID: "document:" + string(resourceID), AuthorizationResourceID: resourceID,
		ContentDigest: protocol.NewContentDigest("allowed body"),
		ServingState:  protocol.ServingActive,
		Versions: protocol.ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
			Index: "index-v1", Graph: "graph-v1", Projection: "projection-v1",
		},
	}
}

func testAuthorizationContext() protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:              protocol.SecurityContractVersion,
		TenantID:             "local",
		KnowledgeBaseID:      "default",
		PrincipalID:          "local-user",
		SessionID:            "session-1",
		RequestID:            "request-1",
		AgentID:              "agent-1",
		TaskID:               "task-1",
		AuthorizationModelID: "local-v1",
		IdentityWatermark:    "identity-v1",
		ACLWatermark:         "acl-v1",
		Consistency:          protocol.ConsistencyHigherConsistency,
	}
}

func testFakeAuthorizationContext() protocol.AuthorizationContext {
	authorization := testAuthorizationContext()
	authorization.TenantID = "tenant_fake"
	authorization.KnowledgeBaseID = "kb_fake"
	return authorization
}

func candidateByID(t *testing.T, candidates []CandidateHandle, resourceID protocol.ResourceID) CandidateHandle {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.Resource.ResourceID == resourceID {
			return candidate
		}
	}
	t.Fatalf("candidate %s was not returned", resourceID)
	return CandidateHandle{}
}

func primitiveTestRepoRoot(t *testing.T) string {
	t.Helper()
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(packageDir, "..", "..", ".."))
}

func writePrimitiveGraphContract(t *testing.T, workspace string) protocol.ResourceHandle {
	t.Helper()
	projectionID := "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	generatedAt := time.Unix(0, 0).UTC()
	resource := testPrimitiveResource(testResourceA)
	resource.Versions.Index = "index_" + projectionID
	resource.Versions.Graph = "graph_" + projectionID
	resource.Versions.Projection = projectionID
	binding, err := protocol.NewGraphResourceBinding(resource)
	if err != nil {
		t.Fatal(err)
	}
	manifest := protocol.ArtifactManifest{
		Version: 1, Workspace: "default", GeneratedAt: generatedAt, SourceCount: 1, DocumentCount: 1,
	}
	set := repository.ArtifactSet{
		Manifest: manifest, GraphBindings: []protocol.GraphResourceBinding{binding},
		ClaimBindings:  []protocol.ClaimTripleBinding{},
		BuildReport:    "# graph contract\n",
		ProjectionJSON: []byte("{\"version\":\"" + projectionID + "\"}\n"), ProjectionResourceCount: 1,
		BundleManifest: protocol.ArtifactBundleManifest{
			Version: protocol.ArtifactBundleManifestVersion, ProjectionID: projectionID, ProjectionVersion: projectionID,
			Namespace: "KnoteKB__" + projectionID, AuthorizationObject: "knowledge-base:default",
			AuthorizationVersion: "acl-v1", GraphBindingContractVersion: protocol.GraphBindingContractVersion,
			SourceSnapshot: protocol.ArtifactSourceSnapshot{
				Version: "source-v1", Digest: strings.Repeat("a", 64), DocumentCount: 1,
			},
			GeneratedAt: generatedAt, Compatibility: manifest,
		},
	}
	payloads, err := repository.CanonicalArtifactFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	set.BundleManifest.Files = repository.ArtifactFileDescriptors(payloads)
	if err := localrepo.New(workspace).WriteArtifacts(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	return resource
}

func writePrimitiveAdapter(t *testing.T, workspace, script string) string {
	t.Helper()
	path := filepath.Join(workspace, "adapter.py")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePrimitiveProvider(t *testing.T, workspace, script string) string {
	t.Helper()
	const module = "knote_permissioned_provider_fixture"
	path := filepath.Join(workspace, module+".py")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	pythonPath := workspace
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath += string(os.PathListSeparator) + existing
	}
	t.Setenv("PYTHONPATH", pythonPath)
	return module + ":create"
}
