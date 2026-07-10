package kag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
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

	retrieved, err := client.Retrieve(context.Background(), RetrieveRequest{Query: "What is knote?", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	intro := candidateByID(t, retrieved.Candidates, fakeIntroID)
	if candidateByID(t, retrieved.Candidates, fakeDeniedID).Resource.ResourceID != fakeDeniedID {
		t.Fatal("fake fixture must expose a candidate for authorization filtering")
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{Frontier: []CandidateHandle{intro}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	local := candidateByID(t, expanded.Candidates, fakeLocalID)
	if candidateByID(t, expanded.Candidates, fakeFrontierDeniedID).Resource.ResourceID != fakeFrontierDeniedID {
		t.Fatal("fake fixture must expose a frontier candidate for per-hop filtering")
	}

	generated, err := client.Generate(context.Background(), GenerateRequest{
		Question: "What is knote?",
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

func TestPrimitiveClientActualRealAdapterReturnsUnsupportedBeforeKAGSetup(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	client := Client{
		AdapterPath: filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   repoRoot,
		Fake:        false,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	candidate := CandidateHandle{Resource: testPrimitiveResource(testResourceA), Score: 0.9}
	evidence := AuthorizedEvidence{
		Resource: candidate.Resource, Content: "allowed body", CitationHandle: "citation-1",
	}

	_, retrieveErr := client.Retrieve(context.Background(), RetrieveRequest{Query: "knote", Limit: 10})
	_, expandErr := client.Expand(context.Background(), ExpandRequest{Frontier: []CandidateHandle{candidate}, Limit: 10})
	_, generateErr := client.Generate(context.Background(), GenerateRequest{Question: "knote", Evidence: []AuthorizedEvidence{evidence}})
	for method, err := range map[string]error{
		"kag.retrieve": retrieveErr,
		"kag.expand":   expandErr,
		"kag.generate": generateErr,
	} {
		if !errors.Is(err, ErrUnsupportedPrimitive) {
			t.Fatalf("%s should return typed unsupported before KAG setup, got %T: %v", method, err, err)
		}
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

	retrieved, err := client.Retrieve(context.Background(), RetrieveRequest{Query: "knote", Limit: 40})
	if err != nil {
		t.Fatal(err)
	}
	if len(retrieved.Candidates) != 1 || retrieved.Candidates[0].Resource.ResourceID != testResourceA {
		t.Fatalf("unexpected retrieve result: %#v", retrieved)
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{Frontier: retrieved.Candidates, Limit: 40})
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded.Expansions) != 1 || expanded.Expansions[0].ToResourceID != testResourceB {
		t.Fatalf("unexpected expand result: %#v", expanded)
	}

	generated, err := client.Generate(context.Background(), GenerateRequest{
		Question: "knote",
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
		Frontier: []CandidateHandle{{Resource: testPrimitiveResource(testResourceA), Score: 0.9}},
		Limit:    10,
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

func TestPrimitiveDecodeRejectsUnknownLeakFields(t *testing.T) {
	resource, err := structParams(testPrimitiveResource(testResourceA))
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Data: map[string]any{
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

func TestGenerateRejectsForeignCitationAndTrace(t *testing.T) {
	req := GenerateRequest{
		Question: "knote",
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

	_, err := client.Retrieve(context.Background(), RetrieveRequest{Query: "knote", Limit: 10})
	if err == nil {
		t.Fatal("unsupported primitive should fail")
	}
	if !errors.Is(err, ErrUnsupportedPrimitive) || !IsUnsupportedPrimitive(err) {
		t.Fatalf("expected typed unsupported primitive error, got %T: %v", err, err)
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

	_, err := client.Retrieve(ctx, RetrieveRequest{Query: "knote", Limit: 10})
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

	_, err := client.Retrieve(ctx, RetrieveRequest{Query: "knote", Limit: 10})
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

	_, err := client.Retrieve(ctx, RetrieveRequest{Query: "knote", Limit: 10})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("context deadline should take precedence over an early adapter error, got %T: %v", err, err)
	}
}

func TestPrimitiveRequestsFailClosedBeforeAdapterExecution(t *testing.T) {
	client := Client{}
	if _, err := client.Retrieve(context.Background(), RetrieveRequest{Query: "", Limit: 10}); err == nil {
		t.Fatal("empty query should fail")
	}
	if _, err := client.Expand(context.Background(), ExpandRequest{Limit: 10}); err == nil {
		t.Fatal("empty authorized frontier should fail")
	}
	if _, err := client.Generate(context.Background(), GenerateRequest{Question: "knote"}); err == nil {
		t.Fatal("empty authorized evidence should fail")
	}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Question: "knote",
		Evidence: []AuthorizedEvidence{{
			Resource: testPrimitiveResource(testResourceA), Content: "wrong body", CitationHandle: "citation-1",
		}},
	}); err == nil {
		t.Fatal("evidence body not bound to its resource digest should fail before adapter execution")
	}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Question: "knote",
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

func writePrimitiveAdapter(t *testing.T, workspace, script string) string {
	t.Helper()
	path := filepath.Join(workspace, "adapter.py")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
