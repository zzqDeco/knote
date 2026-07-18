package kag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	localrepo "github.com/zzqDeco/knote/internal/repository/local"
)

const (
	testResourceA         protocol.ResourceID        = "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testResourceB         protocol.ResourceID        = "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testResourceC         protocol.ResourceID        = "res_cccccccccccccccccccccccccccccccc"
	testResourceD         protocol.ResourceID        = "res_dddddddddddddddddddddddddddddddd"
	testResourceE         protocol.ResourceID        = "res_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	fakeIntroID           protocol.ResourceID        = "res_00000000000000000000000000000001"
	fakeDeniedID          protocol.ResourceID        = "res_00000000000000000000000000000002"
	fakeLocalID           protocol.ResourceID        = "res_00000000000000000000000000000004"
	fakeFrontierDeniedID  protocol.ResourceID        = "res_00000000000000000000000000000005"
	testPredicateKey      protocol.ClaimPredicateKey = "pred_a3b0b7f1948c58d586d3af99fee4704e"
	testProjectionVersion                            = "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fakeProjectionVersion                            = "prj_ffffffffffffffffffffffffffffffff"
)

func TestPrimitiveClientActualFakeAdapterRoundTrip(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	client := Client{
		AdapterPath: filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   repoRoot,
		Fake:        true,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())

	discovered, err := client.Discover(context.Background(), testDiscoverRequest(testFakeAuthorizationContext()))
	if err != nil {
		t.Fatal(err)
	}
	if !discovered.Complete || len(discovered.Resources) == 0 {
		t.Fatalf("unexpected fake discovery result: %+v", discovered)
	}
	retrieved, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testFakeAuthorizationContext(), "What is knote?", 3, discovered.Resources...,
	))
	if err != nil {
		t.Fatal(err)
	}
	intro := candidateByID(t, retrieved.Candidates, fakeIntroID)
	if candidateByID(t, retrieved.Candidates, fakeDeniedID).Resource.ResourceID != fakeDeniedID {
		t.Fatal("fake fixture must expose a candidate for authorization filtering")
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testFakeAuthorizationContext(),
		Operation:     testExpandOperation(t, fakeProjectionVersion, fakeIntroID),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier:      []CandidateHandle{intro},
		Limit:         maxPrimitiveItems,
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
	resource, frontierResource := writePrimitiveTraversalGraphContract(t, workspace)
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
	evidence := AuthorizedEvidence{
		Resource: resource, Content: "allowed body", CitationHandle: "citation-1",
	}

	discovered, err := client.Discover(context.Background(), testDiscoverRequest(testAuthorizationContext()))
	if err != nil {
		t.Fatal(err)
	}
	retrieved, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10, discovered.Resources...,
	))
	if err != nil {
		t.Fatal(err)
	}
	if retrieved.Mode != "real" || len(retrieved.Candidates) != 1 || retrieved.Candidates[0].Resource != resource {
		t.Fatalf("unexpected real retrieve result: %+v", retrieved)
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, frontierResource.Versions.Projection, frontierResource.ResourceID),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier:      []CandidateHandle{{Resource: frontierResource, Score: 0.9}},
		Limit:         maxPrimitiveItems,
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
	resource := writePrimitiveGraphContract(t, workspace)
	client := Client{
		AdapterPath: filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   workspace,
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	t.Setenv("KNOTE_KAG_PERMISSIONED_PROVIDER", "")
	_, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10, resource,
	))
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

	_, err = client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10, resource,
	))
	if !errors.Is(err, ErrInvalidPrimitiveResponse) || !IsInvalidPrimitiveResponse(err) {
		t.Fatalf("oversized provider score error = %T %v", err, err)
	}
}

func TestPrimitiveClientActualRealProviderPipeUsesUTF8(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
	provider := writePrimitiveProvider(t, workspace, `
class Provider:
    def retrieve(self, request):
        if request["query"] != "\u6743\u9650\u68c0\u7d22":
            raise RuntimeError("unexpected query")
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
	t.Setenv("LC_ALL", "C")
	t.Setenv("LANG", "C")
	t.Setenv("PYTHONUTF8", "0")
	t.Setenv("PYTHONCOERCECLOCALE", "0")
	t.Setenv("PYTHONIOENCODING", "utf-8")

	result, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "\u6743\u9650\u68c0\u7d22", 10, resource,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 0 {
		t.Fatalf("UTF-8 provider returned candidates: %+v", result.Candidates)
	}
}

func TestPrimitiveClientActualRealProviderHonorsContextDeadline(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
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
	_, err := client.Retrieve(ctx, testRetrieveRequest(
		testAuthorizationContext(), "knote", 10, resource,
	))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("actual provider deadline error = %T %v", err, err)
	}
}

func TestPrimitiveClientActualRealProviderStopsAfterCancellation(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
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
        ], close_fds=True, start_new_session=True)
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
		_, err := client.Retrieve(ctx, testRetrieveRequest(
			testAuthorizationContext(), "knote", 10, resource,
		))
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

func TestPrimitiveClientActualRealProviderStopsReparentedHelperAfterCancellation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux child-subreaper containment")
	}
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
	provider := writePrimitiveProvider(t, workspace, `
import os
import time
class Provider:
    def retrieve(self, request):
        child = os.fork()
        if child == 0:
            grandchild = os.fork()
            if grandchild == 0:
                time.sleep(0.25)
                with open(os.environ["KNOTE_PROVIDER_COMPLETED"], "w", encoding="utf-8") as stream:
                    stream.write("completed")
                os._exit(0)
            os._exit(0)
        os.waitpid(child, 0)
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
		_, err := client.Retrieve(ctx, testRetrieveRequest(
			testAuthorizationContext(), "knote", 10, resource,
		))
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
			t.Fatal("reparented provider helper did not start before cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("actual provider cancellation error = %T %v", err, err)
	}
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(completed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reparented provider helper completed side effects after cancellation: %v", err)
	}
}

func TestPrimitiveClientActualRealProviderReapsDetachedHelperAfterSuccess(t *testing.T) {
	repoRoot := primitiveTestRepoRoot(t)
	workspace := t.TempDir()
	resource := writePrimitiveGraphContract(t, workspace)
	provider := writePrimitiveProvider(t, workspace, `
import subprocess
import sys
class Provider:
    def retrieve(self, request):
        subprocess.Popen([
            sys.executable,
            "-c",
            "import os,time; time.sleep(0.25); open(os.environ['KNOTE_PROVIDER_COMPLETED'], 'w', encoding='utf-8').write('completed')",
        ], close_fds=True, start_new_session=True)
        return {"candidates": []}
def create(context):
    return Provider()
`)
	completed := filepath.Join(workspace, "provider-completed")
	t.Setenv("KNOTE_PROVIDER_COMPLETED", completed)
	t.Setenv("KNOTE_PYTHON", pythonForTest())
	t.Setenv("KNOTE_KAG_FAKE", "")
	client := Client{
		AdapterPath:          filepath.Join(repoRoot, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:            workspace,
		PermissionedProvider: provider,
	}

	if _, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10, resource,
	)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(completed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("detached helper completed side effects after provider success: %v", err)
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
	_, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	))
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
def resource(resource_id, resource_type):
    return {"resource_id": resource_id, "type": resource_type, "tenant_id": "local", "knowledge_base_id": "default", "authz_object": resource_type + ":" + resource_id, "authorization_resource_id": resource_id, "content_digest": "sha256:" + hashlib.sha256(b"allowed body").hexdigest(), "versions": {"source": "source-v1", "content": "content-v1", "acl": "acl-v1", "index": "index-v1", "graph": "graph-v1", "projection": "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "serving_state": "serving"}
candidate = {"resource": resource(a, "entity"), "score": 0.9}
if method == "kag.retrieve":
    data = {"mode": "fake", "candidates": [candidate]}
elif method == "kag.expand":
    target = {"resource": resource(b, "claim"), "score": 0.8}
    data = {"mode": "fake", "candidates": [target], "expansions": [{"from_resource_id": params["frontier"][0]["resource"]["resource_id"], "to_resource_id": b, "claim_resource_id": b, "predicate_key": "pred_a3b0b7f1948c58d586d3af99fee4704e", "hop": 1}]}
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

	retrieved, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 40,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(retrieved.Candidates) != 1 || retrieved.Candidates[0].Resource.ResourceID != testResourceA {
		t.Fatalf("unexpected retrieve result: %#v", retrieved)
	}

	expanded, err := client.Expand(context.Background(), ExpandRequest{
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier:      retrieved.Candidates,
		Limit:         maxPrimitiveItems,
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
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier:      []CandidateHandle{{Resource: testPrimitiveResource(testResourceA), Score: 0.9}},
		Limit:         maxPrimitiveItems,
	}
	result := ExpandResult{
		Mode:       "fake",
		Candidates: []CandidateHandle{{Resource: testPrimitiveClaim(testResourceB), Score: 0.8}},
		Expansions: []ExpansionHandle{{
			FromResourceID: testResourceB, ToResourceID: testResourceB,
			ClaimResourceID: testResourceB, PredicateKey: testPredicateKey, Hop: 1,
		}},
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
					Operation: testExpandOperation(t, testProjectionVersion, testResourceA),
					Phase:     ExpandPhaseEntityToClaim, Frontier: []CandidateHandle{candidate}, Limit: maxPrimitiveItems,
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

func TestDiscoverContractRejectsPartialAndUnsortedSets(t *testing.T) {
	authorization := testAuthorizationContext()
	request := testDiscoverRequest(authorization)

	partial := DiscoverResult{
		Mode: "fake", Resources: []protocol.ResourceHandle{testPrimitiveResource(testResourceA)}, Complete: false,
	}
	if err := partial.ValidateFor(request); err == nil || !strings.Contains(err.Error(), "fill the requested limit") {
		t.Fatalf("partial discovery should fail explicit overflow semantics, got %v", err)
	}

	unsorted := DiscoverResult{
		Mode: "fake",
		Resources: []protocol.ResourceHandle{
			testPrimitiveResource(testResourceB),
			testPrimitiveResource(testResourceA),
		},
		Complete: true,
	}
	if err := unsorted.ValidateFor(request); err == nil || !strings.Contains(err.Error(), "strictly sorted") {
		t.Fatalf("unsorted discovery should fail, got %v", err)
	}

	request.Limit--
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "full discovery scan limit") {
		t.Fatalf("partial discovery request should fail, got %v", err)
	}
}

func TestRetrieveResultRejectsCandidateOutsideExactAllowedResources(t *testing.T) {
	authorization := testAuthorizationContext()
	allowed := testPrimitiveResource(testResourceA)
	outside := testPrimitiveResource(testResourceB)
	result := RetrieveResult{
		Mode: "fake", Candidates: []CandidateHandle{{Resource: outside, Score: 0.9}},
	}
	if err := result.ValidateFor(testRetrieveRequest(
		authorization, "knote", 10, allowed,
	)); err == nil || !strings.Contains(err.Error(), "outside the exact authorized retrieval scope") {
		t.Fatalf("out-of-allowlist candidate should fail, got %v", err)
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
			if err := result.ValidateFor(testRetrieveRequest(
				auth, "knote", 10,
			)); err == nil {
				t.Fatal("out-of-scope retrieve candidate should fail")
			}
		})

		t.Run("expand frontier "+name, func(t *testing.T) {
			req := ExpandRequest{
				Authorization: auth,
				Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
				Phase:         ExpandPhaseEntityToClaim,
				Frontier:      []CandidateHandle{{Resource: resource, Score: 0.9}},
				Limit:         maxPrimitiveItems,
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
			target.Type = protocol.ResourceClaim
			target.AuthorizationID = "claim:" + string(testResourceB)
			result := ExpandResult{
				Mode:       "fake",
				Candidates: []CandidateHandle{{Resource: target, Score: 0.8}},
				Expansions: []ExpansionHandle{{
					FromResourceID: testResourceA, ToResourceID: testResourceB,
					ClaimResourceID: testResourceB, PredicateKey: testPredicateKey, Hop: 1,
				}},
			}
			if err := result.ValidateFor(ExpandRequest{
				Authorization: auth,
				Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
				Phase:         ExpandPhaseEntityToClaim,
				Frontier:      []CandidateHandle{{Resource: frontier, Score: 0.9}},
				Limit:         maxPrimitiveItems,
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
	target := testPrimitiveClaim(testResourceB)
	target.Versions.Projection = "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	req := ExpandRequest{
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier:      []CandidateHandle{{Resource: frontier, Score: 0.9}},
		Limit:         maxPrimitiveItems,
	}
	result := ExpandResult{
		Mode:       "fake",
		Candidates: []CandidateHandle{{Resource: target, Score: 0.8}},
		Expansions: []ExpansionHandle{{
			FromResourceID: testResourceA, ToResourceID: testResourceB,
			ClaimResourceID: testResourceB, PredicateKey: testPredicateKey, Hop: 1,
		}},
	}
	if err := result.ValidateFor(req); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Fatalf("cross-projection expansion candidate should fail, got %v", err)
	}
}

func TestExpandRequestRejectsUnsupportedPrimitivePlans(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ExpandRequest)
	}{
		{
			name: "inbound direction",
			mutate: func(req *ExpandRequest) {
				req.Operation.Parameters.Direction = protocol.TraversalInbound
			},
		},
		{
			name: "both direction",
			mutate: func(req *ExpandRequest) {
				req.Operation.Parameters.Direction = protocol.TraversalBoth
			},
		},
		{
			name: "provider frontier limit",
			mutate: func(req *ExpandRequest) {
				req.Operation.Parameters.Limits.MaxFrontierWidth = 101
			},
		},
		{
			name: "provider candidate limit",
			mutate: func(req *ExpandRequest) {
				req.Operation.Parameters.Limits.MaxCandidatesPerHop = 101
			},
		},
		{
			name: "unsupported provider resource kind",
			mutate: func(req *ExpandRequest) {
				req.Operation.Parameters.ResourceKinds = []protocol.GraphResourceKind{protocol.GraphResourceDocument}
			},
		},
		{
			name: "unknown predicate",
			mutate: func(req *ExpandRequest) {
				req.Operation.Parameters.PredicateKeys = []protocol.ClaimPredicateKey{"pred_ffffffffffffffffffffffffffffffff"}
			},
		},
		{
			name: "unknown phase",
			mutate: func(req *ExpandRequest) {
				req.Phase = "entity_to_relation"
			},
		},
		{
			name: "stale operation projection",
			mutate: func(req *ExpandRequest) {
				req.Operation = testExpandOperation(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", testResourceA)
			},
		},
		{
			name: "phase frontier kind",
			mutate: func(req *ExpandRequest) {
				req.Phase = ExpandPhaseClaimToObject
			},
		},
		{
			name: "partial provider transport scan",
			mutate: func(req *ExpandRequest) {
				req.Limit = maxPrimitiveItems - 1
			},
		},
		{
			name: "oversized provider transport scan",
			mutate: func(req *ExpandRequest) {
				req.Limit = maxPrimitiveItems + 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := ExpandRequest{
				Authorization: testAuthorizationContext(),
				Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
				Phase:         ExpandPhaseEntityToClaim,
				Frontier: []CandidateHandle{{
					Resource: testPrimitiveResource(testResourceA), Score: 0.9,
				}},
				Limit: maxPrimitiveItems,
			}
			test.mutate(&req)
			if err := req.Validate(); err == nil {
				t.Fatal("unsupported primitive plan should fail")
			}
		})
	}
}

func TestExpandRequestAllowsTransportScanAbovePostAuthorizationCandidateLimit(t *testing.T) {
	req := ExpandRequest{
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier: []CandidateHandle{{
			Resource: testPrimitiveResource(testResourceA), Score: 0.9,
		}},
		Limit: maxPrimitiveItems,
	}
	req.Operation.Parameters.Limits.MaxCandidatesPerHop = 1
	if err := req.Validate(); err != nil {
		t.Fatalf("transport scan above post-authorization candidate limit: %v", err)
	}
}

func TestExpandResultValidatesClaimToObjectEdgeBinding(t *testing.T) {
	req := ExpandRequest{
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseClaimToObject,
		Frontier: []CandidateHandle{{
			Resource: testPrimitiveClaim(testResourceA), Score: 0.9,
		}},
		Limit: maxPrimitiveItems,
	}
	validEdge := ExpansionHandle{
		FromResourceID: testResourceA, ToResourceID: testResourceB,
		ClaimResourceID: testResourceA, PredicateKey: testPredicateKey, Hop: 1,
	}
	valid := ExpandResult{
		Mode:       "fake",
		Candidates: []CandidateHandle{{Resource: testPrimitiveResource(testResourceB), Score: 0.9}},
		Expansions: []ExpansionHandle{validEdge},
	}
	if err := valid.ValidateFor(req); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ExpansionHandle)
	}{
		{
			name: "wrong claim binding",
			mutate: func(edge *ExpansionHandle) {
				edge.ClaimResourceID = testResourceB
			},
		},
		{
			name: "unknown predicate",
			mutate: func(edge *ExpansionHandle) {
				edge.PredicateKey = "pred_ffffffffffffffffffffffffffffffff"
			},
		},
		{
			name: "multi hop primitive edge",
			mutate: func(edge *ExpansionHandle) {
				edge.Hop = 2
			},
		},
		{
			name: "self edge",
			mutate: func(edge *ExpansionHandle) {
				edge.ToResourceID = edge.FromResourceID
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			edge := validEdge
			test.mutate(&edge)
			result := valid
			result.Expansions = []ExpansionHandle{edge}
			if err := result.ValidateFor(req); err == nil {
				t.Fatal("malformed Claim edge should fail")
			}
		})
	}
}

func TestExpandResultRejectsUnsortedEdges(t *testing.T) {
	req := ExpandRequest{
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA, testResourceB),
		Phase:         ExpandPhaseClaimToObject,
		Frontier: []CandidateHandle{
			{Resource: testPrimitiveClaim(testResourceA), Score: 0.9},
			{Resource: testPrimitiveClaim(testResourceB), Score: 0.8},
		},
		Limit: maxPrimitiveItems,
	}
	result := ExpandResult{
		Mode: "fake",
		Candidates: []CandidateHandle{
			{Resource: testPrimitiveResource(testResourceC), Score: 0.9},
			{Resource: testPrimitiveResource(testResourceD), Score: 0.8},
		},
		Expansions: []ExpansionHandle{
			{
				FromResourceID: testResourceB, ToResourceID: testResourceD,
				ClaimResourceID: testResourceB, PredicateKey: testPredicateKey, Hop: 1,
			},
			{
				FromResourceID: testResourceA, ToResourceID: testResourceC,
				ClaimResourceID: testResourceA, PredicateKey: testPredicateKey, Hop: 1,
			},
		},
	}
	if err := result.ValidateFor(req); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("unsorted expansion edges should fail, got %v", err)
	}
}

func TestPrimitiveRequestsRejectMixedProjectionSets(t *testing.T) {
	auth := testAuthorizationContext()
	first := testPrimitiveResource(testResourceA)
	second := testPrimitiveResource(testResourceB)
	second.Versions.Projection = "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	retrieve := RetrieveResult{
		Mode: "fake",
		Candidates: []CandidateHandle{
			{Resource: first, Score: 0.9},
			{Resource: second, Score: 0.8},
		},
	}
	if err := retrieve.ValidateFor(testRetrieveRequest(auth, "knote", 10, first)); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Fatalf("mixed-projection retrieve candidates should fail, got %v", err)
	}

	expand := ExpandRequest{
		Authorization: auth,
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseEntityToClaim,
		Frontier: []CandidateHandle{
			{Resource: first, Score: 0.9},
			{Resource: second, Score: 0.8},
		},
		Limit: maxPrimitiveItems,
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

	if _, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 40,
	)); err == nil {
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

func TestGenerateRequestValidatesCompleteAuthorizedPaths(t *testing.T) {
	terminal := testPrimitiveResource(testResourceC)
	request := GenerateRequest{
		Authorization: testAuthorizationContext(),
		Question:      "knote",
		Evidence: []AuthorizedEvidence{{
			Resource: terminal, Content: "allowed body", CitationHandle: "citation-1",
		}},
		Paths: []GeneratePath{testGeneratePath(
			testPrimitiveResource(testResourceA),
			testPrimitiveClaim(testResourceB),
			terminal,
		)},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}

	zeroHop := request
	zeroHop.Evidence = []AuthorizedEvidence{{
		Resource: testPrimitiveResource(testResourceA), Content: "allowed body", CitationHandle: "citation-zero",
	}}
	zeroHop.Paths = []GeneratePath{{
		Resources:     []protocol.ResourceHandle{testPrimitiveResource(testResourceA)},
		ClaimBindings: []GeneratePathClaimBinding{},
	}}
	if err := zeroHop.Validate(); err != nil {
		t.Fatalf("zero-hop complete path: %v", err)
	}

	result := GenerateResult{
		Mode:                "fake",
		Answer:              "authorized answer",
		Citations:           []CitationHandle{{Handle: "citation-1", ResourceID: testResourceC}},
		EvidenceResourceIDs: []protocol.ResourceID{testResourceC},
		Trace:               GenerationTrace{ResourceIDs: []protocol.ResourceID{testResourceC}, Count: 1},
	}
	if err := result.ValidateFor(request); err != nil {
		t.Fatalf("path metadata must not weaken exact generation evidence binding: %v", err)
	}
}

func TestGenerateRequestRejectsMalformedAuthorizedPaths(t *testing.T) {
	valid := GenerateRequest{
		Authorization: testAuthorizationContext(),
		Question:      "knote",
		Evidence: []AuthorizedEvidence{{
			Resource: testPrimitiveResource(testResourceC), Content: "allowed body", CitationHandle: "citation-1",
		}},
		Paths: []GeneratePath{testGeneratePath(
			testPrimitiveResource(testResourceA),
			testPrimitiveClaim(testResourceB),
			testPrimitiveResource(testResourceC),
		)},
	}
	tests := []struct {
		name   string
		mutate func(*GenerateRequest)
		want   string
	}{
		{
			name: "present but empty",
			mutate: func(request *GenerateRequest) {
				request.Paths = []GeneratePath{}
			},
			want: "exactly one complete path",
		},
		{
			name: "nil bindings",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].ClaimBindings = nil
			},
			want: "claim_bindings must be a list",
		},
		{
			name: "incomplete segment",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].Resources = request.Paths[0].Resources[:2]
			},
			want: "complete entity/Claim/entity",
		},
		{
			name: "wrong resource kind",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].Resources[1] = testPrimitiveResource(testResourceB)
			},
			want: "path shape",
		},
		{
			name: "binding sequence mismatch",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].ClaimBindings[0].ParentResourceID = testResourceD
			},
			want: "resource sequence",
		},
		{
			name: "duplicate cycle resource",
			mutate: func(request *GenerateRequest) {
				request.Evidence[0].Resource = testPrimitiveResource(testResourceA)
				request.Paths[0].Resources[2] = testPrimitiveResource(testResourceA)
				request.Paths[0].ClaimBindings[0].ObjectResourceID = testResourceA
			},
			want: "duplicate resource",
		},
		{
			name: "cross projection",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].Resources[0].Versions.Projection = "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			want: "path projection",
		},
		{
			name: "cross authorization scope",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].Resources[0].TenantID = "other"
			},
			want: "outside authorized tenant",
		},
		{
			name: "terminal handle mismatch",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].Resources[2].Versions.ACL = "acl-stale"
			},
			want: "terminal resource does not exactly match",
		},
		{
			name: "primitive resource bound",
			mutate: func(request *GenerateRequest) {
				request.Paths[0].Resources = make([]protocol.ResourceHandle, maxPrimitiveItems+1)
			},
			want: "primitive item limit",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid.Clone()
			test.mutate(&request)
			if err := request.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("malformed path error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestGeneratePathCloneAndJSONAreDeterministicAndBodyFree(t *testing.T) {
	evidence := AuthorizedEvidence{
		Resource: testPrimitiveResource(testResourceC), Content: "allowed body", CitationHandle: "citation-1",
	}
	first := GenerateRequest{
		Authorization: testAuthorizationContext(), Question: "knote",
		Evidence: []AuthorizedEvidence{evidence},
		Paths: []GeneratePath{testGeneratePath(
			testPrimitiveResource(testResourceA),
			testPrimitiveClaim(testResourceB),
			evidence.Resource,
		)},
	}
	second := first.Clone()
	second.Paths[0] = testGeneratePath(
		testPrimitiveResource(testResourceD),
		testPrimitiveClaim(testResourceE),
		evidence.Resource,
	)
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := second.Validate(); err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	firstJSONAgain, err := json.Marshal(first.Clone())
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, firstJSONAgain) {
		t.Fatalf("cloned request JSON changed:\n%s\n%s", firstJSON, firstJSONAgain)
	}
	if bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("distinct authorized paths to the same terminal must be distinguishable")
	}
	pathJSON, err := json.Marshal(first.Paths[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("allowed body"), []byte(`"body"`), []byte(`"label"`)} {
		if bytes.Contains(pathJSON, forbidden) {
			t.Fatalf("path metadata contains a protected field %s: %s", forbidden, pathJSON)
		}
	}

	nonTraversal := first
	nonTraversal.Paths = nil
	nonTraversalJSON, err := json.Marshal(nonTraversal)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(nonTraversalJSON, []byte(`"paths"`)) {
		t.Fatalf("non-traversal generation must omit paths: %s", nonTraversalJSON)
	}

	clone := first.Clone()
	clone.Paths[0].Resources[0] = testPrimitiveResource(testResourceD)
	if first.Paths[0].Resources[0].ResourceID != testResourceA {
		t.Fatal("GenerateRequest.Clone must deep-clone path resources")
	}

	zeroHop := GenerateRequest{
		Authorization: testAuthorizationContext(), Question: "knote",
		Evidence: []AuthorizedEvidence{evidence},
		Paths: []GeneratePath{{
			Resources:     []protocol.ResourceHandle{evidence.Resource},
			ClaimBindings: []GeneratePathClaimBinding{},
		}},
	}
	zeroHopClone := zeroHop.Clone()
	if zeroHopClone.Paths[0].ClaimBindings == nil {
		t.Fatal("GenerateRequest.Clone changed a zero-hop binding list from empty to nil")
	}
	if err := zeroHopClone.Validate(); err != nil {
		t.Fatalf("cloned zero-hop path is invalid: %v", err)
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

	_, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	))
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

	_, err := client.Retrieve(context.Background(), testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	))
	if !errors.Is(err, ErrInvalidPrimitiveResponse) || !IsInvalidPrimitiveResponse(err) {
		t.Fatalf("expected typed invalid primitive response error, got %T: %v", err, err)
	}
}

func TestPrimitiveResultsRequireMode(t *testing.T) {
	result := RetrieveResult{}
	if err := result.ValidateFor(testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	)); err == nil || !strings.Contains(err.Error(), "mode") {
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

	_, err := client.Retrieve(ctx, testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	))
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

	_, err := client.Retrieve(ctx, testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	))
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

	_, err := client.Retrieve(ctx, testRetrieveRequest(
		testAuthorizationContext(), "knote", 10,
	))
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
		Authorization: testAuthorizationContext(),
		Operation:     testExpandOperation(t, testProjectionVersion, testResourceA),
		Phase:         ExpandPhaseEntityToClaim,
		Limit:         maxPrimitiveItems,
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

func testDiscoverRequest(authorization protocol.AuthorizationContext) DiscoverRequest {
	return DiscoverRequest{
		Authorization: authorization,
		ResourceTypes: []protocol.ResourceType{
			protocol.ResourceChunk,
			protocol.ResourceClaim,
			protocol.ResourceDerivedArtifact,
			protocol.ResourceDocument,
			protocol.ResourceEntity,
		},
		Limit: maxPrimitiveItems,
	}
}

func testRetrieveRequest(
	authorization protocol.AuthorizationContext,
	query string,
	limit int,
	resources ...protocol.ResourceHandle,
) RetrieveRequest {
	if len(resources) == 0 {
		resources = []protocol.ResourceHandle{testPrimitiveResource(testResourceA)}
	}
	return RetrieveRequest{
		Authorization:    authorization,
		Query:            query,
		AllowedResources: append([]protocol.ResourceHandle(nil), resources...),
		Limit:            limit,
	}
}

func testPrimitiveResource(resourceID protocol.ResourceID) protocol.ResourceHandle {
	return testPrimitiveResourceOfType(resourceID, protocol.ResourceEntity)
}

func testPrimitiveClaim(resourceID protocol.ResourceID) protocol.ResourceHandle {
	return testPrimitiveResourceOfType(resourceID, protocol.ResourceClaim)
}

func testGeneratePath(resources ...protocol.ResourceHandle) GeneratePath {
	bindings := make([]GeneratePathClaimBinding, (len(resources)-1)/2)
	for index := range bindings {
		bindings[index] = GeneratePathClaimBinding{
			ParentResourceID: resources[index*2].ResourceID,
			ClaimResourceID:  resources[index*2+1].ResourceID,
			ObjectResourceID: resources[index*2+2].ResourceID,
			PredicateKey:     testPredicateKey,
		}
	}
	return GeneratePath{
		Resources:     append([]protocol.ResourceHandle(nil), resources...),
		ClaimBindings: bindings,
	}
}

func testPrimitiveResourceOfType(resourceID protocol.ResourceID, resourceType protocol.ResourceType) protocol.ResourceHandle {
	return protocol.ResourceHandle{
		ResourceID: resourceID, Type: resourceType, TenantID: "local", KnowledgeBaseID: "default",
		AuthorizationID: string(resourceType) + ":" + string(resourceID), AuthorizationResourceID: resourceID,
		ContentDigest: protocol.NewContentDigest("allowed body"),
		ServingState:  protocol.ServingActive,
		Versions: protocol.ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
			Index: "index-v1", Graph: "graph-v1", Projection: testProjectionVersion,
		},
	}
}

func testExpandOperation(
	t *testing.T,
	projectionVersion string,
	startResourceIDs ...protocol.ResourceID,
) protocol.GraphOperationDescriptor {
	t.Helper()
	descriptor, err := protocol.CompileGraphQuery(protocol.GraphQuery{
		Version:           protocol.GraphQueryContractVersion,
		Operation:         protocol.GraphOperationTraverseClaims,
		ProjectionVersion: projectionVersion,
		IdentityVersion:   protocol.GraphBindingContractVersion,
		StartResourceIDs:  append([]protocol.ResourceID(nil), startResourceIDs...),
		PredicateSources:  []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateLocatedIn},
		ResourceKinds:     []protocol.GraphResourceKind{protocol.GraphResourceEntity},
		Direction:         protocol.TraversalOutbound,
		Limits: protocol.TraversalLimits{
			MaxDepth: 2, MaxFrontierWidth: 100, MaxCandidatesPerHop: 100,
			MaxTotalResources: 128, MaxBatchChecks: 16, MaxWallClockMillis: 5_000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func testAuthorizationContext() protocol.AuthorizationContext {
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
	resource, _ := writePrimitiveGraphContractResources(t, workspace, false)
	return resource
}

func writePrimitiveTraversalGraphContract(
	t *testing.T, workspace string,
) (protocol.ResourceHandle, protocol.ResourceHandle) {
	t.Helper()
	return writePrimitiveGraphContractResources(t, workspace, true)
}

func writePrimitiveGraphContractResources(
	t *testing.T, workspace string, includeEntity bool,
) (protocol.ResourceHandle, protocol.ResourceHandle) {
	t.Helper()
	projectionID := "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	generatedAt := time.Unix(0, 0).UTC()
	scope := catalog.Scope{TenantID: "local", KnowledgeBaseID: "default"}
	resourceID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceDocument, "sources/primitive.md")
	if err != nil {
		t.Fatal(err)
	}
	versions := protocol.ResourceVersions{
		Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
		Index: "index_" + projectionID, Graph: "graph_" + projectionID, Projection: projectionID,
	}
	metadata, err := catalog.NewResourceMetadata(
		scope, protocol.ResourceDocument, "sources/primitive.md", "document:"+string(resourceID), resourceID,
		protocol.NewContentDigest("allowed body"), versions, catalog.SensitivityInternal, "local",
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata.ServingState = catalog.StatePublished
	metadata.ProjectionStatus = catalog.SucceededProjectionStatus()
	resource, err := metadata.ServingHandle()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewGraphResourceBinding(resource)
	if err != nil {
		t.Fatal(err)
	}
	resources := []catalog.ResourceMetadata{metadata}
	bindings := []protocol.GraphResourceBinding{binding}
	var entityResource protocol.ResourceHandle
	if includeEntity {
		entityID, err := protocol.NewStableResourceID(
			scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceEntity, "entity:primitive",
		)
		if err != nil {
			t.Fatal(err)
		}
		entityMetadata, err := catalog.NewResourceMetadata(
			scope, protocol.ResourceEntity, "entity:primitive", "entity:"+string(entityID), entityID,
			protocol.NewContentDigest("primitive entity"), versions, catalog.SensitivityInternal, "local",
		)
		if err != nil {
			t.Fatal(err)
		}
		entityMetadata.Dependencies = []protocol.ResourceID{resource.ResourceID}
		entityMetadata.ServingState = catalog.StatePublished
		entityMetadata.ProjectionStatus = catalog.SucceededProjectionStatus()
		entityResource, err = entityMetadata.ServingHandle()
		if err != nil {
			t.Fatal(err)
		}
		entityBinding, err := protocol.NewGraphResourceBinding(entityResource)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, entityMetadata)
		bindings = append(bindings, entityBinding)
	}
	snapshot := catalog.SourceSnapshotRef{
		Scope: scope, SourceID: "workspace", Version: versions.Source, SecurityDomain: "local",
		Digest: protocol.ContentDigest("sha256:" + strings.Repeat("a", 64)), DocumentCount: 1,
	}
	projection, err := catalog.NewProjection(scope, projectionID, snapshot, catalog.StatePublished, resources)
	if err != nil {
		t.Fatal(err)
	}
	projectionJSON, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	manifest := protocol.ArtifactManifest{
		Version: 1, Workspace: "default", GeneratedAt: generatedAt, SourceCount: 1, DocumentCount: 1,
	}
	set := repository.ArtifactSet{
		Manifest: manifest, GraphBindings: bindings,
		ClaimBindings:  []protocol.ClaimTripleBinding{},
		BuildReport:    "# graph contract\n",
		ProjectionJSON: projectionJSON, ProjectionResourceCount: len(resources),
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
	return resource, entityResource
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
