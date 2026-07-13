package fixture

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestAuthorizationCreatesFreshValidRequestIDs(t *testing.T) {
	first := Authorization(Alice, "session-fixture")
	second := Authorization(Alice, "session-fixture")
	if err := first.Validate(); err != nil {
		t.Fatalf("first authorization is invalid: %v", err)
	}
	if err := second.Validate(); err != nil {
		t.Fatalf("second authorization is invalid: %v", err)
	}
	if first.RequestID == second.RequestID {
		t.Fatalf("Authorization reused request ID %q", first.RequestID)
	}
}

func TestServiceIsolatesFakeRetrieveEvidenceByPrincipal(t *testing.T) {
	backend := &fakePrimitiveBackend{}
	service, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}

	alice, err := service.Query(context.Background(), protocol.QueryRequest{
		Question:      "What is knote?",
		Authorization: Authorization(Alice, "session-alice"),
	})
	if err != nil {
		t.Fatalf("Alice query failed: %v", err)
	}
	assertResourceIDs(t, alice.Evidence.Items, []protocol.ResourceID{introResourceID, overviewResourceID})
	if strings.Contains(alice.Generation.Answer, deniedCanaryContent) {
		t.Fatal("Alice generation contains the denied canary")
	}

	bob, err := service.Query(context.Background(), protocol.QueryRequest{
		Question:      "What is knote?",
		Authorization: Authorization(Bob, "session-bob"),
	})
	if err != nil {
		t.Fatalf("Bob query failed: %v", err)
	}
	assertResourceIDs(t, bob.Evidence.Items, []protocol.ResourceID{overviewResourceID})
	if strings.Contains(bob.Generation.Answer, deniedCanaryContent) {
		t.Fatal("Bob generation contains the denied canary")
	}
	if backend.expandCalls != 0 {
		t.Fatalf("fixture enabled expansion: got %d calls", backend.expandCalls)
	}
	if len(backend.retrieveRequests) != 2 {
		t.Fatalf("got %d retrieve calls, want 2", len(backend.retrieveRequests))
	}
	if backend.retrieveRequests[0].Limit != 3 || backend.retrieveRequests[1].Limit != 3 {
		t.Fatalf("retrieve limits = %d, %d; want 3", backend.retrieveRequests[0].Limit, backend.retrieveRequests[1].Limit)
	}
}

func TestServiceFailsClosedForUnknownPrincipal(t *testing.T) {
	backend := &fakePrimitiveBackend{}
	service, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Query(context.Background(), protocol.QueryRequest{
		Question:      "What is knote?",
		Authorization: Authorization("mallory", "session-mallory"),
	})
	if err == nil {
		t.Fatal("unknown principal query succeeded")
	}
	if len(backend.generateRequests) != 0 {
		t.Fatalf("unknown principal reached generation %d time(s)", len(backend.generateRequests))
	}
	if backend.expandCalls != 0 {
		t.Fatalf("unknown principal reached expansion %d time(s)", backend.expandCalls)
	}
}

func TestServiceRejectsChangedFakeRetrieveHandle(t *testing.T) {
	changed := fixtureResource(introResourceID, introContent)
	changed.Versions.Content = "content_fake_v2"
	backend := &fakePrimitiveBackend{retrieveResult: &kag.RetrieveResult{
		Mode:       "fake",
		Candidates: []kag.CandidateHandle{{Resource: changed, Score: 0.99}},
	}}
	service, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Query(context.Background(), protocol.QueryRequest{
		Question:      "What is knote?",
		Authorization: Authorization(Alice, "session-changed-handle"),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match the exact fake retrieve handle") {
		t.Fatalf("changed handle error = %v", err)
	}
	if len(backend.generateRequests) != 0 {
		t.Fatal("changed handle reached generation")
	}
}

type fakePrimitiveBackend struct {
	retrieveResult   *kag.RetrieveResult
	retrieveRequests []kag.RetrieveRequest
	generateRequests []kag.GenerateRequest
	expandCalls      int
}

func (b *fakePrimitiveBackend) Retrieve(_ context.Context, request kag.RetrieveRequest) (kag.RetrieveResult, error) {
	b.retrieveRequests = append(b.retrieveRequests, request)
	if b.retrieveResult != nil {
		return *b.retrieveResult, nil
	}
	return kag.RetrieveResult{
		Mode: "fake",
		Candidates: []kag.CandidateHandle{
			{Resource: fixtureResource(introResourceID, introContent), Score: 0.99},
			{Resource: fixtureResource(deniedCanaryResourceID, deniedCanaryContent), Score: 0.98},
			{Resource: fixtureResource(overviewResourceID, overviewContent), Score: 0.90},
		},
	}, nil
}

func (b *fakePrimitiveBackend) Expand(context.Context, kag.ExpandRequest) (kag.ExpandResult, error) {
	b.expandCalls++
	return kag.ExpandResult{}, errors.New("fixture expansion must be disabled")
}

func (b *fakePrimitiveBackend) Generate(_ context.Context, request kag.GenerateRequest) (kag.GenerateResult, error) {
	b.generateRequests = append(b.generateRequests, request)
	result := kag.GenerateResult{Mode: "fake"}
	contents := make([]string, len(request.Evidence))
	for index, evidence := range request.Evidence {
		contents[index] = evidence.Content
		result.Citations = append(result.Citations, kag.CitationHandle{
			Handle:     evidence.CitationHandle,
			ResourceID: evidence.Resource.ResourceID,
		})
		result.EvidenceResourceIDs = append(result.EvidenceResourceIDs, evidence.Resource.ResourceID)
		result.Trace.ResourceIDs = append(result.Trace.ResourceIDs, evidence.Resource.ResourceID)
	}
	result.Answer = strings.Join(contents, " ")
	result.Trace.Count = len(result.Trace.ResourceIDs)
	return result, nil
}

func assertResourceIDs(t *testing.T, items []protocol.EvidenceItem, want []protocol.ResourceID) {
	t.Helper()
	got := make([]protocol.ResourceID, len(items))
	for index, item := range items {
		got[index] = item.Resource.ResourceID
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence resource IDs = %v, want %v", got, want)
	}
}
