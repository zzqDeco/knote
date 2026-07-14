package fixture

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
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
	backend := &fakePrimitiveBackend{
		retrieveResult: &kag.RetrieveResult{
			Mode:       "fake",
			Candidates: []kag.CandidateHandle{{Resource: changed, Score: 0.99}},
		},
		bypassRetrieveScope: true,
	}
	service, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Query(context.Background(), protocol.QueryRequest{
		Question:      "What is knote?",
		Authorization: Authorization(Alice, "session-changed-handle"),
	})
	if err == nil || !strings.Contains(err.Error(), "outside the exact authorized retrieval scope") {
		t.Fatalf("changed handle error = %v", err)
	}
	if len(backend.generateRequests) != 0 {
		t.Fatal("changed handle reached generation")
	}
}

func TestApplicationRevocationHidesRevokedEvidenceWithoutPoisoningUnrelatedResources(t *testing.T) {
	backend := &fakePrimitiveBackend{}
	cache, err := authorized.NewQueryCache(8)
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewApplication(backend, ApplicationOptions{
		Cache: cache, RetrieverVersion: "fixture-retriever-v1", PromptVersion: "fixture-prompt-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := Authorization(Alice, "session-revocation")
	result, err := application.Service.Query(context.Background(), protocol.QueryRequest{
		Question: "What is knote?", Authorization: authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.AuthorizeProtectedContent(context.Background(), authorization, binding); err != nil {
		t.Fatalf("protected content was denied before revocation: %v", err)
	}
	if err := application.RemoveTuple(authz.Tuple{
		User: "user:" + Alice, Relation: authz.RelationMember, Object: fakePrivateReaders,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := application.Apply(context.Background(), authorized.RevocationRequest{
		Authorization: authorization,
		Binding:       binding,
		ResourceIDs:   []protocol.ResourceID{introResourceID},
		RevokedAt:     time.Now().Add(-time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.InvalidatedResourceCount != 1 || report.DeniedCount != 1 || report.AllowedCount != 1 {
		t.Fatalf("fixture revocation report = %#v", report)
	}
	if err := application.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, authorized.ErrProtectedContentUnavailable) {
		t.Fatalf("revoked protected block remained visible: %v", err)
	}

	after, err := application.Service.Query(context.Background(), protocol.QueryRequest{
		Question: "What is knote?", Authorization: authorization,
	})
	if err != nil {
		t.Fatalf("unrelated authorized evidence was poisoned by revocation: %v", err)
	}
	assertResourceIDs(t, after.Evidence.Items, []protocol.ResourceID{overviewResourceID})
	if strings.Contains(after.Generation.Answer, introContent) || strings.Contains(after.Generation.Answer, deniedCanaryContent) {
		t.Fatalf("post-revocation answer leaked hidden content: %q", after.Generation.Answer)
	}
}

type fakePrimitiveBackend struct {
	discoverRequests    []kag.DiscoverRequest
	retrieveResult      *kag.RetrieveResult
	bypassRetrieveScope bool
	retrieveRequests    []kag.RetrieveRequest
	generateRequests    []kag.GenerateRequest
	expandCalls         int
}

func (b *fakePrimitiveBackend) Discover(_ context.Context, request kag.DiscoverRequest) (kag.DiscoverResult, error) {
	b.discoverRequests = append(b.discoverRequests, request)
	return kag.DiscoverResult{
		Mode: "fake",
		Resources: []protocol.ResourceHandle{
			fixtureResource(introResourceID, introContent),
			fixtureResource(deniedCanaryResourceID, deniedCanaryContent),
			fixtureResource(overviewResourceID, overviewContent),
		},
		Complete: true,
	}, nil
}

func (b *fakePrimitiveBackend) Retrieve(_ context.Context, request kag.RetrieveRequest) (kag.RetrieveResult, error) {
	b.retrieveRequests = append(b.retrieveRequests, request)
	var result kag.RetrieveResult
	if b.retrieveResult != nil {
		result = *b.retrieveResult
	} else {
		result = kag.RetrieveResult{
			Mode: "fake",
			Candidates: []kag.CandidateHandle{
				{Resource: fixtureResource(introResourceID, introContent), Score: 0.99},
				{Resource: fixtureResource(deniedCanaryResourceID, deniedCanaryContent), Score: 0.98},
				{Resource: fixtureResource(overviewResourceID, overviewContent), Score: 0.90},
			},
		}
	}
	if b.bypassRetrieveScope {
		return result, nil
	}
	allowed := make(map[protocol.ResourceID]protocol.ResourceHandle, len(request.AllowedResources))
	for _, resource := range request.AllowedResources {
		allowed[resource.ResourceID] = resource
	}
	filtered := result
	filtered.Candidates = nil
	for _, candidate := range result.Candidates {
		if resource, ok := allowed[candidate.Resource.ResourceID]; ok && resource == candidate.Resource {
			filtered.Candidates = append(filtered.Candidates, candidate)
		}
	}
	return filtered, nil
}

func (b *fakePrimitiveBackend) Expand(context.Context, kag.ExpandRequest) (kag.ExpandResult, error) {
	b.expandCalls++
	return kag.ExpandResult{}, errors.New("fixture expansion must be disabled")
}

func (b *fakePrimitiveBackend) Generate(_ context.Context, request kag.GenerateRequest) (kag.GenerateResult, error) {
	b.generateRequests = append(b.generateRequests, request.Clone())
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
