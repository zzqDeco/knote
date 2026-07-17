package authorized

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	queryTestModelID   protocol.ResourceID = "res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	queryTestOtherID   protocol.ResourceID = "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	queryTestThirdID   protocol.ResourceID = "res_cccccccccccccccccccccccccccccccc"
	queryTestFourthID  protocol.ResourceID = "res_dddddddddddddddddddddddddddddddd"
	queryTestAuthModel                     = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

type queryTestKAG struct {
	discoverResult *kag.DiscoverResult
	discoverErr    error
	retrieveResult kag.RetrieveResult
	retrieveErr    error
	expandResult   kag.ExpandResult
	expandErr      error
	generateErr    error
	discoverCalls  int
	retrieveCalls  int
	expandCalls    int
	generateCalls  int
	lastDiscover   kag.DiscoverRequest
	lastRetrieve   kag.RetrieveRequest
	lastExpand     kag.ExpandRequest
	lastGenerate   kag.GenerateRequest
	events         *[]string
}

func (f *queryTestKAG) Discover(_ context.Context, request kag.DiscoverRequest) (kag.DiscoverResult, error) {
	f.discoverCalls++
	f.lastDiscover = request
	f.event("discover")
	if f.discoverResult != nil {
		return *f.discoverResult, f.discoverErr
	}
	resources := make([]protocol.ResourceHandle, 0, len(f.retrieveResult.Candidates))
	seen := make(map[protocol.ResourceID]struct{}, len(f.retrieveResult.Candidates))
	for _, candidate := range f.retrieveResult.Candidates {
		if !containsTestResourceType(request.ResourceTypes, candidate.Resource.Type) {
			continue
		}
		if _, duplicate := seen[candidate.Resource.ResourceID]; duplicate {
			continue
		}
		seen[candidate.Resource.ResourceID] = struct{}{}
		resources = append(resources, candidate.Resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	return kag.DiscoverResult{Mode: "fake", Resources: resources, Complete: true}, f.discoverErr
}

func (f *queryTestKAG) Retrieve(_ context.Context, request kag.RetrieveRequest) (kag.RetrieveResult, error) {
	f.retrieveCalls++
	f.lastRetrieve = request
	f.event("retrieve")
	allowed := make(map[protocol.ResourceID]protocol.ResourceHandle, len(request.AllowedResources))
	for _, resource := range request.AllowedResources {
		allowed[resource.ResourceID] = resource
	}
	result := f.retrieveResult
	result.Candidates = nil
	for _, candidate := range f.retrieveResult.Candidates {
		if resource, ok := allowed[candidate.Resource.ResourceID]; ok && resource == candidate.Resource {
			result.Candidates = append(result.Candidates, candidate)
		}
	}
	return result, f.retrieveErr
}

func (f *queryTestKAG) Expand(_ context.Context, request kag.ExpandRequest) (kag.ExpandResult, error) {
	f.expandCalls++
	f.lastExpand = request
	f.event("expand")
	return f.expandResult, f.expandErr
}

func (f *queryTestKAG) Generate(_ context.Context, request kag.GenerateRequest) (kag.GenerateResult, error) {
	f.generateCalls++
	f.lastGenerate = request.Clone()
	f.event("generate")
	if f.generateErr != nil {
		return kag.GenerateResult{}, f.generateErr
	}
	result := kag.GenerateResult{Mode: "fake", Answer: "authorized answer"}
	for _, evidence := range request.Evidence {
		result.Citations = append(result.Citations, kag.CitationHandle{
			Handle: evidence.CitationHandle, ResourceID: evidence.Resource.ResourceID,
		})
		result.EvidenceResourceIDs = append(result.EvidenceResourceIDs, evidence.Resource.ResourceID)
		result.Trace.ResourceIDs = append(result.Trace.ResourceIDs, evidence.Resource.ResourceID)
	}
	result.Trace.Count = len(result.Trace.ResourceIDs)
	return result, nil
}

func (f *queryTestKAG) event(value string) {
	if f.events != nil {
		*f.events = append(*f.events, value)
	}
}

func containsTestResourceType(types []protocol.ResourceType, target protocol.ResourceType) bool {
	for _, resourceType := range types {
		if resourceType == target {
			return true
		}
	}
	return false
}

type queryTestAuthorizer struct {
	calls  []authz.BatchCheckRequest
	decide func(int, authz.BatchCheckRequest) ([]authz.Decision, error)
	events *[]string
}

func (f *queryTestAuthorizer) BatchCheck(_ context.Context, request authz.BatchCheckRequest) ([]authz.Decision, error) {
	call := len(f.calls)
	f.calls = append(f.calls, request)
	if f.events != nil {
		*f.events = append(*f.events, "authz")
	}
	if f.decide != nil {
		return f.decide(call, request)
	}
	return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
}

type queryTestLoader struct {
	items     map[protocol.ResourceID]protocol.EvidenceItem
	load      func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error)
	calls     [][]protocol.ResourceHandle
	events    *[]string
	loadError error
}

func (f *queryTestLoader) Load(_ context.Context, handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
	copyHandles := append([]protocol.ResourceHandle(nil), handles...)
	f.calls = append(f.calls, copyHandles)
	if f.events != nil {
		*f.events = append(*f.events, "load")
	}
	if f.loadError != nil {
		return nil, f.loadError
	}
	if f.load != nil {
		return f.load(copyHandles)
	}
	items := make([]protocol.EvidenceItem, 0, len(handles))
	for _, handle := range handles {
		item, ok := f.items[handle.ResourceID]
		if !ok {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func TestQueryScopesEvidencePerPrincipal(t *testing.T) {
	documentA := queryTestDocument(queryTestModelID, "alice content", "projection-v1")
	documentB := queryTestDocument(queryTestOtherID, "bob content", "projection-v1")
	for _, test := range []struct {
		principal string
		allowed   protocol.ResourceHandle
		denied    protocol.ResourceHandle
	}{
		{principal: "alice", allowed: documentA, denied: documentB},
		{principal: "bob", allowed: documentB, denied: documentA},
	} {
		t.Run(test.principal, func(t *testing.T) {
			events := []string{}
			backend := &queryTestKAG{events: &events, retrieveResult: queryTestRetrieve(documentA, documentB)}
			authorizer := &queryTestAuthorizer{events: &events}
			authorizer.decide = func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
					return check.Object == test.allowed.AuthorizationID
				}), nil
			}
			loader := &queryTestLoader{events: &events, items: map[protocol.ResourceID]protocol.EvidenceItem{
				documentA.ResourceID: queryTestItem(documentA), documentB.ResourceID: queryTestItem(documentB),
			}}
			service := queryTestService(t, backend, authorizer, loader, 0, 4)
			authorization := queryTestAuthorization(test.principal, "request-query")

			result, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "shared question", Authorization: authorization,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := result.Evidence.ValidateFor(authorization); err != nil {
				t.Fatalf("evidence package: %v", err)
			}
			if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{test.allowed.ResourceID}) {
				t.Fatalf("generation evidence = %v", got)
			}
			if len(loader.calls) != 1 || len(loader.calls[0]) != 1 || loader.calls[0][0] != test.allowed {
				t.Fatalf("loader received %#v", loader.calls)
			}
			if got := backend.lastRetrieve.AllowedResources; !reflect.DeepEqual(got, []protocol.ResourceHandle{test.allowed}) {
				t.Fatalf("retrieval authorization scope = %#v, want only %#v", got, test.allowed)
			}
			if strings.Contains(result.Generation.Answer, string(test.denied.ResourceID)) {
				t.Fatal("denied resource reached generation")
			}
			if got, want := events, []string{"discover", "authz", "retrieve", "load", "authz", "generate"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
			for _, call := range authorizer.calls {
				for _, check := range call.Checks {
					if check.User != "user:"+test.principal {
						t.Fatalf("authorization user = %q", check.User)
					}
				}
			}
		})
	}
}

func TestQueryFailsClosedBeforeRankingWhenDiscoveryIsIncomplete(t *testing.T) {
	resources := make([]protocol.ResourceHandle, maxPrimitiveLimit)
	for index := range resources {
		resources[index] = queryTestDocument(
			protocol.ResourceID(fmt.Sprintf("res_%032x", index+1)),
			"content",
			"projection-v1",
		)
	}
	backend := &queryTestKAG{discoverResult: &kag.DiscoverResult{
		Mode: "fake", Resources: resources, Complete: false,
	}}
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{}
	service := queryTestService(t, backend, authorizer, loader, 0, 4)

	_, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-incomplete-discovery"),
	})
	if !errors.Is(err, errIncompleteCandidateDiscovery) {
		t.Fatalf("incomplete discovery error = %v", err)
	}
	if len(authorizer.calls) != 0 || backend.retrieveCalls != 0 || len(loader.calls) != 0 || backend.generateCalls != 0 {
		t.Fatalf(
			"incomplete discovery crossed a protected boundary: authz=%d retrieve=%d load=%d generate=%d",
			len(authorizer.calls), backend.retrieveCalls, len(loader.calls), backend.generateCalls,
		)
	}
}

func TestQueryRunsFinalAuthorizationGateBeforeGeneration(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	events := []string{}
	backend := &queryTestKAG{events: &events, retrieveResult: queryTestRetrieve(document)}
	authorizer := &queryTestAuthorizer{events: &events}
	loader := &queryTestLoader{events: &events, items: map[protocol.ResourceID]protocol.EvidenceItem{
		document.ResourceID: queryTestItem(document),
	}}
	wantAuthorization := queryTestAuthorization("alice", "request-final-identity-gate")
	service, err := New(Options{
		KAG: backend, Authorizer: authorizer, Loader: loader,
		RetrieveLimit: 10, EvidenceLimit: 2,
		Now: func() time.Time { return time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC) },
		FinalAuthorizationGate: func(_ context.Context, authorization protocol.AuthorizationContext) error {
			events = append(events, "identity-gate")
			if authorization != wantAuthorization {
				t.Fatalf("final gate authorization = %+v, want %+v", authorization, wantAuthorization)
			}
			return errors.New("provider identity detail must not escape")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Query(context.Background(), protocol.QueryRequest{
		Question: "shared question", Authorization: wantAuthorization,
	})
	if err != ErrProtectedContentUnavailable || err.Error() != ErrProtectedContentUnavailable.Error() {
		t.Fatalf("query error = %v, want exact protected content unavailable", err)
	}
	if backend.generateCalls != 0 {
		t.Fatalf("generate calls = %d, want 0", backend.generateCalls)
	}
	if got, want := events, []string{"discover", "authz", "retrieve", "load", "authz", "identity-gate"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestQueryHidesDeniedResourceExistence(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	request := protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-hidden"),
	}

	absentService := queryTestService(t, &queryTestKAG{retrieveResult: queryTestRetrieve()}, &queryTestAuthorizer{}, &queryTestLoader{}, 0, 2)
	_, absentErr := absentService.Query(context.Background(), request)

	hiddenAuthorizer := &queryTestAuthorizer{decide: func(_ int, batch authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(batch, func(authz.BatchCheckItem) bool { return false }), nil
	}}
	hiddenService := queryTestService(t, &queryTestKAG{retrieveResult: queryTestRetrieve(document)}, hiddenAuthorizer, &queryTestLoader{}, 0, 2)
	_, hiddenErr := hiddenService.Query(context.Background(), request)

	revokedAuthorizer := &queryTestAuthorizer{decide: func(call int, batch authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(batch, func(authz.BatchCheckItem) bool { return call == 0 }), nil
	}}
	revokedBackend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
	revokedLoader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		document.ResourceID: queryTestItem(document),
	}}
	revokedService := queryTestService(t, revokedBackend, revokedAuthorizer, revokedLoader, 0, 2)
	_, revokedErr := revokedService.Query(context.Background(), request)

	for name, err := range map[string]error{"absent": absentErr, "hidden": hiddenErr, "revoked": revokedErr} {
		if !errors.Is(err, errNoEvidence) {
			t.Fatalf("%s error = %v, want generic no-evidence error", name, err)
		}
		if strings.Contains(err.Error(), string(document.ResourceID)) {
			t.Fatalf("%s error leaked denied resource ID: %v", name, err)
		}
	}
	if absentErr.Error() != hiddenErr.Error() || absentErr.Error() != revokedErr.Error() {
		t.Fatalf("externally visible errors differ: absent=%q hidden=%q revoked=%q", absentErr, hiddenErr, revokedErr)
	}
	if revokedBackend.generateCalls != 0 {
		t.Fatal("revoked evidence reached generation")
	}
}

func TestQueryFailsClosedOnMalformedBatchResults(t *testing.T) {
	documentA := queryTestDocument(queryTestModelID, "a", "projection-v1")
	documentB := queryTestDocument(queryTestOtherID, "b", "projection-v1")
	tests := []struct {
		name   string
		decide func(authz.BatchCheckRequest) ([]authz.Decision, error)
	}{
		{name: "error", decide: func(authz.BatchCheckRequest) ([]authz.Decision, error) { return nil, errors.New("unavailable") }},
		{name: "partial", decide: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true })[:1], nil
		}},
		{name: "duplicate", decide: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			decisions := queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true })
			decisions[1].CorrelationID = decisions[0].CorrelationID
			return decisions, nil
		}},
		{name: "unexpected", decide: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			decisions := queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true })
			decisions[0].CorrelationID = "unexpected"
			return decisions, nil
		}},
		{name: "model mismatch", decide: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			decisions := queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true })
			decisions[0].AuthorizationModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
			return decisions, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &queryTestKAG{retrieveResult: queryTestRetrieve(documentA, documentB)}
			authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				return test.decide(request)
			}}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{}}
			service := queryTestService(t, backend, authorizer, loader, 0, 4)
			if _, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-batch"),
			}); err == nil {
				t.Fatal("malformed authorization response should fail")
			}
			if len(loader.calls) != 0 || backend.generateCalls != 0 {
				t.Fatal("authorization failure reached content or generation")
			}
		})
	}
}

func TestQueryChunksFinalAuthorizationChecks(t *testing.T) {
	resources := make([]protocol.ResourceHandle, authz.MaxBatchChecks+1)
	supports := make([]protocol.ProvenanceSupport, len(resources))
	for index := range resources {
		id := protocol.ResourceID(fmt.Sprintf("res_%032x", index+1))
		resources[index] = queryTestDocument(id, "content", "projection-v1")
		supports[index] = protocol.ProvenanceSupport{
			SupportID: fmt.Sprintf("support-%03d", index),
			Resource:  resources[index],
			Evidence:  []protocol.ResourceHandle{resources[index]},
			Complete:  true,
		}
	}
	item := protocol.EvidenceItem{
		Resource: resources[0], Content: "content", Derivation: protocol.DerivationAllRequired,
		Supports: supports,
		Citation: protocol.Citation{Handle: "citation-large-provenance", Resource: resources[0]},
	}
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(resources[0])}
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{resources[0].ResourceID: item}}
	service := queryTestService(t, backend, authorizer, loader, 0, 1)
	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-large-provenance"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(authorizer.calls), 3; got != want {
		t.Fatalf("authorization calls = %d, want %d", got, want)
	}
	if got, want := len(authorizer.calls[1].Checks), authz.MaxBatchChecks; got != want {
		t.Fatalf("first final batch size = %d, want %d", got, want)
	}
	if got, want := len(authorizer.calls[2].Checks), 1; got != want {
		t.Fatalf("second final batch size = %d, want %d", got, want)
	}
	if got, want := len(result.Evidence.Decisions), len(resources); got != want {
		t.Fatalf("evidence decisions = %d, want %d", got, want)
	}
	if backend.generateCalls != 1 {
		t.Fatalf("generate calls = %d, want 1", backend.generateCalls)
	}
}

func TestQueryRejectsChunkBoundaryFromAnotherEvidenceItem(t *testing.T) {
	parent := queryTestDocument(queryTestModelID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestOtherID, parent, "chunk")
	other := queryTestDocument(queryTestThirdID, "b", "projection-v1")
	malformedChunk := protocol.EvidenceItem{
		Resource: chunk, Content: "chunk", Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-malformed-chunk", Resource: chunk,
			Evidence: []protocol.ResourceHandle{other}, Complete: true,
		}},
		Citation: protocol.Citation{Handle: "citation-malformed-chunk", Resource: chunk},
	}
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(chunk, parent)}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		chunk.ResourceID:  malformedChunk,
		parent.ResourceID: queryTestItem(parent),
	}}
	service := queryTestService(t, backend, &queryTestAuthorizer{}, loader, 0, 2)
	if _, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-item-boundary"),
	}); err == nil {
		t.Fatal("a different evidence item's provenance must not supply the chunk parent boundary")
	}
	if backend.generateCalls != 0 {
		t.Fatal("malformed chunk provenance reached generation")
	}
}

func TestQueryRejectsChunkBoundaryFromAnotherAnySupport(t *testing.T) {
	parent := queryTestDocument(queryTestModelID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestOtherID, parent, "chunk")
	other := queryTestDocument(queryTestThirdID, "b", "projection-v1")
	item := protocol.EvidenceItem{
		Resource: chunk, Content: "chunk", Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{
			{
				SupportID: "support-without-parent", Resource: chunk,
				Evidence: []protocol.ResourceHandle{other}, Complete: true,
			},
			{
				SupportID: "support-with-parent", Resource: parent,
				Evidence: []protocol.ResourceHandle{parent}, Complete: true,
			},
		},
		Citation: protocol.Citation{Handle: "citation-cross-support-chunk", Resource: chunk},
	}
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(chunk)}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{chunk.ResourceID: item}}
	service := queryTestService(t, backend, &queryTestAuthorizer{}, loader, 0, 1)
	if _, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-support-boundary"),
	}); err == nil {
		t.Fatal("an any_support branch must not borrow a chunk parent from another support")
	}
	if backend.generateCalls != 0 {
		t.Fatal("cross-support chunk boundary reached generation")
	}
}

func TestQueryRejectsInvalidRetrievalBeforeAuthorization(t *testing.T) {
	valid := queryTestDocument(queryTestModelID, "a", "projection-v1")
	crossTenant := valid
	crossTenant.TenantID = "other"
	nonServing := valid
	nonServing.ServingState = protocol.ServingRevoked
	otherProjection := queryTestDocument(queryTestOtherID, "b", "projection-v2")
	tests := []struct {
		name       string
		candidates []kag.CandidateHandle
	}{
		{name: "cross tenant", candidates: []kag.CandidateHandle{{Resource: crossTenant, Score: 0.9}}},
		{name: "non serving", candidates: []kag.CandidateHandle{{Resource: nonServing, Score: 0.9}}},
		{name: "mixed projection", candidates: []kag.CandidateHandle{{Resource: valid, Score: 0.9}, {Resource: otherProjection, Score: 0.8}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &queryTestKAG{retrieveResult: kag.RetrieveResult{Mode: "fake", Candidates: test.candidates}}
			authorizer := &queryTestAuthorizer{}
			loader := &queryTestLoader{}
			service := queryTestService(t, backend, authorizer, loader, 0, 4)
			if _, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-invalid"),
			}); err == nil {
				t.Fatal("invalid retrieval should fail")
			}
			if len(authorizer.calls) != 0 || len(loader.calls) != 0 || backend.generateCalls != 0 {
				t.Fatal("invalid retrieval crossed an authorization boundary")
			}
		})
	}
}

func TestNewRejectsLegacyUntypedExpandLimit(t *testing.T) {
	_, err := New(Options{
		KAG:           &queryTestKAG{},
		Authorizer:    &queryTestAuthorizer{},
		Loader:        &queryTestLoader{},
		RetrieveLimit: 10,
		EvidenceLimit: 3,
		ExpandLimit:   4,
	})
	if err == nil || !strings.Contains(err.Error(), "legacy untyped expand_limit") {
		t.Fatalf("New error = %v, want legacy untyped expand limit rejection", err)
	}
}

func TestQueryRejectsLoaderMutationAndFinalRevocation(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	t.Run("loader mutation", func(t *testing.T) {
		backend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
		authorizer := &queryTestAuthorizer{}
		loader := &queryTestLoader{load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
			mutated := queryTestItem(document)
			mutated.Resource.Versions.Content = "content-v2"
			mutated.Citation.Resource = mutated.Resource
			return []protocol.EvidenceItem{mutated}, nil
		}}
		service := queryTestService(t, backend, authorizer, loader, 0, 2)
		if _, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-loader"),
		}); err == nil {
			t.Fatal("mutated loader handle should fail")
		}
		if backend.generateCalls != 0 {
			t.Fatal("loader mutation reached generation")
		}
	})

	t.Run("final revocation", func(t *testing.T) {
		events := []string{}
		backend := &queryTestKAG{events: &events, retrieveResult: queryTestRetrieve(document)}
		authorizer := &queryTestAuthorizer{events: &events}
		authorizer.decide = func(call int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return call == 0 }), nil
		}
		loader := &queryTestLoader{events: &events, items: map[protocol.ResourceID]protocol.EvidenceItem{
			document.ResourceID: queryTestItem(document),
		}}
		service := queryTestService(t, backend, authorizer, loader, 0, 2)
		if _, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-revoke"),
		}); err == nil {
			t.Fatal("final revocation should fail")
		}
		if backend.generateCalls != 0 {
			t.Fatal("final revocation reached generation")
		}
		if got, want := events, []string{"discover", "authz", "retrieve", "load", "authz"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("events = %v, want %v", got, want)
		}
	})
}

func TestQueryRejectsExistingTombstoneBeforeGenerate(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	parent := queryTestDocument(queryTestOtherID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestThirdID, parent, "chunk")
	for _, test := range []struct {
		name      string
		resource  protocol.ResourceHandle
		item      protocol.EvidenceItem
		tombstone protocol.ResourceID
	}{
		{name: "evidence", resource: document, item: queryTestItem(document), tombstone: document.ResourceID},
		{name: "authorization boundary", resource: chunk, item: queryTestChunkItem(chunk, parent), tombstone: parent.ResourceID},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := mustQueryCache(t, 2)
			if _, err := cache.InvalidateResource(test.tombstone, time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)); err != nil {
				t.Fatal(err)
			}
			backend := &queryTestKAG{retrieveResult: queryTestRetrieve(test.resource)}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				test.resource.ResourceID: test.item,
			}}
			service := cacheTestService(
				t, backend, &queryTestAuthorizer{}, loader, cache, "retriever-v1", "prompt-v1",
			)

			_, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-tombstone-"+test.name),
			})
			if !errors.Is(err, ErrProtectedContentUnavailable) {
				t.Fatalf("query error = %v, want protected content unavailable", err)
			}
			if backend.retrieveCalls != 1 || backend.generateCalls != 0 {
				t.Fatalf("KAG calls: retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
			}
		})
	}
}

func TestQueryFailsClosedWithoutFallback(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	t.Run("retrieve error", func(t *testing.T) {
		backend := &queryTestKAG{retrieveErr: errors.New("KAG unavailable")}
		authorizer := &queryTestAuthorizer{}
		loader := &queryTestLoader{}
		service := queryTestService(t, backend, authorizer, loader, 0, 2)
		if _, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-retrieve-error"),
		}); err == nil {
			t.Fatal("retrieve failure should fail closed")
		}
		if len(authorizer.calls) != 0 || len(loader.calls) != 0 || backend.generateCalls != 0 {
			t.Fatal("retrieve failure triggered a fallback path")
		}
	})

	for _, test := range []struct {
		name string
		load func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error)
	}{
		{name: "missing", load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) { return nil, nil }},
		{name: "extra", load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
			item := queryTestItem(document)
			return []protocol.EvidenceItem{item, item}, nil
		}},
	} {
		t.Run("loader "+test.name, func(t *testing.T) {
			backend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
			loader := &queryTestLoader{load: test.load}
			service := queryTestService(t, backend, &queryTestAuthorizer{}, loader, 0, 2)
			if _, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-loader-"+test.name),
			}); err == nil {
				t.Fatalf("loader %s result should fail", test.name)
			}
			if backend.generateCalls != 0 {
				t.Fatal("invalid loader result reached generation")
			}
		})
	}
}

func TestOpenCitationReauthorizesChunkBoundary(t *testing.T) {
	parent := queryTestDocument(queryTestModelID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestOtherID, parent, "chunk")
	chunkItem := queryTestChunkItem(chunk, parent)
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(chunk)}
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{chunk.ResourceID: chunkItem}}
	service := queryTestService(t, backend, authorizer, loader, 0, 2)
	authorization := queryTestAuthorization("alice", "request-query")
	result, err := service.Query(context.Background(), protocol.QueryRequest{Question: "q", Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	if len(authorizer.calls) != 2 || len(authorizer.calls[0].Checks) != 1 || len(authorizer.calls[1].Checks) != 1 {
		t.Fatalf("chunk/document authorization was not deduplicated: %#v", authorizer.calls)
	}

	authorizer.calls = nil
	loader.calls = nil
	current := authorization
	current.RequestID = "request-citation"
	opened, err := service.OpenCitation(context.Background(), current, result.Evidence, chunkItem.Citation.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, chunkItem) {
		t.Fatalf("opened citation = %#v", opened)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("live citation checks = %#v", authorizer.calls)
	}
	for _, call := range authorizer.calls {
		if len(call.Checks) != 1 || call.Checks[0].Object != parent.AuthorizationID {
			t.Fatalf("live citation checks = %#v", authorizer.calls)
		}
		if call.Consistency != authz.ConsistencyHigherConsistency {
			t.Fatalf("live citation consistency = %q", call.Consistency)
		}
	}
	if len(loader.calls) != 1 || !reflect.DeepEqual(loader.calls[0], []protocol.ResourceHandle{chunk}) {
		t.Fatalf("citation loader calls = %#v", loader.calls)
	}
}

func TestOpenCitationFailsClosed(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	item := queryTestItem(document)
	authorization := queryTestAuthorization("alice", "request-query")
	baseBackend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
	baseAuthorizer := &queryTestAuthorizer{}
	baseLoader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{document.ResourceID: item}}
	baseService := queryTestService(t, baseBackend, baseAuthorizer, baseLoader, 0, 2)
	result, err := baseService.Query(context.Background(), protocol.QueryRequest{Question: "q", Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	current := authorization
	current.RequestID = "request-citation"

	for _, test := range []struct {
		name   string
		decide func(authz.BatchCheckRequest) ([]authz.Decision, error)
	}{
		{name: "denied", decide: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return false }), nil
		}},
		{name: "error", decide: func(authz.BatchCheckRequest) ([]authz.Decision, error) {
			return nil, errors.New("AUTHORIZATION_CANARY")
		}},
		{name: "missing", decide: func(authz.BatchCheckRequest) ([]authz.Decision, error) { return nil, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				return test.decide(request)
			}}
			loader := &queryTestLoader{items: baseLoader.items}
			service := queryTestService(t, &queryTestKAG{}, authorizer, loader, 0, 2)
			if _, err := service.OpenCitation(context.Background(), current, result.Evidence, item.Citation.Handle); !errors.Is(err, ErrCitationUnavailable) {
				t.Fatalf("%s citation authorization should fail", test.name)
			} else if strings.Contains(err.Error(), "AUTHORIZATION_CANARY") || strings.Contains(err.Error(), string(document.ResourceID)) {
				t.Fatalf("%s citation error leaked protected metadata: %v", test.name, err)
			}
			if len(loader.calls) != 0 {
				t.Fatalf("%s citation reached loader", test.name)
			}
		})
	}

	t.Run("revoked after load", func(t *testing.T) {
		authorizer := &queryTestAuthorizer{decide: func(call int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return call == 0 }), nil
		}}
		loader := &queryTestLoader{items: baseLoader.items}
		service := queryTestService(t, &queryTestKAG{}, authorizer, loader, 0, 2)
		if _, err := service.OpenCitation(context.Background(), current, result.Evidence, item.Citation.Handle); err == nil {
			t.Fatal("citation revoked after loading should fail")
		}
		if len(loader.calls) != 1 || len(authorizer.calls) != 2 {
			t.Fatalf("citation revocation events: authz=%d load=%d", len(authorizer.calls), len(loader.calls))
		}
	})

	t.Run("mutated loader item", func(t *testing.T) {
		authorizer := &queryTestAuthorizer{}
		loader := &queryTestLoader{load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
			mutated := item
			other := queryTestDocument(queryTestOtherID, "b", document.Versions.Projection)
			mutated.Supports = append([]protocol.ProvenanceSupport(nil), item.Supports...)
			mutated.Supports[0].Evidence = []protocol.ResourceHandle{other}
			return []protocol.EvidenceItem{mutated}, nil
		}}
		service := queryTestService(t, &queryTestKAG{}, authorizer, loader, 0, 2)
		if _, err := service.OpenCitation(context.Background(), current, result.Evidence, item.Citation.Handle); err == nil {
			t.Fatal("mutated citation should fail")
		}
	})

	for _, mutate := range []func(*protocol.AuthorizationContext){
		func(value *protocol.AuthorizationContext) { value.TenantID = "other" },
		func(value *protocol.AuthorizationContext) { value.KnowledgeBaseID = "other" },
		func(value *protocol.AuthorizationContext) { value.PrincipalID = "bob" },
		func(value *protocol.AuthorizationContext) { value.SessionID = "session-2" },
		func(value *protocol.AuthorizationContext) { value.AgentID = "agent-2" },
		func(value *protocol.AuthorizationContext) { value.TaskID = "task-2" },
	} {
		mismatched := current
		mutate(&mismatched)
		service := queryTestService(t, &queryTestKAG{}, &queryTestAuthorizer{}, baseLoader, 0, 2)
		if _, err := service.OpenCitation(context.Background(), mismatched, result.Evidence, item.Citation.Handle); err == nil {
			t.Fatal("mismatched current authorization should fail")
		}
	}
	if _, err := baseService.OpenCitation(context.Background(), current, result.Evidence, "unknown"); err == nil {
		t.Fatal("unknown citation should fail")
	}
}

func TestOpenCitationUsesCurrentModelWithStaleWatermarks(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	item := queryTestItem(document)
	original := queryTestAuthorization("alice", "request-original-model")
	baseService := queryTestService(
		t,
		&queryTestKAG{retrieveResult: queryTestRetrieve(document)},
		&queryTestAuthorizer{},
		&queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{document.ResourceID: item}},
		0,
		2,
	)
	result, err := baseService.Query(context.Background(), protocol.QueryRequest{Question: "q", Authorization: original})
	if err != nil {
		t.Fatal(err)
	}

	current := original
	current.RequestID = "request-current-model"
	current.AuthorizationModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
	current.Consistency = protocol.ConsistencyMinimizeLatency
	authorizer := &queryTestAuthorizer{}
	service := queryTestService(
		t,
		&queryTestKAG{},
		authorizer,
		&queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{document.ResourceID: item}},
		0,
		2,
	)
	opened, err := service.OpenCitation(context.Background(), current, result.Evidence, item.Citation.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, item) {
		t.Fatalf("opened citation = %#v", opened)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("current-model citation checks = %d", len(authorizer.calls))
	}
	for _, call := range authorizer.calls {
		if call.AuthorizationModelID != current.AuthorizationModelID || call.Consistency != authz.ConsistencyHigherConsistency {
			t.Fatalf("current-model citation check = %#v", call)
		}
	}
}

func TestOpenCitationRejectsTombstoneIntroducedDuringFinalCheck(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	item := queryTestItem(document)
	authorization := queryTestAuthorization("alice", "request-query")
	baseService := queryTestService(
		t,
		&queryTestKAG{retrieveResult: queryTestRetrieve(document)},
		&queryTestAuthorizer{},
		&queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{document.ResourceID: item}},
		0,
		2,
	)
	result, err := baseService.Query(context.Background(), protocol.QueryRequest{Question: "q", Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}

	cache := mustQueryCache(t, 2)
	var invalidationErr error
	authorizer := &queryTestAuthorizer{decide: func(call int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		if call == 1 {
			_, invalidationErr = cache.InvalidateResource(
				document.ResourceID, time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC),
			)
		}
		return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{document.ResourceID: item}}
	service := cacheTestService(t, &queryTestKAG{}, authorizer, loader, cache, "retriever-v1", "prompt-v1")
	current := authorization
	current.RequestID = "request-citation"

	opened, err := service.OpenCitation(context.Background(), current, result.Evidence, item.Citation.Handle)
	if invalidationErr != nil {
		t.Fatal(invalidationErr)
	}
	if !errors.Is(err, ErrCitationUnavailable) {
		t.Fatalf("open citation error = %v, want citation unavailable", err)
	}
	if !reflect.DeepEqual(opened, protocol.EvidenceItem{}) {
		t.Fatalf("open citation returned protected content: %#v", opened)
	}
	if len(authorizer.calls) != 2 || len(loader.calls) != 1 {
		t.Fatalf("citation checks: authz=%d load=%d", len(authorizer.calls), len(loader.calls))
	}
}

func TestServiceRejectsNilContextAndMissingDependencies(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("missing dependencies should fail")
	}
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	service := queryTestService(t, &queryTestKAG{retrieveResult: queryTestRetrieve(document)}, &queryTestAuthorizer{}, &queryTestLoader{}, 0, 2)
	if _, err := service.Query(nil, protocol.QueryRequest{Question: "q", Authorization: queryTestAuthorization("alice", "request")}); err == nil {
		t.Fatal("nil query context should fail")
	}
}

func queryTestService(t *testing.T, backend *queryTestKAG, authorizer *queryTestAuthorizer, loader *queryTestLoader, expandLimit, evidenceLimit int) *Service {
	t.Helper()
	service, err := New(Options{
		KAG: backend, Authorizer: authorizer, Loader: loader,
		RetrieveLimit: 10, EvidenceLimit: evidenceLimit, ExpandLimit: expandLimit,
		Now: func() time.Time { return time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func queryTestAuthorization(principal, requestID string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version: protocol.SecurityContractVersion, TenantID: "tenant-1", KnowledgeBaseID: "kb-1",
		PrincipalID: principal, SessionID: "session-1", RequestID: requestID,
		AgentID: "agent-1", TaskID: "task-1", AuthorizationModelID: queryTestAuthModel,
		IdentityWatermark: "identity-v1", ACLWatermark: "acl-v1",
		Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func queryTestDocument(id protocol.ResourceID, content, projection string) protocol.ResourceHandle {
	return protocol.ResourceHandle{
		ResourceID: id, Type: protocol.ResourceDocument, TenantID: "tenant-1", KnowledgeBaseID: "kb-1",
		AuthorizationID: "document:" + string(id), AuthorizationResourceID: id,
		ContentDigest: protocol.NewContentDigest(content), ServingState: protocol.ServingActive,
		Versions: protocol.ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1", Index: "index-v1",
			Graph: "graph-v1", Projection: projection,
		},
	}
}

func queryTestChunk(id protocol.ResourceID, parent protocol.ResourceHandle, content string) protocol.ResourceHandle {
	chunk := queryTestDocument(id, content, parent.Versions.Projection)
	chunk.Type = protocol.ResourceChunk
	chunk.AuthorizationID = parent.AuthorizationID
	chunk.AuthorizationResourceID = parent.ResourceID
	chunk.Versions.ACL = parent.Versions.ACL
	return chunk
}

func queryTestItem(resource protocol.ResourceHandle) protocol.EvidenceItem {
	content := queryTestContent(resource)
	return protocol.EvidenceItem{
		Resource: resource, Content: content, Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-" + string(resource.ResourceID), Resource: resource,
			Evidence: []protocol.ResourceHandle{resource}, Complete: true,
		}},
		Citation: protocol.Citation{Handle: "citation-" + string(resource.ResourceID), Resource: resource},
	}
}

func queryTestChunkItem(chunk, parent protocol.ResourceHandle) protocol.EvidenceItem {
	return protocol.EvidenceItem{
		Resource: chunk, Content: queryTestContent(chunk), Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-" + string(chunk.ResourceID), Resource: chunk,
			Evidence: []protocol.ResourceHandle{parent}, Complete: true,
		}},
		Citation: protocol.Citation{Handle: "citation-" + string(chunk.ResourceID), Resource: chunk},
	}
}

func queryTestContent(resource protocol.ResourceHandle) string {
	for _, value := range []string{"alice content", "bob content", "content", "parent", "chunk", "a", "b", "c", "d"} {
		if protocol.NewContentDigest(value) == resource.ContentDigest {
			return value
		}
	}
	panic(fmt.Sprintf("unknown test content digest %s", resource.ContentDigest))
}

func queryTestRetrieve(resources ...protocol.ResourceHandle) kag.RetrieveResult {
	result := kag.RetrieveResult{Mode: "fake"}
	for index, resource := range resources {
		result.Candidates = append(result.Candidates, kag.CandidateHandle{Resource: resource, Score: 0.9 - float64(index)*0.1})
	}
	return result
}

func queryTestDecisions(request authz.BatchCheckRequest, allowed func(authz.BatchCheckItem) bool) []authz.Decision {
	decisions := make([]authz.Decision, len(request.Checks))
	for index, check := range request.Checks {
		decisions[index] = authz.Decision{
			CorrelationID: check.CorrelationID, Allowed: allowed(check),
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions
}
