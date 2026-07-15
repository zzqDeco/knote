package authorized

import (
	"context"
	"encoding/json"
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

const traversalTestProjection = "prj_11111111111111111111111111111111"

type traversalTestBackend struct {
	discover       *kag.DiscoverResult
	retrieve       kag.RetrieveResult
	expand         func(context.Context, int, kag.ExpandRequest) (kag.ExpandResult, error)
	expandRequests []kag.ExpandRequest
	discoverCalls  int
	retrieveCalls  int
	generateCalls  int
	lastDiscover   kag.DiscoverRequest
	lastRetrieve   kag.RetrieveRequest
	lastGenerate   kag.GenerateRequest
	events         *[]string
}

func (backend *traversalTestBackend) Discover(
	_ context.Context,
	request kag.DiscoverRequest,
) (kag.DiscoverResult, error) {
	backend.discoverCalls++
	backend.lastDiscover = request
	if backend.discover != nil {
		return *backend.discover, nil
	}
	resources := make([]protocol.ResourceHandle, 0, len(backend.retrieve.Candidates))
	seen := make(map[protocol.ResourceID]struct{}, len(backend.retrieve.Candidates))
	for _, candidate := range backend.retrieve.Candidates {
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
	return kag.DiscoverResult{Mode: "fake", Resources: resources, Complete: true}, nil
}

func (backend *traversalTestBackend) Retrieve(
	_ context.Context,
	request kag.RetrieveRequest,
) (kag.RetrieveResult, error) {
	backend.retrieveCalls++
	backend.lastRetrieve = request
	allowed := make(map[protocol.ResourceID]protocol.ResourceHandle, len(request.AllowedResources))
	for _, resource := range request.AllowedResources {
		allowed[resource.ResourceID] = resource
	}
	result := backend.retrieve
	result.Candidates = nil
	for _, candidate := range backend.retrieve.Candidates {
		if resource, ok := allowed[candidate.Resource.ResourceID]; ok && resource == candidate.Resource {
			result.Candidates = append(result.Candidates, candidate)
		}
	}
	return result, nil
}

func (backend *traversalTestBackend) Expand(
	ctx context.Context,
	request kag.ExpandRequest,
) (kag.ExpandResult, error) {
	call := len(backend.expandRequests)
	backend.expandRequests = append(backend.expandRequests, request)
	if backend.events != nil {
		*backend.events = append(*backend.events, "expand:"+string(request.Phase))
	}
	if backend.expand == nil {
		return kag.ExpandResult{Mode: "fake"}, nil
	}
	return backend.expand(ctx, call, request)
}

func (backend *traversalTestBackend) Generate(
	_ context.Context,
	request kag.GenerateRequest,
) (kag.GenerateResult, error) {
	backend.generateCalls++
	backend.lastGenerate = request.Clone()
	result := kag.GenerateResult{Mode: "fake", Answer: "authorized traversal answer"}
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

type traversalTestAuthorizer struct {
	calls  []authz.BatchCheckRequest
	decide func(context.Context, int, authz.BatchCheckRequest) ([]authz.Decision, error)
	events *[]string
}

func (authorizer *traversalTestAuthorizer) BatchCheck(
	ctx context.Context,
	request authz.BatchCheckRequest,
) ([]authz.Decision, error) {
	call := len(authorizer.calls)
	authorizer.calls = append(authorizer.calls, request)
	if authorizer.events != nil {
		kind := "resource"
		if len(request.Checks) > 0 {
			kind = strings.SplitN(request.Checks[0].Object, ":", 2)[0]
		}
		*authorizer.events = append(*authorizer.events, "check:"+kind)
	}
	if authorizer.decide != nil {
		return authorizer.decide(ctx, call, request)
	}
	return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
}

func TestTraversalZeroOneAndMultipleHops(t *testing.T) {
	start := traversalTestResource(1, protocol.ResourceEntity, "a")
	claimOne := traversalTestResource(2, protocol.ResourceClaim, "content")
	entityTwo := traversalTestResource(3, protocol.ResourceEntity, "b")
	claimTwo := traversalTestResource(4, protocol.ResourceClaim, "content")
	entityThree := traversalTestResource(5, protocol.ResourceEntity, "c")
	support := traversalTestResource(90, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)

	for _, test := range []struct {
		name            string
		depth           int
		wantTerminal    protocol.ResourceHandle
		wantExpandCalls int
		wantPath        []protocol.ResourceID
	}{
		{name: "zero", depth: 0, wantTerminal: start, wantExpandCalls: 0, wantPath: []protocol.ResourceID{start.ResourceID}},
		{name: "one", depth: 1, wantTerminal: entityTwo, wantExpandCalls: 2, wantPath: []protocol.ResourceID{
			start.ResourceID, claimOne.ResourceID, entityTwo.ResourceID,
		}},
		{name: "multiple", depth: 2, wantTerminal: entityThree, wantExpandCalls: 4, wantPath: []protocol.ResourceID{
			start.ResourceID, claimOne.ResourceID, entityTwo.ResourceID, claimTwo.ResourceID, entityThree.ResourceID,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
			backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
				switch request.Phase {
				case kag.ExpandPhaseEntityToClaim:
					switch request.Frontier[0].Resource.ResourceID {
					case start.ResourceID:
						return traversalTestExpansion(
							[]kag.CandidateHandle{{Resource: claimOne, Score: 0.9}},
							[]kag.ExpansionHandle{traversalTestEdge(start, claimOne, claimOne, predicate)},
						), nil
					case entityTwo.ResourceID:
						return traversalTestExpansion(
							[]kag.CandidateHandle{{Resource: claimTwo, Score: 0.8}},
							[]kag.ExpansionHandle{traversalTestEdge(entityTwo, claimTwo, claimTwo, predicate)},
						), nil
					}
				case kag.ExpandPhaseClaimToObject:
					switch request.Frontier[0].Resource.ResourceID {
					case claimOne.ResourceID:
						return traversalTestExpansion(
							[]kag.CandidateHandle{{Resource: entityTwo, Score: 0.8}},
							[]kag.ExpansionHandle{traversalTestEdge(claimOne, entityTwo, claimOne, predicate)},
						), nil
					case claimTwo.ResourceID:
						return traversalTestExpansion(
							[]kag.CandidateHandle{{Resource: entityThree, Score: 0.7}},
							[]kag.ExpansionHandle{traversalTestEdge(claimTwo, entityThree, claimTwo, predicate)},
						), nil
					}
				}
				return kag.ExpandResult{Mode: "fake"}, nil
			}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				test.wantTerminal.ResourceID: traversalTestEvidence(test.wantTerminal, support),
			}}
			service := traversalTestService(t, backend, &traversalTestAuthorizer{}, loader, traversalTestConfig(test.depth))

			result, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-"+test.name),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{test.wantTerminal.ResourceID}) {
				t.Fatalf("terminal evidence = %v", got)
			}
			if len(backend.expandRequests) != test.wantExpandCalls {
				t.Fatalf("expand calls = %d, want %d", len(backend.expandRequests), test.wantExpandCalls)
			}
			for index, request := range backend.expandRequests {
				wantPhase := kag.ExpandPhaseEntityToClaim
				if index%2 == 1 {
					wantPhase = kag.ExpandPhaseClaimToObject
				}
				if request.Phase != wantPhase || request.Operation.Parameters.ProjectionVersion != traversalTestProjection ||
					request.Operation.Parameters.IdentityVersion != protocol.GraphBindingContractVersion {
					t.Fatalf("expand request %d lost its exact operation binding: %+v", index, request)
				}
				for _, order := range request.Operation.Parameters.Order {
					if order.Key == protocol.GraphSortPredicateKey {
						t.Fatalf("expand request %d ranks before Claim authorization by predicate key: %+v", index, request.Operation.Parameters.Order)
					}
				}
			}
			wantDecisions := append(append([]protocol.ResourceID(nil), test.wantPath...), support.ResourceID)
			if got := traversalDecisionResourceIDs(result.Evidence); !reflect.DeepEqual(got, wantDecisions) {
				t.Fatalf("decision resources = %v, want %v", got, wantDecisions)
			}
			if len(backend.lastGenerate.Paths) != 1 {
				t.Fatalf("generator paths = %#v, want exactly one selected path", backend.lastGenerate.Paths)
			}
			generatedPath := backend.lastGenerate.Paths[0]
			if got := traversalGeneratePathResourceIDs(generatedPath); !reflect.DeepEqual(got, test.wantPath) {
				t.Fatalf("generator path resources = %v, want %v", got, test.wantPath)
			}
			if generatedPath.ClaimBindings == nil || len(generatedPath.ClaimBindings) != test.depth {
				t.Fatalf("generator Claim bindings = %#v, want %d", generatedPath.ClaimBindings, test.depth)
			}
			for index, binding := range generatedPath.ClaimBindings {
				if binding.ParentResourceID != test.wantPath[index*2] ||
					binding.ClaimResourceID != test.wantPath[index*2+1] ||
					binding.ObjectResourceID != test.wantPath[index*2+2] ||
					binding.PredicateKey != predicate {
					t.Fatalf("generator Claim binding %d = %#v", index, binding)
				}
			}
		})
	}
}

func TestTraversalChecksClaimBeforeObjectExpansionAndDropsDeniedCanary(t *testing.T) {
	events := []string{}
	start := traversalTestResource(10, protocol.ResourceEntity, "a")
	allowedClaim := traversalTestResource(11, protocol.ResourceClaim, "content")
	deniedClaim := traversalTestResource(12, protocol.ResourceClaim, "DENIED CLAIM BODY CANARY")
	terminal := traversalTestResource(13, protocol.ResourceEntity, "b")
	support := traversalTestResource(91, protocol.ResourceDocument, "parent")
	allowedPredicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	deniedPredicate := traversalTestPredicate(t, protocol.ClaimPredicateSupports)
	backend := &traversalTestBackend{events: &events, retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		switch request.Phase {
		case kag.ExpandPhaseEntityToClaim:
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: deniedClaim, Score: 0.99}, {Resource: allowedClaim, Score: 0.7}},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, allowedClaim, allowedClaim, allowedPredicate),
					traversalTestEdge(start, deniedClaim, allowedClaim, deniedPredicate),
				},
			), nil
		case kag.ExpandPhaseClaimToObject:
			if len(request.Frontier) != 1 || request.Frontier[0].Resource != allowedClaim {
				t.Fatalf("object expansion frontier = %#v", request.Frontier)
			}
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
				[]kag.ExpansionHandle{traversalTestEdge(allowedClaim, terminal, allowedClaim, allowedPredicate)},
			), nil
		default:
			return kag.ExpandResult{}, errors.New("unexpected phase")
		}
	}
	authorizer := &traversalTestAuthorizer{events: &events}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != deniedClaim.AuthorizationID
		}), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		terminal.ResourceID: traversalTestEvidence(terminal, support),
	}}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(1))

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-denied-claim"),
	})
	if err != nil {
		t.Fatal(err)
	}
	claimCheck := traversalEventIndex(events, "check:claim")
	objectExpand := traversalEventIndex(events, "expand:"+string(kag.ExpandPhaseClaimToObject))
	if claimCheck < 0 || objectExpand < 0 || claimCheck > objectExpand {
		t.Fatalf("events = %v", events)
	}
	for _, decision := range result.Evidence.Decisions {
		if decision.Resource.ResourceID == deniedClaim.ResourceID {
			t.Fatal("denied Claim entered evidence decisions")
		}
	}
	encoded := fmt.Sprintf("%+v", backend.lastGenerate)
	if strings.Contains(encoded, "DENIED CLAIM BODY CANARY") || strings.Contains(encoded, string(deniedPredicate)) {
		t.Fatalf("denied Claim canary entered generation: %s", encoded)
	}
	if len(loader.calls) != 1 || !reflect.DeepEqual(loader.calls[0], []protocol.ResourceHandle{terminal}) {
		t.Fatalf("loader calls = %#v", loader.calls)
	}
	if result.Traversal == nil {
		t.Fatal("authorized traversal report is missing")
	}
	wantDrops := []TraversalHopDrop{
		{Hop: 0, Phase: TraversalPhaseDiscovery, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
		{Hop: 0, Phase: TraversalPhaseStart, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
		{Hop: 1, Phase: TraversalPhaseClaim, CandidateCount: 2, AllowedCount: 1, DroppedCount: 1},
		{Hop: 1, Phase: TraversalPhaseObject, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
	}
	if result.Traversal.AuthorizedPathCompleteness != 1 ||
		result.Traversal.SelectedPathCount != 1 || result.Traversal.CompletePathCount != 1 ||
		result.Traversal.BatchCheckRPCCount != 5 || !reflect.DeepEqual(result.Traversal.HopDrops, wantDrops) {
		t.Fatalf("authorized traversal report = %#v", result.Traversal)
	}
	encodedReport, err := json.Marshal(result.Traversal)
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{"DENIED CLAIM BODY CANARY", string(deniedPredicate), string(deniedClaim.ResourceID)} {
		if strings.Contains(string(encodedReport), protected) {
			t.Fatalf("traversal report leaked protected value %q: %s", protected, encodedReport)
		}
	}
}

func TestTraversalAppliesCandidateLimitAfterClaimAuthorization(t *testing.T) {
	start := traversalTestResource(14, protocol.ResourceEntity, "a")
	deniedClaim := traversalTestResource(15, protocol.ResourceClaim, "content")
	allowedClaim := traversalTestResource(16, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(17, protocol.ResourceEntity, "b")
	support := traversalTestResource(18, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		if request.Limit != maxPrimitiveLimit {
			t.Fatalf("provider scan limit = %d, want %d", request.Limit, maxPrimitiveLimit)
		}
		if request.Phase == kag.ExpandPhaseEntityToClaim {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: deniedClaim, Score: 0.99}, {Resource: allowedClaim, Score: 0.8}},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, deniedClaim, deniedClaim, predicate),
					traversalTestEdge(start, allowedClaim, allowedClaim, predicate),
				},
			), nil
		}
		if len(request.Frontier) != 1 || request.Frontier[0].Resource != allowedClaim {
			t.Fatalf("object frontier = %+v, want only allowed Claim", request.Frontier)
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: terminal, Score: 0.7}},
			[]kag.ExpansionHandle{traversalTestEdge(allowedClaim, terminal, allowedClaim, predicate)},
		), nil
	}
	authorizer := &traversalTestAuthorizer{}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != deniedClaim.AuthorizationID
		}), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		terminal.ResourceID: traversalTestEvidence(terminal, support),
	}}
	config := traversalTestConfig(1)
	config.Limits.MaxCandidatesPerHop = 1
	service := traversalTestService(t, backend, authorizer, loader, config)
	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-authorized-candidate-limit"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{terminal.ResourceID}) {
		t.Fatalf("terminal evidence = %v", got)
	}
}

func TestTraversalEvidenceLimitBackfillsAfterFinalPathDeny(t *testing.T) {
	first := traversalTestResource(19, protocol.ResourceEntity, "a")
	second := traversalTestResource(20, protocol.ResourceEntity, "b")
	deniedSupport := traversalTestResource(21, protocol.ResourceDocument, "c")
	allowedSupport := traversalTestResource(22, protocol.ResourceDocument, "parent")
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(first, second)}
	authorizer := &traversalTestAuthorizer{}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != deniedSupport.AuthorizationID
		}), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		first.ResourceID:  traversalTestEvidence(first, deniedSupport),
		second.ResourceID: traversalTestEvidence(second, allowedSupport),
	}}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(0))
	service.evidenceLimit = 1
	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-final-path-backfill"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{second.ResourceID}) {
		t.Fatalf("backfilled terminal evidence = %v, want %s", got, second.ResourceID)
	}
	if result.Traversal == nil || result.Traversal.SelectedPathCount != 2 ||
		result.Traversal.CompletePathCount != 1 || result.Traversal.AuthorizedPathCompleteness != 0.5 {
		t.Fatalf("backfilled traversal report = %#v", result.Traversal)
	}
}

func TestTraversalDeterministicallyDeduplicatesPathsAndStopsCycles(t *testing.T) {
	start := traversalTestResource(20, protocol.ResourceEntity, "a")
	lowClaim := traversalTestResource(21, protocol.ResourceClaim, "content")
	highClaim := traversalTestResource(22, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(23, protocol.ResourceEntity, "b")
	cycleClaim := traversalTestResource(24, protocol.ResourceClaim, "content")
	support := traversalTestResource(92, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		frontierID := request.Frontier[0].Resource.ResourceID
		if request.Phase == kag.ExpandPhaseEntityToClaim && frontierID == start.ResourceID {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: highClaim, Score: 0.9}, {Resource: lowClaim, Score: 0.4}},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, lowClaim, lowClaim, predicate),
					traversalTestEdge(start, highClaim, highClaim, predicate),
				},
			), nil
		}
		if request.Phase == kag.ExpandPhaseClaimToObject && len(request.Frontier) == 2 {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
				[]kag.ExpansionHandle{
					traversalTestEdge(lowClaim, terminal, lowClaim, predicate),
					traversalTestEdge(highClaim, terminal, highClaim, predicate),
				},
			), nil
		}
		if request.Phase == kag.ExpandPhaseEntityToClaim && frontierID == terminal.ResourceID {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: cycleClaim, Score: 0.9}},
				[]kag.ExpansionHandle{traversalTestEdge(terminal, cycleClaim, cycleClaim, predicate)},
			), nil
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: start, Score: 0.9}},
			[]kag.ExpansionHandle{traversalTestEdge(cycleClaim, start, cycleClaim, predicate)},
		), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		terminal.ResourceID: traversalTestEvidence(terminal, support),
	}}
	service := traversalTestService(t, backend, &traversalTestAuthorizer{}, loader, traversalTestConfig(2))

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-cycle"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{terminal.ResourceID}) {
		t.Fatalf("terminals = %v", got)
	}
	decisions := traversalDecisionResourceIDs(result.Evidence)
	if traversalContainsID(decisions, lowClaim.ResourceID) || traversalContainsID(decisions, cycleClaim.ResourceID) {
		t.Fatalf("discarded duplicate or cycle path entered decisions: %v", decisions)
	}
	if !traversalContainsID(decisions, highClaim.ResourceID) {
		t.Fatalf("highest inherited-score path was not retained: %v", decisions)
	}
}

func TestTraversalFinalAuthorizationFallsBackToAlternatePathForSameTerminal(t *testing.T) {
	start := traversalTestResource(25, protocol.ResourceEntity, "a")
	highClaim := traversalTestResource(26, protocol.ResourceClaim, "content")
	lowClaim := traversalTestResource(27, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(28, protocol.ResourceEntity, "b")
	support := traversalTestResource(29, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		switch request.Phase {
		case kag.ExpandPhaseEntityToClaim:
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: highClaim, Score: 0.9}, {Resource: lowClaim, Score: 0.8}},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, highClaim, highClaim, predicate),
					traversalTestEdge(start, lowClaim, lowClaim, predicate),
				},
			), nil
		case kag.ExpandPhaseClaimToObject:
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: terminal, Score: 0.9}},
				[]kag.ExpansionHandle{
					traversalTestEdge(highClaim, terminal, highClaim, predicate),
					traversalTestEdge(lowClaim, terminal, lowClaim, predicate),
				},
			), nil
		default:
			return kag.ExpandResult{Mode: "fake"}, nil
		}
	}
	authorizer := &traversalTestAuthorizer{}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return !strings.HasPrefix(check.CorrelationID, "tr-final-") || check.Object != highClaim.AuthorizationID
		}), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		terminal.ResourceID: traversalTestEvidence(terminal, support),
	}}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(1))

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-alternate-path"),
	})
	if err != nil {
		t.Fatal(err)
	}
	decisions := traversalDecisionResourceIDs(result.Evidence)
	if traversalContainsID(decisions, highClaim.ResourceID) || !traversalContainsID(decisions, lowClaim.ResourceID) {
		t.Fatalf("final path decisions = %v, want only the authorized alternate Claim", decisions)
	}
	if len(backend.lastGenerate.Paths) != 1 || !reflect.DeepEqual(
		traversalGeneratePathResourceIDs(backend.lastGenerate.Paths[0]),
		[]protocol.ResourceID{start.ResourceID, lowClaim.ResourceID, terminal.ResourceID},
	) {
		t.Fatalf("generator did not receive the authorized alternate path: %#v", backend.lastGenerate.Paths)
	}
}

func TestTraversalFinalAuthorizationRanksOnlySurvivingPaths(t *testing.T) {
	start := traversalTestResource(0x40, protocol.ResourceEntity, "a")
	deniedHighClaim := traversalTestResource(0x41, protocol.ResourceClaim, "content")
	allowedLowClaim := traversalTestResource(0x42, protocol.ResourceClaim, "content")
	allowedOtherClaim := traversalTestResource(0x43, protocol.ResourceClaim, "content")
	sharedTerminal := traversalTestResource(0x44, protocol.ResourceEntity, "b")
	otherTerminal := traversalTestResource(0x45, protocol.ResourceEntity, "c")
	sharedSupport := traversalTestResource(0x46, protocol.ResourceDocument, "parent")
	otherSupport := traversalTestResource(0x47, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		if request.Phase == kag.ExpandPhaseEntityToClaim {
			return traversalTestExpansion(
				[]kag.CandidateHandle{
					{Resource: deniedHighClaim, Score: 0.9},
					{Resource: allowedOtherClaim, Score: 0.7},
					{Resource: allowedLowClaim, Score: 0.2},
				},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, deniedHighClaim, deniedHighClaim, predicate),
					traversalTestEdge(start, allowedOtherClaim, allowedOtherClaim, predicate),
					traversalTestEdge(start, allowedLowClaim, allowedLowClaim, predicate),
				},
			), nil
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: sharedTerminal, Score: 1}, {Resource: otherTerminal, Score: 1}},
			[]kag.ExpansionHandle{
				traversalTestEdge(deniedHighClaim, sharedTerminal, deniedHighClaim, predicate),
				traversalTestEdge(allowedLowClaim, sharedTerminal, allowedLowClaim, predicate),
				traversalTestEdge(allowedOtherClaim, otherTerminal, allowedOtherClaim, predicate),
			},
		), nil
	}
	authorizer := &traversalTestAuthorizer{}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return !strings.HasPrefix(check.CorrelationID, "tr-final-") || check.Object != deniedHighClaim.AuthorizationID
		}), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		sharedTerminal.ResourceID: traversalTestEvidence(sharedTerminal, sharedSupport),
		otherTerminal.ResourceID:  traversalTestEvidence(otherTerminal, otherSupport),
	}}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(1))
	service.evidenceLimit = 1

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-surviving-rank"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{otherTerminal.ResourceID}) {
		t.Fatalf("evidence ranked by a denied path = %v, want %s", got, otherTerminal.ResourceID)
	}
	decisions := traversalDecisionResourceIDs(result.Evidence)
	if !traversalContainsID(decisions, allowedOtherClaim.ResourceID) ||
		traversalContainsID(decisions, deniedHighClaim.ResourceID) ||
		traversalContainsID(decisions, allowedLowClaim.ResourceID) {
		t.Fatalf("selected path decisions = %v, want only the surviving ranked path", decisions)
	}
	if len(backend.lastGenerate.Paths) != 1 || !reflect.DeepEqual(
		traversalGeneratePathResourceIDs(backend.lastGenerate.Paths[0]),
		[]protocol.ResourceID{start.ResourceID, allowedOtherClaim.ResourceID, otherTerminal.ResourceID},
	) {
		t.Fatalf("generator path was influenced by a denied path: %#v", backend.lastGenerate.Paths)
	}
}

func TestTraversalMixedFanoutOrdersTerminalEvidenceByInheritedScore(t *testing.T) {
	start := traversalTestResource(30, protocol.ResourceEntity, "a")
	claimHigh := traversalTestResource(31, protocol.ResourceClaim, "content")
	claimLow := traversalTestResource(32, protocol.ResourceClaim, "content")
	entityHigh := traversalTestResource(33, protocol.ResourceEntity, "b")
	entityLow := traversalTestResource(34, protocol.ResourceEntity, "c")
	supportHigh := traversalTestResource(93, protocol.ResourceDocument, "parent")
	supportLow := traversalTestResource(94, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		if request.Phase == kag.ExpandPhaseEntityToClaim {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: claimHigh, Score: 0.9}, {Resource: claimLow, Score: 0.5}},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, claimHigh, claimHigh, predicate),
					traversalTestEdge(start, claimLow, claimLow, predicate),
				},
			), nil
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: entityLow, Score: 0.9}, {Resource: entityHigh, Score: 0.8}},
			[]kag.ExpansionHandle{
				traversalTestEdge(claimHigh, entityHigh, claimHigh, predicate),
				traversalTestEdge(claimLow, entityLow, claimLow, predicate),
			},
		), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		entityHigh.ResourceID: traversalTestEvidence(entityHigh, supportHigh),
		entityLow.ResourceID:  traversalTestEvidence(entityLow, supportLow),
	}}
	service := traversalTestService(t, backend, &traversalTestAuthorizer{}, loader, traversalTestConfig(1))

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-fanout"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []protocol.ResourceID{entityHigh.ResourceID, entityLow.ResourceID}
	if !reflect.DeepEqual(result.Generation.EvidenceResourceIDs, want) {
		t.Fatalf("terminal ranking = %v, want %v", result.Generation.EvidenceResourceIDs, want)
	}
}

func TestTraversalRejectsBudgetsWithoutClamping(t *testing.T) {
	start := traversalTestResource(40, protocol.ResourceEntity, "a")
	secondStart := traversalTestResource(41, protocol.ResourceEntity, "b")
	claimOne := traversalTestResource(42, protocol.ResourceClaim, "content")
	claimTwo := traversalTestResource(43, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(44, protocol.ResourceEntity, "c")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)

	baseExpand := func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		if request.Phase == kag.ExpandPhaseEntityToClaim {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: claimOne, Score: 0.9}},
				[]kag.ExpansionHandle{traversalTestEdge(start, claimOne, claimOne, predicate)},
			), nil
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
			[]kag.ExpansionHandle{traversalTestEdge(claimOne, terminal, claimOne, predicate)},
		), nil
	}

	t.Run("depth", func(t *testing.T) {
		backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start), expand: baseExpand}
		service := traversalTestService(t, backend, &traversalTestAuthorizer{}, &queryTestLoader{
			items: map[protocol.ResourceID]protocol.EvidenceItem{
				terminal.ResourceID: traversalTestEvidence(terminal, traversalTestResource(95, protocol.ResourceDocument, "parent")),
			},
		}, traversalTestConfig(1))
		if _, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-depth-budget"),
		}); err != nil {
			t.Fatal(err)
		}
		if len(backend.expandRequests) != 2 {
			t.Fatalf("depth budget allowed %d primitive calls", len(backend.expandRequests))
		}
	})

	tests := []struct {
		name      string
		config    TraversalConfig
		retrieve  kag.RetrieveResult
		expand    func(context.Context, int, kag.ExpandRequest) (kag.ExpandResult, error)
		wantCalls int
	}{
		{
			name: "frontier", config: traversalTestConfig(1),
			retrieve: traversalTestRetrieve(start, secondStart), wantCalls: 0,
		},
		{
			name: "candidates", config: traversalTestConfig(1), retrieve: traversalTestRetrieve(start),
			expand: func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
				return traversalTestExpansion(
					[]kag.CandidateHandle{{Resource: claimOne, Score: 0.9}, {Resource: claimTwo, Score: 0.8}},
					[]kag.ExpansionHandle{
						traversalTestEdge(start, claimOne, claimOne, predicate),
						traversalTestEdge(start, claimTwo, claimTwo, predicate),
					},
				), nil
			},
			wantCalls: 1,
		},
		{name: "total unique", config: traversalTestConfig(1), retrieve: traversalTestRetrieve(start), expand: baseExpand, wantCalls: 2},
		{name: "batch RPC", config: traversalTestConfig(1), retrieve: traversalTestRetrieve(start), expand: baseExpand, wantCalls: 1},
	}
	tests[0].config.Limits.MaxFrontierWidth = 1
	tests[1].config.Limits.MaxCandidatesPerHop = 1
	tests[2].config.Limits.MaxTotalResources = 2
	tests[3].config.Limits.MaxBatchChecks = 2
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &traversalTestBackend{retrieve: test.retrieve, expand: test.expand}
			service := traversalTestService(t, backend, &traversalTestAuthorizer{}, &queryTestLoader{}, test.config)
			_, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-budget-"+test.name),
			})
			if !errors.Is(err, errTraversalBudgetExceeded) {
				t.Fatalf("error = %v, want budget exceeded", err)
			}
			if len(backend.expandRequests) != test.wantCalls {
				t.Fatalf("expand calls = %d, want %d", len(backend.expandRequests), test.wantCalls)
			}
		})
	}

	t.Run("denied retrieval candidates count toward total unique", func(t *testing.T) {
		config := traversalTestConfig(1)
		config.Limits.MaxTotalResources = 1
		backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start, secondStart)}
		authorizer := &traversalTestAuthorizer{}
		authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
				return check.Object == start.AuthorizationID
			}), nil
		}
		service := traversalTestService(t, backend, authorizer, &queryTestLoader{}, config)
		_, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-budget-denied-start"),
		})
		if !errors.Is(err, errTraversalBudgetExceeded) {
			t.Fatalf("error = %v, want budget exceeded", err)
		}
		if len(authorizer.calls) != 0 || len(backend.expandRequests) != 0 {
			t.Fatalf("over-budget retrieval crossed authorization boundary: checks=%d expands=%d", len(authorizer.calls), len(backend.expandRequests))
		}
	})

	t.Run("denied expansion candidates count toward total unique", func(t *testing.T) {
		config := traversalTestConfig(1)
		config.Limits.MaxTotalResources = 2
		backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
		backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: claimOne, Score: 0.9}, {Resource: claimTwo, Score: 0.8}},
				[]kag.ExpansionHandle{
					traversalTestEdge(start, claimOne, claimOne, predicate),
					traversalTestEdge(start, claimTwo, claimTwo, predicate),
				},
			), nil
		}
		authorizer := &traversalTestAuthorizer{}
		authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
				return strings.HasPrefix(check.CorrelationID, "tr-discover-") ||
					strings.HasPrefix(check.CorrelationID, "tr-start-") ||
					check.Object == claimOne.AuthorizationID
			}), nil
		}
		service := traversalTestService(t, backend, authorizer, &queryTestLoader{}, config)
		_, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-budget-denied-claim"),
		})
		if !errors.Is(err, errTraversalBudgetExceeded) {
			t.Fatalf("error = %v, want budget exceeded", err)
		}
		if len(authorizer.calls) != 2 || len(backend.expandRequests) != 1 {
			t.Fatalf("over-budget expansion crossed claim authorization boundary: checks=%d expands=%d", len(authorizer.calls), len(backend.expandRequests))
		}
	})

	t.Run("wall clock", func(t *testing.T) {
		config := traversalTestConfig(1)
		config.Limits.MaxWallClockMillis = 5
		backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
		backend.expand = func(ctx context.Context, _ int, _ kag.ExpandRequest) (kag.ExpandResult, error) {
			<-ctx.Done()
			return kag.ExpandResult{}, ctx.Err()
		}
		service := traversalTestService(t, backend, &traversalTestAuthorizer{}, &queryTestLoader{}, config)
		_, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: queryTestAuthorization("alice", "request-wall-clock"),
		})
		if !errors.Is(err, errTraversalBudgetExceeded) {
			t.Fatalf("error = %v, want wall-clock budget", err)
		}
	})
}

func TestTraversalCancellationTerminatesQuery(t *testing.T) {
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(traversalTestResource(50, protocol.ResourceEntity, "a"))}
	service := traversalTestService(t, backend, &traversalTestAuthorizer{}, &queryTestLoader{}, traversalTestConfig(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.Query(ctx, protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-cancel"),
	})
	if !errors.Is(err, context.Canceled) || backend.retrieveCalls != 0 {
		t.Fatalf("error=%v retrieve_calls=%d", err, backend.retrieveCalls)
	}
}

func TestTraversalRechecksAuthorizedStartBeforeExpansion(t *testing.T) {
	start := traversalTestResource(51, protocol.ResourceEntity, "a")
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	authorizer := &traversalTestAuthorizer{}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return strings.HasPrefix(check.CorrelationID, "tr-discover-")
		}), nil
	}
	loader := &queryTestLoader{}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(1))

	_, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-start-revocation"),
	})
	if !errors.Is(err, errNoEvidence) {
		t.Fatalf("start revocation error = %v", err)
	}
	if backend.retrieveCalls != 1 || len(backend.expandRequests) != 0 || len(loader.calls) != 0 || backend.generateCalls != 0 {
		t.Fatalf(
			"start revocation crossed expansion/content boundary: retrieve=%d expand=%d load=%d generate=%d",
			backend.retrieveCalls, len(backend.expandRequests), len(loader.calls), backend.generateCalls,
		)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("authorization calls = %d, want discovery and start", len(authorizer.calls))
	}
}

func TestTraversalRejectsProjectionDriftStaleHandlesAndParentClaimMismatch(t *testing.T) {
	start := traversalTestResource(60, protocol.ResourceEntity, "a")
	claim := traversalTestResource(61, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(62, protocol.ResourceEntity, "b")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	otherPredicate := traversalTestPredicate(t, protocol.ClaimPredicateSupports)

	tests := []struct {
		name   string
		depth  int
		expand func(context.Context, int, kag.ExpandRequest) (kag.ExpandResult, error)
	}{
		{
			name: "projection drift", depth: 1,
			expand: func(_ context.Context, _ int, _ kag.ExpandRequest) (kag.ExpandResult, error) {
				drifted := claim
				drifted.Versions.Projection = "prj_22222222222222222222222222222222"
				return traversalTestExpansion(
					[]kag.CandidateHandle{{Resource: drifted, Score: 0.9}},
					[]kag.ExpansionHandle{traversalTestEdge(start, drifted, drifted, predicate)},
				), nil
			},
		},
		{
			name: "parent Claim mismatch", depth: 1,
			expand: func(_ context.Context, call int, request kag.ExpandRequest) (kag.ExpandResult, error) {
				if call == 0 {
					return traversalTestExpansion(
						[]kag.CandidateHandle{{Resource: claim, Score: 0.9}},
						[]kag.ExpansionHandle{traversalTestEdge(start, claim, claim, predicate)},
					), nil
				}
				return traversalTestExpansion(
					[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
					[]kag.ExpansionHandle{traversalTestEdge(claim, terminal, claim, otherPredicate)},
				), nil
			},
		},
		{
			name: "stale cycle handle", depth: 2,
			expand: func(_ context.Context, call int, request kag.ExpandRequest) (kag.ExpandResult, error) {
				switch call {
				case 0:
					return traversalTestExpansion(
						[]kag.CandidateHandle{{Resource: claim, Score: 0.9}},
						[]kag.ExpansionHandle{traversalTestEdge(start, claim, claim, predicate)},
					), nil
				case 1:
					return traversalTestExpansion(
						[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
						[]kag.ExpansionHandle{traversalTestEdge(claim, terminal, claim, predicate)},
					), nil
				case 2:
					secondClaim := traversalTestResource(63, protocol.ResourceClaim, "content")
					return traversalTestExpansion(
						[]kag.CandidateHandle{{Resource: secondClaim, Score: 0.9}},
						[]kag.ExpansionHandle{traversalTestEdge(terminal, secondClaim, secondClaim, predicate)},
					), nil
				default:
					stale := start
					stale.ContentDigest = protocol.NewContentDigest("d")
					secondClaim := request.Frontier[0].Resource
					return traversalTestExpansion(
						[]kag.CandidateHandle{{Resource: stale, Score: 0.9}},
						[]kag.ExpansionHandle{traversalTestEdge(secondClaim, stale, secondClaim, predicate)},
					), nil
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start), expand: test.expand}
			service := traversalTestService(t, backend, &traversalTestAuthorizer{}, &queryTestLoader{}, traversalTestConfig(test.depth))
			_, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-invalid-"+test.name),
			})
			if !errors.Is(err, errInvalidTraversalResponse) {
				t.Fatalf("error = %v, want invalid traversal response", err)
			}
			if strings.Contains(err.Error(), string(predicate)) || strings.Contains(err.Error(), string(otherPredicate)) {
				t.Fatalf("public error leaked a predicate key: %v", err)
			}
		})
	}
}

func TestTraversalBatchCheckMalformedOrTimeoutDropsOnlyFailedChunk(t *testing.T) {
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	starts := make([]protocol.ResourceHandle, 0, 31)
	claims := make([]protocol.ResourceHandle, 0, 31)
	terminals := make([]protocol.ResourceHandle, 0, 31)
	items := make(map[protocol.ResourceID]protocol.EvidenceItem, 31)
	for index := 0; index < 31; index++ {
		base := index*4 + 100
		if index == 30 {
			base = 0x10000
		}
		start := traversalTestResource(base, protocol.ResourceEntity, "a")
		claim := traversalTestResource(base+1, protocol.ResourceClaim, "content")
		terminal := traversalTestResource(base+2, protocol.ResourceEntity, "b")
		support := traversalTestResource(base+3, protocol.ResourceDocument, "parent")
		starts = append(starts, start)
		claims = append(claims, claim)
		terminals = append(terminals, terminal)
		items[terminal.ResourceID] = traversalTestEvidence(terminal, support)
	}

	for _, test := range []struct {
		name string
		fail func(authz.BatchCheckRequest) ([]authz.Decision, error)
	}{
		{name: "malformed", fail: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true })[:1], nil
		}},
		{name: "timeout", fail: func(authz.BatchCheckRequest) ([]authz.Decision, error) {
			return nil, fmt.Errorf("%w: provider timeout", authz.ErrTimeout)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &traversalTestBackend{retrieve: traversalTestRetrieve(starts...)}
			backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
				if request.Phase == kag.ExpandPhaseEntityToClaim {
					candidates := make([]kag.CandidateHandle, len(claims))
					edges := make([]kag.ExpansionHandle, len(claims))
					for index := range claims {
						candidates[index] = kag.CandidateHandle{Resource: claims[index], Score: 0.9 - float64(index)/100}
						edges[index] = traversalTestEdge(starts[index], claims[index], claims[index], predicate)
					}
					return traversalTestExpansion(candidates, edges), nil
				}
				candidates := make([]kag.CandidateHandle, len(terminals))
				edges := make([]kag.ExpansionHandle, len(terminals))
				for index := range terminals {
					candidates[index] = kag.CandidateHandle{Resource: terminals[index], Score: 0.9 - float64(index)/100}
					edges[index] = traversalTestEdge(claims[index], terminals[index], claims[index], predicate)
				}
				return traversalTestExpansion(candidates, edges), nil
			}
			finalRPC := 0
			authorizer := &traversalTestAuthorizer{}
			authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				if strings.HasPrefix(request.Checks[0].CorrelationID, "tr-final-") {
					finalRPC++
					if finalRPC == 1 {
						return test.fail(request)
					}
				}
				return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
			}
			config := traversalTestConfig(1)
			config.Limits.MaxFrontierWidth = 64
			config.Limits.MaxCandidatesPerHop = 64
			config.Limits.MaxTotalResources = 200
			config.Limits.MaxBatchChecks = 10
			service := traversalTestService(t, backend, authorizer, &queryTestLoader{items: items}, config)

			result, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-partial-"+test.name),
			})
			if err != nil {
				t.Fatal(err)
			}
			if finalRPC != 3 {
				t.Fatalf("final BatchCheck RPCs = %d, want 3", finalRPC)
			}
			want := make([]protocol.ResourceID, 0, len(terminals)-13)
			for _, terminal := range terminals[13:] {
				want = append(want, terminal.ResourceID)
			}
			if !reflect.DeepEqual(result.Generation.EvidenceResourceIDs, want) {
				t.Fatalf("surviving terminal evidence = %v, want %v", result.Generation.EvidenceResourceIDs, want)
			}
			if result.Traversal == nil || result.Traversal.BatchCheckRPCCount != 7 {
				t.Fatalf("traversal authorization RPC report = %#v, want 7", result.Traversal)
			}
		})
	}
}

func TestTraversalCacheRevalidationFailureDoesNotFallThroughToGeneration(t *testing.T) {
	for _, test := range []struct {
		name string
		fail func(authz.BatchCheckRequest) ([]authz.Decision, error)
	}{
		{name: "deny", fail: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return false }), nil
		}},
		{name: "malformed", fail: func(request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true })[:0], nil
		}},
		{name: "timeout", fail: func(authz.BatchCheckRequest) ([]authz.Decision, error) {
			return nil, fmt.Errorf("%w: cache revalidation timeout", authz.ErrTimeout)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := traversalTestResource(0x200+len(test.name), protocol.ResourceEntity, "a")
			support := traversalTestResource(0x300+len(test.name), protocol.ResourceDocument, "parent")
			backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
			failCache := false
			authorizer := &traversalTestAuthorizer{}
			authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				if failCache && len(request.Checks) > 0 && strings.HasPrefix(request.Checks[0].CorrelationID, "cache-") {
					return test.fail(request)
				}
				return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
			}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				start.ResourceID: traversalTestEvidence(start, support),
			}}
			service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(0))
			service.cache = mustQueryCache(t, 4)
			service.retrieverVersion = "retriever-v1"
			service.promptVersion = "prompt-v1"
			request := protocol.QueryRequest{
				Question: "cached traversal", Authorization: queryTestAuthorization("alice", "request-cache-prime-"+test.name),
			}
			if _, err := service.Query(context.Background(), request); err != nil {
				t.Fatal(err)
			}

			failCache = true
			request.Authorization.RequestID = "request-cache-recheck-" + test.name
			_, err := service.Query(context.Background(), request)
			if !errors.Is(err, ErrProtectedContentUnavailable) {
				t.Fatalf("cache revalidation error = %v, want protected content unavailable", err)
			}
			if backend.generateCalls != 1 {
				t.Fatalf("generate calls = %d, want no generation after failed cache revalidation", backend.generateCalls)
			}
		})
	}
}

func TestTraversalConfigRejectsUnsupportedCapabilitiesAndHasStableDigest(t *testing.T) {
	backend := &traversalTestBackend{}
	authorizer := &traversalTestAuthorizer{}
	loader := &queryTestLoader{}
	for _, test := range []struct {
		name   string
		mutate func(*TraversalConfig)
	}{
		{name: "inbound", mutate: func(config *TraversalConfig) { config.Direction = protocol.TraversalInbound }},
		{name: "both", mutate: func(config *TraversalConfig) { config.Direction = protocol.TraversalBoth }},
		{name: "frontier provider limit", mutate: func(config *TraversalConfig) { config.Limits.MaxFrontierWidth = 101 }},
		{name: "candidate provider limit", mutate: func(config *TraversalConfig) { config.Limits.MaxCandidatesPerHop = 101 }},
		{name: "predicate ranking", mutate: func(config *TraversalConfig) {
			config.Order = []protocol.GraphOrder{{
				Key: protocol.GraphSortPredicateKey, Direction: protocol.GraphSortAscending, Priority: 0,
			}}
		}},
		{name: "resource kind", mutate: func(config *TraversalConfig) {
			config.ResourceKinds = []protocol.GraphResourceKind{protocol.GraphResourceDocument}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := traversalTestConfig(1)
			test.mutate(&config)
			if _, err := New(Options{
				KAG: backend, Authorizer: authorizer, Loader: loader,
				RetrieveLimit: 10, EvidenceLimit: 8, Traversal: config,
			}); err == nil {
				t.Fatal("unsupported capability was accepted")
			}
		})
	}

	firstConfig := traversalTestConfig(2)
	firstConfig.PredicateSources = []protocol.ClaimPredicateSourceKey{
		protocol.ClaimPredicateSupports, protocol.ClaimPredicateLocatedIn,
	}
	secondConfig := firstConfig
	secondConfig.PredicateSources = []protocol.ClaimPredicateSourceKey{
		protocol.ClaimPredicateLocatedIn, protocol.ClaimPredicateSupports,
	}
	first := traversalTestService(t, backend, authorizer, loader, firstConfig)
	second := traversalTestService(t, backend, authorizer, loader, secondConfig)
	if first.configuredTraversalPlanDigest() != second.configuredTraversalPlanDigest() ||
		first.configuredTraversalPlanDigest() == (traversalPlanDigest{}) {
		t.Fatal("canonical traversal plan digest is unstable or empty")
	}
}

func TestTraversalCacheUsesFreshPlanAndRevalidatesEveryPathDecision(t *testing.T) {
	start := traversalTestResource(71, protocol.ResourceEntity, "a")
	support := traversalTestResource(72, protocol.ResourceDocument, "parent")
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	authorizer := &traversalTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		start.ResourceID: traversalTestEvidence(start, support),
	}}
	cache := mustQueryCache(t, 2)
	service, err := New(Options{
		KAG: backend, Authorizer: authorizer, Loader: loader,
		Cache: cache, RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 64, EvidenceLimit: 64, Traversal: traversalTestConfig(0),
		Now: func() time.Time { return time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-cache-bypass"),
	}
	first, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Authorization.RequestID = "request-cache-hit"
	second, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if backend.retrieveCalls != 2 || backend.generateCalls != 1 || len(cache.entries) != 1 {
		t.Fatalf("traversal cache calls: retrieve=%d generate=%d entries=%d",
			backend.retrieveCalls, backend.generateCalls, len(cache.entries))
	}
	if len(authorizer.calls) != 8 {
		t.Fatalf("authorization calls = %d, want first discovery/start/final plus fresh-hit discovery/start/final and cache pre/final", len(authorizer.calls))
	}
	if len(loader.calls) != 3 {
		t.Fatalf("loader calls = %d, want current exact load plus cached exact reload on hit", len(loader.calls))
	}
	if err := first.Evidence.ValidateFor(queryTestAuthorization("alice", "request-cache-bypass")); err != nil {
		t.Fatalf("first evidence: %v", err)
	}
	if err := second.Evidence.ValidateFor(request.Authorization); err != nil {
		t.Fatalf("rebound cached evidence: %v", err)
	}
	if first.Traversal == nil || second.Traversal == nil ||
		first.Traversal.AuthorizedPathCompleteness != 1 || second.Traversal.AuthorizedPathCompleteness != 1 ||
		first.Traversal.BatchCheckRPCCount != 3 || second.Traversal.BatchCheckRPCCount != 5 {
		t.Fatalf("fresh/cache traversal reports = %#v / %#v", first.Traversal, second.Traversal)
	}
	for _, entry := range cache.entries {
		if entry.result.Traversal != nil {
			t.Fatal("query cache persisted a traversal report")
		}
	}
}

func TestTraversalCacheKeyIncludesEverySelectedPathResource(t *testing.T) {
	start := traversalTestResource(73, protocol.ResourceEntity, "a")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	cache := mustQueryCache(t, 4)
	newService := func(
		claim protocol.ResourceHandle,
		terminal protocol.ResourceHandle,
		support protocol.ResourceHandle,
	) (*Service, *traversalTestBackend) {
		backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
		backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
			if request.Phase == kag.ExpandPhaseEntityToClaim {
				return traversalTestExpansion(
					[]kag.CandidateHandle{{Resource: claim, Score: 0.9}},
					[]kag.ExpansionHandle{traversalTestEdge(start, claim, claim, predicate)},
				), nil
			}
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
				[]kag.ExpansionHandle{traversalTestEdge(claim, terminal, claim, predicate)},
			), nil
		}
		service, err := New(Options{
			KAG: backend, Authorizer: &traversalTestAuthorizer{},
			Loader: &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				terminal.ResourceID: traversalTestEvidence(terminal, support),
			}},
			Cache: cache, RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
			RetrieveLimit: 64, EvidenceLimit: 64, Traversal: traversalTestConfig(1),
			Now: func() time.Time { return time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		return service, backend
	}
	first, firstBackend := newService(
		traversalTestResource(74, protocol.ResourceClaim, "content"),
		traversalTestResource(75, protocol.ResourceEntity, "b"),
		traversalTestResource(76, protocol.ResourceDocument, "parent"),
	)
	second, secondBackend := newService(
		traversalTestResource(77, protocol.ResourceClaim, "content"),
		traversalTestResource(78, protocol.ResourceEntity, "c"),
		traversalTestResource(79, protocol.ResourceDocument, "parent"),
	)
	request := protocol.QueryRequest{
		Question:      "same path-sensitive question",
		Authorization: queryTestAuthorization("alice", "request-path-a"),
	}
	if _, err := first.Query(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Authorization.RequestID = "request-path-b"
	if _, err := second.Query(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if firstBackend.generateCalls != 1 || secondBackend.generateCalls != 1 || len(cache.entries) != 2 {
		t.Fatalf("different authorized paths shared a cache entry: first=%d second=%d entries=%d",
			firstBackend.generateCalls, secondBackend.generateCalls, len(cache.entries))
	}
	keys := make([]queryCacheKey, 0, len(cache.entries))
	for key := range cache.entries {
		keys = append(keys, key)
	}
	if keys[0].traversalPlanDigest != keys[1].traversalPlanDigest {
		t.Fatal("identical dynamic traversal descriptors produced different plan digests")
	}
	if keys[0].traversalPathDigest == keys[1].traversalPathDigest {
		t.Fatal("different intermediate Claim paths produced the same path digest")
	}
}

func TestTraversalRevocationDuringObjectExpansionFailsBeforeGeneration(t *testing.T) {
	start := traversalTestResource(80, protocol.ResourceEntity, "a")
	claim := traversalTestResource(81, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(82, protocol.ResourceEntity, "b")
	support := traversalTestResource(83, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	objectExpansionStarted := make(chan struct{})
	releaseObjectExpansion := make(chan struct{})
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(ctx context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		if request.Phase == kag.ExpandPhaseEntityToClaim {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: claim, Score: 0.9}},
				[]kag.ExpansionHandle{traversalTestEdge(start, claim, claim, predicate)},
			), nil
		}
		close(objectExpansionStarted)
		select {
		case <-ctx.Done():
			return kag.ExpandResult{}, ctx.Err()
		case <-releaseObjectExpansion:
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
			[]kag.ExpansionHandle{traversalTestEdge(claim, terminal, claim, predicate)},
		), nil
	}
	cacheNow := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	cache, err := newQueryCache(4, func() time.Time { return cacheNow })
	if err != nil {
		t.Fatal(err)
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		terminal.ResourceID: traversalTestEvidence(terminal, support),
	}}
	service, err := New(Options{
		KAG: backend, Authorizer: &traversalTestAuthorizer{}, Loader: loader,
		Cache: cache, RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 64, EvidenceLimit: 64, Traversal: traversalTestConfig(1),
		Now: func() time.Time { return cacheNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-revoked-during-traversal")
	binding, _ := revocationTestBindingWithIntermediateClaim(
		t, authorization, traversalTestEvidence(terminal, support), claim,
	)
	type queryOutcome struct {
		result QueryResult
		err    error
	}
	done := make(chan queryOutcome, 1)
	go func() {
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "q", Authorization: authorization,
		})
		done <- queryOutcome{result: result, err: err}
	}()
	<-objectExpansionStarted
	if _, err := coordinator.Apply(context.Background(), RevocationRequest{
		Authorization: authorization,
		Binding:       binding,
		ResourceIDs:   []protocol.ResourceID{claim.ResourceID},
		RevokedAt:     cacheNow.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	close(releaseObjectExpansion)
	outcome := <-done
	if !errors.Is(outcome.err, ErrProtectedContentUnavailable) {
		t.Fatalf("in-flight traversal error = %v", outcome.err)
	}
	if outcome.result.Generation.Answer != "" || backend.generateCalls != 0 || len(cache.entries) != 0 {
		t.Fatalf("revoked traversal escaped before generation: result=%#v generate=%d cache=%d",
			outcome.result, backend.generateCalls, len(cache.entries))
	}
}

func TestTraversalOpenCitationReauthorizesIntermediateClaim(t *testing.T) {
	start := traversalTestResource(84, protocol.ResourceEntity, "a")
	claim := traversalTestResource(85, protocol.ResourceClaim, "content")
	terminal := traversalTestResource(86, protocol.ResourceEntity, "b")
	support := traversalTestResource(87, protocol.ResourceDocument, "parent")
	predicate := traversalTestPredicate(t, protocol.ClaimPredicateLocatedIn)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(_ context.Context, _ int, request kag.ExpandRequest) (kag.ExpandResult, error) {
		if request.Phase == kag.ExpandPhaseEntityToClaim {
			return traversalTestExpansion(
				[]kag.CandidateHandle{{Resource: claim, Score: 0.9}},
				[]kag.ExpansionHandle{traversalTestEdge(start, claim, claim, predicate)},
			), nil
		}
		return traversalTestExpansion(
			[]kag.CandidateHandle{{Resource: terminal, Score: 0.8}},
			[]kag.ExpansionHandle{traversalTestEdge(claim, terminal, claim, predicate)},
		), nil
	}
	denyClaim := false
	authorizer := &traversalTestAuthorizer{}
	authorizer.decide = func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return !denyClaim || check.Object != claim.AuthorizationID
		}), nil
	}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		terminal.ResourceID: traversalTestEvidence(terminal, support),
	}}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(1))
	authorization := queryTestAuthorization("alice", "request-open-citation-claim")
	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence.Items) != 1 {
		t.Fatalf("evidence items = %d", len(result.Evidence.Items))
	}

	denyClaim = true
	authorizationCalls := len(authorizer.calls)
	loaderCalls := len(loader.calls)
	_, err = service.OpenCitation(
		context.Background(), authorization, result.Evidence, result.Evidence.Items[0].Citation.Handle,
	)
	if !errors.Is(err, ErrCitationUnavailable) {
		t.Fatalf("citation after intermediate Claim deny error = %v", err)
	}
	if len(loader.calls) != loaderCalls {
		t.Fatalf("citation content loaded before path reauthorization: calls=%d want=%d", len(loader.calls), loaderCalls)
	}
	sawClaim := false
	for _, request := range authorizer.calls[authorizationCalls:] {
		for _, check := range request.Checks {
			sawClaim = sawClaim || check.Object == claim.AuthorizationID
		}
	}
	if !sawClaim {
		t.Fatal("citation open did not reauthorize the intermediate Claim")
	}

	denyClaim = false
	cacheNow := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	cache, err := newQueryCache(4, func() time.Time { return cacheNow })
	if err != nil {
		t.Fatal(err)
	}
	service.cache = cache
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(context.Background(), RevocationRequest{
		Authorization: authorization,
		Binding:       binding,
		ResourceIDs:   []protocol.ResourceID{claim.ResourceID},
		RevokedAt:     cacheNow.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	loaderCalls = len(loader.calls)
	_, err = service.OpenCitation(
		context.Background(), authorization, result.Evidence, result.Evidence.Items[0].Citation.Handle,
	)
	if !errors.Is(err, ErrCitationUnavailable) {
		t.Fatalf("citation after intermediate Claim tombstone error = %v", err)
	}
	if len(loader.calls) != loaderCalls {
		t.Fatalf("tombstoned citation loaded protected content: calls=%d want=%d", len(loader.calls), loaderCalls)
	}
}

func TestTraversalUnsupportedProviderFailureIsSanitized(t *testing.T) {
	start := traversalTestResource(70, protocol.ResourceEntity, "a")
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(start)}
	backend.expand = func(context.Context, int, kag.ExpandRequest) (kag.ExpandResult, error) {
		return kag.ExpandResult{}, fmt.Errorf("%w: MATCH (n:ProtectedLabel)", kag.ErrUnsupportedPrimitive)
	}
	service := traversalTestService(t, backend, &traversalTestAuthorizer{}, &queryTestLoader{}, traversalTestConfig(1))
	_, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-unsupported"),
	})
	if !errors.Is(err, errTraversalUnsupported) || strings.Contains(err.Error(), "ProtectedLabel") || strings.Contains(err.Error(), "MATCH") {
		t.Fatalf("error = %v", err)
	}
}

func traversalTestService(
	t *testing.T,
	backend *traversalTestBackend,
	authorizer *traversalTestAuthorizer,
	loader *queryTestLoader,
	config TraversalConfig,
) *Service {
	t.Helper()
	service, err := New(Options{
		KAG: backend, Authorizer: authorizer, Loader: loader,
		RetrieveLimit: 64, EvidenceLimit: 64, Traversal: config,
		Now: func() time.Time { return time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func traversalTestConfig(depth int) TraversalConfig {
	return TraversalConfig{
		Enabled:          true,
		PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateLocatedIn},
		ResourceKinds:    []protocol.GraphResourceKind{protocol.GraphResourceEntity},
		Direction:        protocol.TraversalOutbound,
		Limits: protocol.TraversalLimits{
			MaxDepth: depth, MaxFrontierWidth: 64, MaxCandidatesPerHop: 64,
			MaxTotalResources: 128, MaxBatchChecks: 16, MaxWallClockMillis: 5_000,
		},
	}
}

func traversalTestResource(number int, resourceType protocol.ResourceType, content string) protocol.ResourceHandle {
	resourceID := protocol.ResourceID(fmt.Sprintf("res_%032x", number))
	resource := queryTestDocument(resourceID, content, traversalTestProjection)
	resource.Type = resourceType
	resource.AuthorizationID = string(resourceType) + ":" + string(resourceID)
	resource.AuthorizationResourceID = resourceID
	return resource
}

func traversalTestEvidence(resource, support protocol.ResourceHandle) protocol.EvidenceItem {
	return protocol.EvidenceItem{
		Resource: resource, Content: traversalTestContent(resource), Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-" + string(resource.ResourceID), Resource: support,
			Evidence: []protocol.ResourceHandle{support}, Complete: true,
		}},
		Citation: protocol.Citation{Handle: "citation-" + string(resource.ResourceID), Resource: resource},
	}
}

func traversalTestContent(resource protocol.ResourceHandle) string {
	for _, content := range []string{"a", "b", "c", "d", "content", "parent"} {
		if protocol.NewContentDigest(content) == resource.ContentDigest {
			return content
		}
	}
	panic(fmt.Sprintf("unknown traversal test content digest %s", resource.ContentDigest))
}

func traversalTestRetrieve(resources ...protocol.ResourceHandle) kag.RetrieveResult {
	candidates := make([]kag.CandidateHandle, len(resources))
	for index, resource := range resources {
		candidates[index] = kag.CandidateHandle{Resource: resource, Score: 1 - float64(index)/100}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Resource.ResourceID < candidates[j].Resource.ResourceID
	})
	return kag.RetrieveResult{Mode: "fake", Candidates: candidates}
}

func traversalTestExpansion(candidates []kag.CandidateHandle, edges []kag.ExpansionHandle) kag.ExpandResult {
	candidates = append([]kag.CandidateHandle(nil), candidates...)
	edges = append([]kag.ExpansionHandle(nil), edges...)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Resource.ResourceID < candidates[j].Resource.ResourceID
	})
	sort.Slice(edges, func(i, j int) bool {
		left, right := edges[i], edges[j]
		if left.Hop != right.Hop {
			return left.Hop < right.Hop
		}
		if left.FromResourceID != right.FromResourceID {
			return left.FromResourceID < right.FromResourceID
		}
		if left.ToResourceID != right.ToResourceID {
			return left.ToResourceID < right.ToResourceID
		}
		if left.ClaimResourceID != right.ClaimResourceID {
			return left.ClaimResourceID < right.ClaimResourceID
		}
		return left.PredicateKey < right.PredicateKey
	})
	return kag.ExpandResult{Mode: "fake", Candidates: candidates, Expansions: edges}
}

func traversalTestEdge(
	from protocol.ResourceHandle,
	to protocol.ResourceHandle,
	claim protocol.ResourceHandle,
	predicate protocol.ClaimPredicateKey,
) kag.ExpansionHandle {
	return kag.ExpansionHandle{
		FromResourceID: from.ResourceID, ToResourceID: to.ResourceID,
		ClaimResourceID: claim.ResourceID, PredicateKey: predicate, Hop: 1,
	}
}

func traversalTestPredicate(t *testing.T, source protocol.ClaimPredicateSourceKey) protocol.ClaimPredicateKey {
	t.Helper()
	key, err := protocol.NewClaimPredicateKey(string(source))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func traversalDecisionResourceIDs(evidence protocol.EvidencePackage) []protocol.ResourceID {
	result := make([]protocol.ResourceID, len(evidence.Decisions))
	for index, decision := range evidence.Decisions {
		result[index] = decision.Resource.ResourceID
	}
	return result
}

func traversalGeneratePathResourceIDs(path kag.GeneratePath) []protocol.ResourceID {
	result := make([]protocol.ResourceID, len(path.Resources))
	for index, resource := range path.Resources {
		result[index] = resource.ResourceID
	}
	return result
}

func traversalEventIndex(events []string, target string) int {
	for index, event := range events {
		if event == target {
			return index
		}
	}
	return -1
}

func traversalContainsID(resourceIDs []protocol.ResourceID, target protocol.ResourceID) bool {
	for _, resourceID := range resourceIDs {
		if resourceID == target {
			return true
		}
	}
	return false
}
