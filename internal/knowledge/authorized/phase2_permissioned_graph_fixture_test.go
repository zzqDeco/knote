package authorized_test

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

const (
	phase2UnknownPrincipal = "unknown"

	phase2StartID          protocol.ResourceID = "res_20000000000000000000000000000001"
	phase2HiddenClaimID    protocol.ResourceID = "res_20000000000000000000000000000002"
	phase2HiddenObjectID   protocol.ResourceID = "res_20000000000000000000000000000003"
	phase2BridgeClaimID    protocol.ResourceID = "res_20000000000000000000000000000004"
	phase2MiddleID         protocol.ResourceID = "res_20000000000000000000000000000005"
	phase2DeniedClaimID    protocol.ResourceID = "res_20000000000000000000000000000006"
	phase2AlternateClaimID protocol.ResourceID = "res_20000000000000000000000000000007"
	phase2SharedTerminalID protocol.ResourceID = "res_20000000000000000000000000000008"
	phase2FanoutClaimID    protocol.ResourceID = "res_20000000000000000000000000000009"
	phase2FanoutEntityID   protocol.ResourceID = "res_2000000000000000000000000000000a"
	phase2CycleClaimID     protocol.ResourceID = "res_2000000000000000000000000000000b"
	phase2DeepClaimID      protocol.ResourceID = "res_2000000000000000000000000000000c"
	phase2DeepTerminalID   protocol.ResourceID = "res_2000000000000000000000000000000d"
	phase2SourceID         protocol.ResourceID = "res_2000000000000000000000000000000e"
	phase2VisibleSupportID protocol.ResourceID = "res_2000000000000000000000000000000f"
	phase2HiddenSupportID  protocol.ResourceID = "res_20000000000000000000000000000010"
	phase2RequiredSupportA protocol.ResourceID = "res_20000000000000000000000000000011"
	phase2RequiredSupportB protocol.ResourceID = "res_20000000000000000000000000000012"

	phase2HiddenClaimCanary   = "PHASE2 HIDDEN CLAIM CANARY"
	phase2DeniedClaimCanary   = "PHASE2 DENIED INTERMEDIATE CANARY"
	phase2HiddenSupportCanary = "PHASE2 HIDDEN SUPPORT CANARY"
)

const (
	phase2DiscoverDuration   = 2 * time.Millisecond
	phase2RetrieveDuration   = 3 * time.Millisecond
	phase2ExpandDuration     = 4 * time.Millisecond
	phase2LoadDuration       = 2 * time.Millisecond
	phase2GenerateDuration   = 5 * time.Millisecond
	phase2BatchCheckDuration = 2 * time.Millisecond
)

var phase2ClockEpoch = time.Date(2026, time.July, 15, 2, 0, 0, 0, time.UTC)

type phase2SyntheticClock struct {
	mu  sync.Mutex
	now time.Time
}

func newPhase2SyntheticClock() *phase2SyntheticClock {
	return &phase2SyntheticClock{now: phase2ClockEpoch}
}

func (c *phase2SyntheticClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *phase2SyntheticClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type phase2GraphEdge struct {
	from        protocol.ResourceHandle
	claim       protocol.ResourceHandle
	to          protocol.ResourceHandle
	claimScore  float64
	objectScore float64
}

type phase2PermissionedGraphFixture struct {
	clock *phase2SyntheticClock

	start          protocol.ResourceHandle
	hiddenClaim    protocol.ResourceHandle
	hiddenObject   protocol.ResourceHandle
	bridgeClaim    protocol.ResourceHandle
	middle         protocol.ResourceHandle
	deniedClaim    protocol.ResourceHandle
	alternateClaim protocol.ResourceHandle
	sharedTerminal protocol.ResourceHandle
	fanoutClaim    protocol.ResourceHandle
	fanoutEntity   protocol.ResourceHandle
	cycleClaim     protocol.ResourceHandle
	deepClaim      protocol.ResourceHandle
	deepTerminal   protocol.ResourceHandle
	source         protocol.ResourceHandle
	visibleSupport protocol.ResourceHandle
	hiddenSupport  protocol.ResourceHandle
	requiredA      protocol.ResourceHandle
	requiredB      protocol.ResourceHandle

	allResources []protocol.ResourceHandle
	edges        []phase2GraphEdge
	backend      *phase2GraphBackend
	loader       *phase2GraphLoader
}

func newPhase2PermissionedGraphFixture() *phase2PermissionedGraphFixture {
	clock := newPhase2SyntheticClock()
	graph := &phase2PermissionedGraphFixture{
		clock:          clock,
		start:          phase2Resource(phase2StartID, protocol.ResourceEntity, "phase2 graph start"),
		hiddenClaim:    phase2Resource(phase2HiddenClaimID, protocol.ResourceClaim, phase2HiddenClaimCanary),
		hiddenObject:   phase2Resource(phase2HiddenObjectID, protocol.ResourceEntity, "hidden object"),
		bridgeClaim:    phase2Resource(phase2BridgeClaimID, protocol.ResourceClaim, "bridge claim"),
		middle:         phase2Resource(phase2MiddleID, protocol.ResourceEntity, "phase2 graph middle"),
		deniedClaim:    phase2Resource(phase2DeniedClaimID, protocol.ResourceClaim, phase2DeniedClaimCanary),
		alternateClaim: phase2Resource(phase2AlternateClaimID, protocol.ResourceClaim, "authorized alternate claim"),
		sharedTerminal: phase2Resource(phase2SharedTerminalID, protocol.ResourceEntity, "shared authorized terminal"),
		fanoutClaim:    phase2Resource(phase2FanoutClaimID, protocol.ResourceClaim, "fanout claim"),
		fanoutEntity:   phase2Resource(phase2FanoutEntityID, protocol.ResourceEntity, "fanout entity"),
		cycleClaim:     phase2Resource(phase2CycleClaimID, protocol.ResourceClaim, "cycle claim"),
		deepClaim:      phase2Resource(phase2DeepClaimID, protocol.ResourceClaim, "deep claim"),
		deepTerminal:   phase2Resource(phase2DeepTerminalID, protocol.ResourceEntity, "deep authorized terminal"),
		source:         phase2Resource(phase2SourceID, protocol.ResourceDocument, "phase2 graph source"),
		visibleSupport: phase2Resource(phase2VisibleSupportID, protocol.ResourceDocument, "visible dynamic support"),
		hiddenSupport:  phase2Resource(phase2HiddenSupportID, protocol.ResourceDocument, phase2HiddenSupportCanary),
		requiredA:      phase2Resource(phase2RequiredSupportA, protocol.ResourceDocument, "required support a"),
		requiredB:      phase2Resource(phase2RequiredSupportB, protocol.ResourceDocument, "required support b"),
	}
	graph.allResources = []protocol.ResourceHandle{
		graph.start, graph.hiddenClaim, graph.hiddenObject, graph.bridgeClaim, graph.middle,
		graph.deniedClaim, graph.alternateClaim, graph.sharedTerminal, graph.fanoutClaim,
		graph.fanoutEntity, graph.cycleClaim, graph.deepClaim, graph.deepTerminal, graph.source,
		graph.visibleSupport, graph.hiddenSupport, graph.requiredA, graph.requiredB,
	}
	graph.edges = []phase2GraphEdge{
		{from: graph.start, claim: graph.hiddenClaim, to: graph.hiddenObject, claimScore: 1.00, objectScore: 1.00},
		{from: graph.start, claim: graph.bridgeClaim, to: graph.middle, claimScore: 0.95, objectScore: 0.95},
		{from: graph.middle, claim: graph.deniedClaim, to: graph.sharedTerminal, claimScore: 0.99, objectScore: 0.99},
		{from: graph.middle, claim: graph.alternateClaim, to: graph.sharedTerminal, claimScore: 0.80, objectScore: 0.99},
		{from: graph.middle, claim: graph.fanoutClaim, to: graph.fanoutEntity, claimScore: 0.90, objectScore: 0.90},
		{from: graph.middle, claim: graph.cycleClaim, to: graph.start, claimScore: 0.70, objectScore: 0.70},
		{from: graph.fanoutEntity, claim: graph.deepClaim, to: graph.deepTerminal, claimScore: 0.90, objectScore: 0.90},
	}

	items := map[protocol.ResourceID]protocol.EvidenceItem{
		graph.start.ResourceID:        phase2EntityEvidence(graph.start, "phase2 graph start", graph.source),
		graph.hiddenObject.ResourceID: phase2EntityEvidence(graph.hiddenObject, "hidden object", graph.source),
		graph.middle.ResourceID:       phase2EntityEvidence(graph.middle, "phase2 graph middle", graph.source),
		graph.fanoutEntity.ResourceID: phase2EntityEvidence(graph.fanoutEntity, "fanout entity", graph.source),
		graph.sharedTerminal.ResourceID: acceptanceEvidenceItem(
			graph.sharedTerminal,
			"shared authorized terminal",
			protocol.DerivationAnySupport,
			[]protocol.ProvenanceSupport{
				phase2Support("support_hidden", graph.hiddenSupport, true),
				phase2Support("support_visible", graph.visibleSupport, true),
			},
		),
		graph.deepTerminal.ResourceID: acceptanceEvidenceItem(
			graph.deepTerminal,
			"deep authorized terminal",
			protocol.DerivationAllRequired,
			[]protocol.ProvenanceSupport{
				phase2Support("support_required_a", graph.requiredA, false),
				phase2Support("support_required_b", graph.requiredB, false),
			},
		),
	}
	graph.loader = &phase2GraphLoader{
		acceptanceLoader: &acceptanceLoader{items: items},
		clock:            clock,
	}
	graph.backend = &phase2GraphBackend{
		acceptanceBackend: newAcceptanceBackend(kag.CandidateHandle{Resource: graph.start, Score: 1}),
		fixture:           graph,
		clock:             clock,
	}
	return graph
}

func phase2Resource(
	id protocol.ResourceID,
	resourceType protocol.ResourceType,
	content string,
) protocol.ResourceHandle {
	resource := acceptanceResource(id, resourceType, content)
	resource.AuthorizationID = string(resourceType) + ":" + string(id)
	return resource
}

func phase2Support(
	supportID string,
	resource protocol.ResourceHandle,
	complete bool,
) protocol.ProvenanceSupport {
	return protocol.ProvenanceSupport{
		SupportID: supportID,
		Resource:  resource,
		Evidence:  []protocol.ResourceHandle{resource},
		Complete:  complete,
	}
}

func phase2EntityEvidence(
	resource protocol.ResourceHandle,
	content string,
	source protocol.ResourceHandle,
) protocol.EvidenceItem {
	return acceptanceEvidenceItem(
		resource,
		content,
		protocol.DerivationAnySupport,
		[]protocol.ProvenanceSupport{phase2Support("support_"+string(resource.ResourceID), source, true)},
	)
}

func phase2TraversalConfig(depth int) authorized.TraversalConfig {
	return authorized.TraversalConfig{
		Enabled:          true,
		PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateSupports},
		ResourceKinds: []protocol.GraphResourceKind{
			protocol.GraphResourceClaim,
			protocol.GraphResourceEntity,
		},
		Direction: protocol.TraversalOutbound,
		Limits: protocol.TraversalLimits{
			MaxDepth: depth, MaxFrontierWidth: 16, MaxCandidatesPerHop: 16,
			MaxTotalResources: 64, MaxBatchChecks: 32, MaxWallClockMillis: 1_000,
		},
	}
}

func (f *phase2PermissionedGraphFixture) newService(
	t testing.TB,
	invariant string,
	oracle *phase2PolicyOracle,
	cache *authorized.QueryCache,
	config authorized.TraversalConfig,
) *authorized.Service {
	return f.newServiceWithTelemetry(t, invariant, oracle, cache, config, nil)
}

func (f *phase2PermissionedGraphFixture) newServiceWithTelemetry(
	t testing.TB,
	invariant string,
	oracle *phase2PolicyOracle,
	cache *authorized.QueryCache,
	config authorized.TraversalConfig,
	sink telemetry.Sink,
) *authorized.Service {
	t.Helper()
	options := authorized.Options{
		KAG: f.backend, Authorizer: oracle, Loader: f.loader, Cache: cache,
		RetrieverVersion: "phase2_retriever_v1", PromptVersion: "phase2_prompt_v1",
		RetrieveLimit: 1, EvidenceLimit: 4, Traversal: config, Now: f.clock.Now, Telemetry: sink,
	}
	service, err := authorized.New(options)
	if err != nil {
		acceptanceFatalf(t, invariant, "create Phase 2 graph service: %v", err)
	}
	return service
}

func (f *phase2PermissionedGraphFixture) allowedResourceIDs(principal string) map[protocol.ResourceID]bool {
	allowed := make(map[protocol.ResourceID]bool)
	allow := func(resources ...protocol.ResourceHandle) {
		for _, resource := range resources {
			allowed[resource.ResourceID] = true
		}
	}
	switch principal {
	case fixture.Alice:
		allow(
			f.start, f.bridgeClaim, f.middle, f.alternateClaim, f.sharedTerminal,
			f.fanoutClaim, f.fanoutEntity, f.cycleClaim, f.deepClaim, f.deepTerminal,
			f.source, f.visibleSupport, f.requiredA, f.requiredB,
		)
	case fixture.Bob:
		allow(f.start, f.bridgeClaim, f.middle, f.alternateClaim, f.sharedTerminal, f.source, f.visibleSupport)
	}
	return allowed
}

func (f *phase2PermissionedGraphFixture) newPolicyOracle(
	t testing.TB,
	invariant string,
) *phase2PolicyOracle {
	t.Helper()
	const organization = "organization:phase2-tenant"
	tuples := []authz.Tuple{
		{User: "user:" + fixture.Alice, Relation: authz.RelationMember, Object: organization},
		{User: "user:" + fixture.Bob, Relation: authz.RelationMember, Object: organization},
	}
	for _, resource := range f.allResources {
		tuples = append(tuples, authz.Tuple{
			User: organization, Relation: authz.RelationOrganization, Object: resource.AuthorizationID,
		})
	}
	for _, principal := range []string{fixture.Alice, fixture.Bob} {
		allowed := f.allowedResourceIDs(principal)
		for _, resource := range f.allResources {
			if !allowed[resource.ResourceID] {
				continue
			}
			tuples = append(tuples, authz.Tuple{
				User: "user:" + principal, Relation: authz.RelationViewer, Object: resource.AuthorizationID,
			})
		}
	}
	for _, edge := range f.edges {
		tuples = append(tuples,
			authz.Tuple{User: f.source.AuthorizationID, Relation: authz.RelationSourceDocument, Object: edge.claim.AuthorizationID},
			authz.Tuple{User: edge.from.AuthorizationID, Relation: authz.RelationSubject, Object: edge.claim.AuthorizationID},
			authz.Tuple{User: edge.to.AuthorizationID, Relation: authz.RelationObject, Object: edge.claim.AuthorizationID},
			authz.Tuple{User: "user:*", Relation: authz.RelationRestricted, Object: edge.claim.AuthorizationID},
		)
	}
	local, err := authz.NewLocalAuthorizer(fixture.AuthorizationModelID, tuples)
	if err != nil {
		acceptanceFatalf(t, invariant, "create Phase 2 policy oracle: %v", err)
	}
	delegate := &phase2OracleDelegate{local: local, clock: f.clock}
	return &phase2PolicyOracle{
		recordingAuthorizer: &recordingAuthorizer{delegate: delegate},
		local:               local,
		delegate:            delegate,
	}
}

type phase2OracleHook func(
	context.Context,
	authz.BatchCheckRequest,
	[]authz.Decision,
	error,
) ([]authz.Decision, error)

type phase2OracleDelegate struct {
	mu    sync.Mutex
	local *authz.LocalAuthorizer
	clock *phase2SyntheticClock
	hook  phase2OracleHook
}

func (d *phase2OracleDelegate) BatchCheck(
	ctx context.Context,
	request authz.BatchCheckRequest,
) ([]authz.Decision, error) {
	d.clock.Advance(phase2BatchCheckDuration)
	decisions, err := d.local.BatchCheck(ctx, request)
	d.mu.Lock()
	hook := d.hook
	d.mu.Unlock()
	if hook != nil {
		return hook(ctx, request, decisions, err)
	}
	return decisions, err
}

type phase2PolicyOracle struct {
	*recordingAuthorizer
	local    *authz.LocalAuthorizer
	delegate *phase2OracleDelegate
}

func (o *phase2PolicyOracle) setHook(hook phase2OracleHook) {
	o.delegate.mu.Lock()
	o.delegate.hook = hook
	o.delegate.mu.Unlock()
}

func (o *phase2PolicyOracle) removeViewer(
	principal string,
	resource protocol.ResourceHandle,
) error {
	return o.local.RemoveTuple(authz.Tuple{
		User: "user:" + principal, Relation: authz.RelationViewer, Object: resource.AuthorizationID,
	})
}

type phase2ExpandObservation struct {
	phase    kag.ExpandPhase
	frontier []protocol.ResourceHandle
}

type phase2GraphBackendStats struct {
	acceptanceBackendStats
	discoverCalls int
	expands       []phase2ExpandObservation
}

type phase2ExpandHook func(context.Context, int, kag.ExpandRequest) error

type phase2GraphBackend struct {
	*acceptanceBackend
	fixture *phase2PermissionedGraphFixture
	clock   *phase2SyntheticClock

	graphMu       sync.Mutex
	discoverCalls int
	expands       []phase2ExpandObservation
	expandHook    phase2ExpandHook
}

func (b *phase2GraphBackend) Discover(
	ctx context.Context,
	request kag.DiscoverRequest,
) (kag.DiscoverResult, error) {
	if err := ctx.Err(); err != nil {
		return kag.DiscoverResult{}, err
	}
	if err := request.Validate(); err != nil {
		return kag.DiscoverResult{}, err
	}
	b.clock.Advance(phase2DiscoverDuration)
	b.graphMu.Lock()
	b.discoverCalls++
	b.graphMu.Unlock()

	resources := make([]protocol.ResourceHandle, 0, len(b.fixture.allResources))
	for _, resource := range b.fixture.allResources {
		if acceptanceContainsResourceType(request.ResourceTypes, resource.Type) {
			resources = append(resources, resource)
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	return kag.DiscoverResult{Mode: "phase2-fixture", Resources: resources, Complete: true}, nil
}

func (b *phase2GraphBackend) Retrieve(
	ctx context.Context,
	request kag.RetrieveRequest,
) (kag.RetrieveResult, error) {
	if err := ctx.Err(); err != nil {
		return kag.RetrieveResult{}, err
	}
	b.clock.Advance(phase2RetrieveDuration)
	return b.acceptanceBackend.Retrieve(ctx, request)
}

func (b *phase2GraphBackend) Expand(
	ctx context.Context,
	request kag.ExpandRequest,
) (kag.ExpandResult, error) {
	if err := ctx.Err(); err != nil {
		return kag.ExpandResult{}, err
	}
	b.clock.Advance(phase2ExpandDuration)
	observation := phase2ExpandObservation{phase: request.Phase, frontier: make([]protocol.ResourceHandle, len(request.Frontier))}
	for index, candidate := range request.Frontier {
		observation.frontier[index] = candidate.Resource
	}
	b.graphMu.Lock()
	call := len(b.expands)
	b.expands = append(b.expands, observation)
	hook := b.expandHook
	b.graphMu.Unlock()
	b.acceptanceBackend.mu.Lock()
	b.acceptanceBackend.expandCalls++
	b.acceptanceBackend.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, call, request); err != nil {
			return kag.ExpandResult{}, err
		}
	}

	frontier := make(map[protocol.ResourceID]struct{}, len(request.Frontier))
	for _, candidate := range request.Frontier {
		frontier[candidate.Resource.ResourceID] = struct{}{}
	}
	candidates := make(map[protocol.ResourceID]kag.CandidateHandle)
	expansions := make([]kag.ExpansionHandle, 0)
	predicate := request.Operation.Parameters.PredicateKeys[0]
	for _, edge := range b.fixture.edges {
		var candidate kag.CandidateHandle
		var expansion kag.ExpansionHandle
		switch request.Phase {
		case kag.ExpandPhaseEntityToClaim:
			if _, ok := frontier[edge.from.ResourceID]; !ok {
				continue
			}
			candidate = kag.CandidateHandle{Resource: edge.claim, Score: edge.claimScore}
			expansion = kag.ExpansionHandle{
				FromResourceID: edge.from.ResourceID, ToResourceID: edge.claim.ResourceID,
				ClaimResourceID: edge.claim.ResourceID, PredicateKey: predicate, Hop: 1,
			}
		case kag.ExpandPhaseClaimToObject:
			if _, ok := frontier[edge.claim.ResourceID]; !ok {
				continue
			}
			candidate = kag.CandidateHandle{Resource: edge.to, Score: edge.objectScore}
			expansion = kag.ExpansionHandle{
				FromResourceID: edge.claim.ResourceID, ToResourceID: edge.to.ResourceID,
				ClaimResourceID: edge.claim.ResourceID, PredicateKey: predicate, Hop: 1,
			}
		default:
			return kag.ExpandResult{}, fmt.Errorf("unsupported Phase 2 expansion phase %q", request.Phase)
		}
		if previous, ok := candidates[candidate.Resource.ResourceID]; !ok || candidate.Score > previous.Score {
			candidates[candidate.Resource.ResourceID] = candidate
		}
		expansions = append(expansions, expansion)
	}

	orderedCandidates := make([]kag.CandidateHandle, 0, len(candidates))
	for _, candidate := range candidates {
		orderedCandidates = append(orderedCandidates, candidate)
	}
	sort.Slice(orderedCandidates, func(i, j int) bool {
		if orderedCandidates[i].Score != orderedCandidates[j].Score {
			return orderedCandidates[i].Score > orderedCandidates[j].Score
		}
		return orderedCandidates[i].Resource.ResourceID < orderedCandidates[j].Resource.ResourceID
	})
	sort.Slice(expansions, func(i, j int) bool {
		left, right := expansions[i], expansions[j]
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
	return kag.ExpandResult{Mode: "phase2-fixture", Candidates: orderedCandidates, Expansions: expansions}, nil
}

func (b *phase2GraphBackend) Generate(
	ctx context.Context,
	request kag.GenerateRequest,
) (kag.GenerateResult, error) {
	if err := ctx.Err(); err != nil {
		return kag.GenerateResult{}, err
	}
	b.clock.Advance(phase2GenerateDuration)
	return b.acceptanceBackend.Generate(ctx, request)
}

func (b *phase2GraphBackend) setExpandHook(hook phase2ExpandHook) {
	b.graphMu.Lock()
	b.expandHook = hook
	b.graphMu.Unlock()
}

func (b *phase2GraphBackend) graphStats() phase2GraphBackendStats {
	b.graphMu.Lock()
	discoverCalls := b.discoverCalls
	expands := make([]phase2ExpandObservation, len(b.expands))
	for index, observation := range b.expands {
		expands[index] = phase2ExpandObservation{
			phase: observation.phase, frontier: append([]protocol.ResourceHandle(nil), observation.frontier...),
		}
	}
	b.graphMu.Unlock()
	return phase2GraphBackendStats{
		acceptanceBackendStats: b.acceptanceBackend.stats(),
		discoverCalls:          discoverCalls,
		expands:                expands,
	}
}

type phase2GraphLoader struct {
	*acceptanceLoader
	clock *phase2SyntheticClock
}

func (l *phase2GraphLoader) Load(
	ctx context.Context,
	handles []protocol.ResourceHandle,
) ([]protocol.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.clock.Advance(phase2LoadDuration)
	return l.acceptanceLoader.Load(ctx, handles)
}

func phase2PathResourceIDs(path kag.GeneratePath) []protocol.ResourceID {
	result := make([]protocol.ResourceID, len(path.Resources))
	for index, resource := range path.Resources {
		result[index] = resource.ResourceID
	}
	return result
}

func phase2FrontierContains(observation phase2ExpandObservation, resourceID protocol.ResourceID) bool {
	for _, resource := range observation.frontier {
		if resource.ResourceID == resourceID {
			return true
		}
	}
	return false
}
