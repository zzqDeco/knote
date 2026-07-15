package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

const (
	phase2GraphModelID         = "01J10000000000000000000000"
	phase2GraphProjection      = "prj_33333333333333333333333333333333"
	phase2GraphAnswerCanary    = "PHASE2_GRAPH_PROTECTED_ANSWER_CANARY"
	phase2GraphCitationCanary  = "citation-phase2-terminal-canary"
	phase2GraphQuestion        = "follow the phase2 graph"
	phase2GraphRetriever       = "phase2-graph-retriever-v1"
	phase2GraphPrompt          = "phase2-graph-prompt-v1"
	phase2GraphRuntimeSession  = "sess-phase2-graph-replay"
	phase2GraphRuntimeToolName = "knote_query"
)

func TestPhase2GraphReplayAcceptanceRevocationClosesTraversalCacheCitationAndSession(t *testing.T) {
	fixture := newPhase2GraphFixture(t)
	backend := newPhase2GraphBackend(fixture)
	authorizer := &phase2GraphAuthorizer{}
	loader := &phase2GraphLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		fixture.terminal.ResourceID: fixture.evidence,
	}}
	cache, err := authorized.NewQueryCache(8)
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	service, err := authorized.New(authorized.Options{
		KAG: backend, Authorizer: authorizer, Loader: loader, Cache: cache,
		RetrieverVersion: phase2GraphRetriever, PromptVersion: phase2GraphPrompt,
		RetrieveLimit: 8, EvidenceLimit: 8,
		Traversal: authorized.TraversalConfig{
			Enabled: true, PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateLocatedIn},
			ResourceKinds: []protocol.GraphResourceKind{protocol.GraphResourceEntity},
			Direction:     protocol.TraversalOutbound,
			Limits: protocol.TraversalLimits{
				MaxDepth: 1, MaxFrontierWidth: 8, MaxCandidatesPerHop: 8,
				MaxTotalResources: 16, MaxBatchChecks: 12, MaxWallClockMillis: 2_000,
			},
		},
		Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := authorized.NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}

	workspace := t.TempDir()
	store := local.New(workspace)
	provider := newPhase2GraphAuthorizationProvider()
	runner := &phase2GraphRunner{service: service}
	manager := New(Dependencies{
		Workspace: workspace, Sessions: store, EinoRunner: runner,
		AuthorizationContextProvider: provider,
		ProtectedContentAuthorizer:   phase2GraphProtectedContentAuthorizer(service),
		NewSessionID:                 func() string { return phase2GraphRuntimeSession },
	})
	if _, err := manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	manager.SendMessage(context.Background(), "/help")
	localEvents := manager.Interrupt(context.Background())
	if len(localEvents) != 1 || localEvents[0].Type != protocol.EventStatusUpdate {
		t.Fatalf("safe local history = %+v", localEvents)
	}
	safeLocalMessage := localEvents[0].Message
	queryEvents := manager.SendMessage(context.Background(), phase2GraphQuestion)
	if hasEvent(queryEvents, protocol.EventError) {
		t.Fatalf("initial graph query failed: %+v", queryEvents)
	}
	initial := runner.snapshot()
	if initial.result.Traversal == nil || initial.result.Traversal.AuthorizedPathCompleteness != 1 ||
		initial.result.Traversal.CompletePathCount != 1 || len(initial.result.Evidence.Items) != 1 {
		t.Fatalf("initial traversal result = %+v", initial.result)
	}
	if !phase2GraphBindingContains(initial.binding, fixture.claim.ResourceID) {
		t.Fatalf("protected binding omitted intermediate Claim %s: %+v", fixture.claim.ResourceID, initial.binding)
	}
	if backend.stats().generateCalls != 1 {
		t.Fatalf("initial generate calls = %d", backend.stats().generateCalls)
	}

	opened, err := service.OpenCitation(
		context.Background(), initial.authorization, initial.result.Evidence, phase2GraphCitationCanary,
	)
	if err != nil || opened.Content != fixture.evidence.Content {
		t.Fatalf("citation before revocation = %+v, %v", opened, err)
	}

	objectExpansionStarted, releaseObjectExpansion := backend.blockNextObjectExpansion()
	secondAuthorization := initial.authorization
	secondAuthorization.RequestID = "request-phase2-graph-inflight"
	type queryOutcome struct {
		result authorized.QueryResult
		err    error
	}
	done := make(chan queryOutcome, 1)
	go func() {
		result, queryErr := service.Query(context.Background(), protocol.QueryRequest{
			Question: phase2GraphQuestion, Authorization: secondAuthorization,
		})
		done <- queryOutcome{result: result, err: queryErr}
	}()
	select {
	case <-objectExpansionStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("second traversal did not reach object expansion")
	}
	report, err := coordinator.Apply(context.Background(), authorized.RevocationRequest{
		Authorization: initial.authorization, Binding: initial.binding,
		ResourceIDs: []protocol.ResourceID{fixture.claim.ResourceID}, RevokedAt: fixedNow.Add(-time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.InvalidatedResourceCount != 1 || report.RemovedEntryCount != 1 {
		t.Fatalf("revocation report = %+v", report)
	}
	close(releaseObjectExpansion)
	var inFlight queryOutcome
	select {
	case inFlight = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked traversal did not finish")
	}
	if !errors.Is(inFlight.err, authorized.ErrProtectedContentUnavailable) {
		t.Fatalf("in-flight revocation error = %v", inFlight.err)
	}
	if inFlight.result.Generation.Answer != "" || backend.stats().generateCalls != 1 {
		t.Fatalf("revoked in-flight traversal generated content: result=%+v stats=%+v", inFlight.result, backend.stats())
	}

	thirdAuthorization := initial.authorization
	thirdAuthorization.RequestID = "request-phase2-graph-after-revocation"
	_, err = service.Query(context.Background(), protocol.QueryRequest{
		Question: phase2GraphQuestion, Authorization: thirdAuthorization,
	})
	if !errors.Is(err, authorized.ErrProtectedContentUnavailable) || backend.stats().generateCalls != 1 {
		t.Fatalf("cached path after revocation = err %v, stats %+v", err, backend.stats())
	}

	loadCalls := loader.callCount()
	_, err = service.OpenCitation(
		context.Background(), thirdAuthorization, initial.result.Evidence, phase2GraphCitationCanary,
	)
	if !errors.Is(err, authorized.ErrCitationUnavailable) {
		t.Fatalf("citation after Claim revocation error = %v", err)
	}
	if loader.callCount() != loadCalls {
		t.Fatalf("revoked citation loaded content: calls=%d want=%d", loader.callCount(), loadCalls)
	}

	replayManager := New(Dependencies{
		Workspace: workspace, Sessions: store, EinoRunner: &phase2GraphRunner{service: service},
		AuthorizationContextProvider: provider,
		ProtectedContentAuthorizer:   phase2GraphProtectedContentAuthorizer(service),
	})
	replayed, err := replayManager.Start(context.Background(), StartOptions{ResumeID: phase2GraphRuntimeSession})
	if err != nil {
		t.Fatal(err)
	}
	if !permissionedAcceptanceHasSafeSlash(replayed) ||
		!strings.Contains(permissionedAcceptanceEventText(replayed), safeLocalMessage) {
		t.Fatalf("safe local history was not replayed: %+v", replayed)
	}
	if permissionedAcceptanceHasBlock(replayed, initial.binding.BlockID) ||
		strings.Contains(permissionedAcceptanceEventText(replayed), phase2GraphAnswerCanary) ||
		strings.Contains(permissionedAcceptanceEventText(replayed), phase2GraphCitationCanary) ||
		strings.Contains(permissionedAcceptanceEventText(replayed), string(fixture.claim.ResourceID)) {
		t.Fatalf("revoked protected graph history replayed: %+v", replayed)
	}
	if loader.callCount() != loadCalls {
		t.Fatalf("revoked session replay loaded content: calls=%d want=%d", loader.callCount(), loadCalls)
	}
}

type phase2GraphFixture struct {
	start     protocol.ResourceHandle
	claim     protocol.ResourceHandle
	terminal  protocol.ResourceHandle
	support   protocol.ResourceHandle
	evidence  protocol.EvidenceItem
	predicate protocol.ClaimPredicateKey
}

func newPhase2GraphFixture(t *testing.T) phase2GraphFixture {
	t.Helper()
	start := phase2GraphResource("res_30000000000000000000000000000001", protocol.ResourceEntity, "phase2 start")
	claim := phase2GraphResource("res_30000000000000000000000000000002", protocol.ResourceClaim, "phase2 claim")
	terminal := phase2GraphResource("res_30000000000000000000000000000003", protocol.ResourceEntity, "phase2 terminal")
	support := phase2GraphResource("res_30000000000000000000000000000004", protocol.ResourceDocument, "phase2 support")
	predicate, err := protocol.NewClaimPredicateKey(string(protocol.ClaimPredicateLocatedIn))
	if err != nil {
		t.Fatal(err)
	}
	evidence := protocol.EvidenceItem{
		Resource: terminal, Content: "phase2 terminal", Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "phase2-support", Resource: support,
			Evidence: []protocol.ResourceHandle{support}, Complete: true,
		}},
		Citation: protocol.Citation{Handle: phase2GraphCitationCanary, Resource: terminal},
	}
	return phase2GraphFixture{
		start: start, claim: claim, terminal: terminal, support: support,
		evidence: evidence, predicate: predicate,
	}
}

func phase2GraphResource(
	resourceID protocol.ResourceID,
	resourceType protocol.ResourceType,
	content string,
) protocol.ResourceHandle {
	return protocol.ResourceHandle{
		ResourceID: resourceID, Type: resourceType, TenantID: "tenant-phase2", KnowledgeBaseID: "kb-phase2",
		AuthorizationID:         string(resourceType) + ":" + string(resourceID),
		AuthorizationResourceID: resourceID, ContentDigest: protocol.NewContentDigest(content),
		Versions: protocol.ResourceVersions{
			Source: "source-phase2-v1", Content: "content-phase2-v1", ACL: "acl-phase2-v1",
			Index: "index-phase2-v1", Graph: "graph-phase2-v1", Projection: phase2GraphProjection,
		},
		ServingState: protocol.ServingActive,
	}
}

func phase2GraphAuthorization(sessionID, requestID string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version: protocol.SecurityContractVersion, TenantID: "tenant-phase2", KnowledgeBaseID: "kb-phase2",
		PrincipalID: "alice", SessionID: sessionID, RequestID: requestID,
		AuthorizationModelID: phase2GraphModelID, IdentityWatermark: "identity-phase2-v1",
		ACLWatermark: "acl-phase2-v1", Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func newPhase2GraphAuthorizationProvider() AuthorizationContextProvider {
	var mu sync.Mutex
	sequence := 0
	return func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		mu.Lock()
		sequence++
		requestID := fmt.Sprintf("request-phase2-graph-%02d", sequence)
		mu.Unlock()
		return phase2GraphAuthorization(sessionID, requestID), nil
	}
}

func phase2GraphProtectedContentAuthorizer(service *authorized.Service) ProtectedContentAuthorizer {
	return func(
		ctx context.Context,
		current protocol.AuthorizationContext,
		binding protocol.ProtectedContentBinding,
	) error {
		_, err := service.AuthorizeProtectedContent(ctx, current, binding)
		return err
	}
}

func phase2GraphBindingContains(binding protocol.ProtectedContentBinding, resourceID protocol.ResourceID) bool {
	for _, resource := range binding.Resources {
		if resource.Resource.ResourceID == resourceID || resource.AuthorizationResource.ResourceID == resourceID {
			return true
		}
	}
	return false
}

type phase2GraphRunnerSnapshot struct {
	authorization protocol.AuthorizationContext
	result        authorized.QueryResult
	binding       protocol.ProtectedContentBinding
}

type phase2GraphRunner struct {
	service *authorized.Service

	mu   sync.Mutex
	last phase2GraphRunnerSnapshot
}

func (r *phase2GraphRunner) Ready(context.Context) error {
	if r == nil || r.service == nil {
		return errors.New("phase2 graph runner is unavailable")
	}
	return nil
}

func (*phase2GraphRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return []RunnerToolInfo{{Name: phase2GraphRuntimeToolName, Description: "phase2 graph query"}}, nil
}

func (r *phase2GraphRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok {
		return nil, errors.New("phase2 graph query requires trusted authorization")
	}
	result, err := r.service.Query(ctx, protocol.QueryRequest{
		Question: input.Message, Authorization: authorization,
	})
	if err != nil {
		return nil, err
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
	if err != nil {
		return nil, err
	}
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventToolComplete, input.SessionID, "phase2 graph query complete", map[string]any{
			"tool": phase2GraphRuntimeToolName,
		}),
		protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, result.Generation.Answer, map[string]any{
			"citations": result.Generation.Citations,
		}),
	}
	for index := range events {
		copy := binding
		events[index].ProtectedContent = &copy
	}
	r.mu.Lock()
	r.last = phase2GraphRunnerSnapshot{authorization: authorization, result: result, binding: binding}
	r.mu.Unlock()
	return events, nil
}

func (r *phase2GraphRunner) snapshot() phase2GraphRunnerSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

type phase2GraphBackendStats struct {
	discoverCalls int
	retrieveCalls int
	expandCalls   int
	generateCalls int
}

type phase2GraphBackend struct {
	fixture phase2GraphFixture

	mu                     sync.Mutex
	statsValue             phase2GraphBackendStats
	blockObjectExpansion   bool
	objectExpansionStarted chan struct{}
	releaseObjectExpansion chan struct{}
}

func newPhase2GraphBackend(fixture phase2GraphFixture) *phase2GraphBackend {
	return &phase2GraphBackend{fixture: fixture}
}

func (b *phase2GraphBackend) blockNextObjectExpansion() (<-chan struct{}, chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blockObjectExpansion = true
	b.objectExpansionStarted = make(chan struct{})
	b.releaseObjectExpansion = make(chan struct{})
	return b.objectExpansionStarted, b.releaseObjectExpansion
}

func (b *phase2GraphBackend) stats() phase2GraphBackendStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.statsValue
}

func (b *phase2GraphBackend) Discover(
	_ context.Context,
	_ kag.DiscoverRequest,
) (kag.DiscoverResult, error) {
	b.mu.Lock()
	b.statsValue.discoverCalls++
	b.mu.Unlock()
	return kag.DiscoverResult{
		Mode: "fake", Resources: []protocol.ResourceHandle{b.fixture.start}, Complete: true,
	}, nil
}

func (b *phase2GraphBackend) Retrieve(
	_ context.Context,
	request kag.RetrieveRequest,
) (kag.RetrieveResult, error) {
	b.mu.Lock()
	b.statsValue.retrieveCalls++
	b.mu.Unlock()
	for _, allowed := range request.AllowedResources {
		if allowed == b.fixture.start {
			return kag.RetrieveResult{Mode: "fake", Candidates: []kag.CandidateHandle{{
				Resource: b.fixture.start, Score: 1,
			}}}, nil
		}
	}
	return kag.RetrieveResult{Mode: "fake"}, nil
}

func (b *phase2GraphBackend) Expand(
	ctx context.Context,
	request kag.ExpandRequest,
) (kag.ExpandResult, error) {
	b.mu.Lock()
	b.statsValue.expandCalls++
	block := request.Phase == kag.ExpandPhaseClaimToObject && b.blockObjectExpansion
	started := b.objectExpansionStarted
	release := b.releaseObjectExpansion
	if block {
		b.blockObjectExpansion = false
	}
	b.mu.Unlock()
	if block {
		close(started)
		select {
		case <-ctx.Done():
			return kag.ExpandResult{}, ctx.Err()
		case <-release:
		}
	}
	if request.Phase == kag.ExpandPhaseEntityToClaim {
		return kag.ExpandResult{
			Mode:       "fake",
			Candidates: []kag.CandidateHandle{{Resource: b.fixture.claim, Score: 0.9}},
			Expansions: []kag.ExpansionHandle{{
				FromResourceID: b.fixture.start.ResourceID, ToResourceID: b.fixture.claim.ResourceID,
				ClaimResourceID: b.fixture.claim.ResourceID, PredicateKey: b.fixture.predicate, Hop: 1,
			}},
		}, nil
	}
	return kag.ExpandResult{
		Mode:       "fake",
		Candidates: []kag.CandidateHandle{{Resource: b.fixture.terminal, Score: 0.8}},
		Expansions: []kag.ExpansionHandle{{
			FromResourceID: b.fixture.claim.ResourceID, ToResourceID: b.fixture.terminal.ResourceID,
			ClaimResourceID: b.fixture.claim.ResourceID, PredicateKey: b.fixture.predicate, Hop: 1,
		}},
	}, nil
}

func (b *phase2GraphBackend) Generate(
	_ context.Context,
	request kag.GenerateRequest,
) (kag.GenerateResult, error) {
	b.mu.Lock()
	b.statsValue.generateCalls++
	b.mu.Unlock()
	result := kag.GenerateResult{Mode: "fake", Answer: phase2GraphAnswerCanary}
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

type phase2GraphAuthorizer struct {
	mu    sync.Mutex
	calls int
}

func (a *phase2GraphAuthorizer) BatchCheck(
	ctx context.Context,
	request authz.BatchCheckRequest,
) ([]authz.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	decisions := make([]authz.Decision, len(request.Checks))
	for index, check := range request.Checks {
		decisions[index] = authz.Decision{
			CorrelationID: check.CorrelationID, Allowed: true,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions, nil
}

type phase2GraphLoader struct {
	mu    sync.Mutex
	items map[protocol.ResourceID]protocol.EvidenceItem
	calls int
}

func (l *phase2GraphLoader) Load(
	ctx context.Context,
	handles []protocol.ResourceHandle,
) ([]protocol.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	items := make([]protocol.EvidenceItem, len(handles))
	for index, handle := range handles {
		item, ok := l.items[handle.ResourceID]
		if !ok || item.Resource != handle {
			return nil, fmt.Errorf("phase2 graph loader missing exact resource %s", handle.ResourceID)
		}
		items[index] = phase2CloneGraphEvidence(item)
	}
	return items, nil
}

func (l *phase2GraphLoader) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func phase2CloneGraphEvidence(item protocol.EvidenceItem) protocol.EvidenceItem {
	clone := item
	clone.Supports = make([]protocol.ProvenanceSupport, len(item.Supports))
	for index, support := range item.Supports {
		clone.Supports[index] = support
		clone.Supports[index].Evidence = append([]protocol.ResourceHandle(nil), support.Evidence...)
	}
	return clone
}
