package authorized_test

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	acceptanceProjectionVersion = fixture.ProjectionVersion
	acceptanceSourceVersion     = "source_fake_v1"
	acceptanceContentVersion    = "content_fake_v1"
	acceptanceACLVersion        = "acl_fake_v1"
	acceptanceIndexVersion      = "index_" + acceptanceProjectionVersion
	acceptanceGraphVersion      = "graph_" + acceptanceProjectionVersion

	fixtureIntroID        protocol.ResourceID = "res_00000000000000000000000000000001"
	fixtureDeniedCanaryID protocol.ResourceID = "res_00000000000000000000000000000002"
	fixtureOverviewID     protocol.ResourceID = "res_00000000000000000000000000000003"

	acceptanceSourceID    protocol.ResourceID = "res_10000000000000000000000000000001"
	acceptanceEntityID    protocol.ResourceID = "res_10000000000000000000000000000002"
	acceptanceDeniedID    protocol.ResourceID = "res_10000000000000000000000000000003"
	acceptanceAlternateID protocol.ResourceID = "res_10000000000000000000000000000004"
	acceptanceDerivedID   protocol.ResourceID = "res_10000000000000000000000000000005"
	acceptanceSecondDocID protocol.ResourceID = "res_10000000000000000000000000000006"

	fixtureIntroContent        = "knote is local-first."
	fixtureDeniedCanaryContent = "DENIED CANARY BODY must never cross the authorization boundary"
	fixtureOverviewContent     = "knote exposes a versioned knowledge workflow."
)

// These are CI guardrails for deterministic in-memory fixtures, not production SLOs.
const (
	acceptanceQueryBudget      = time.Second
	acceptanceRetrievalBudget  = time.Second
	acceptanceBatchCheckBudget = time.Second
	acceptanceRevocationSLO    = time.Second
)

var acceptanceCheckedAt = time.Date(2026, time.July, 13, 1, 0, 0, 0, time.UTC)

func acceptanceFatalf(t testing.TB, invariant, format string, args ...any) {
	t.Helper()
	detail := fmt.Sprintf(format, args...)
	t.Fatalf(
		"invariant=%q projection=%q authz_model=%q: %s",
		invariant,
		acceptanceProjectionVersion,
		fixture.AuthorizationModelID,
		detail,
	)
}

func acceptanceService(
	t testing.TB,
	invariant string,
	backend kag.PrimitiveBackend,
	authorizer authz.BatchChecker,
	loader authorized.EvidenceLoader,
	retrieveLimit int,
	evidenceLimit int,
) *authorized.Service {
	t.Helper()
	service, err := authorized.New(authorized.Options{
		KAG:           backend,
		Authorizer:    authorizer,
		Loader:        loader,
		RetrieveLimit: retrieveLimit,
		EvidenceLimit: evidenceLimit,
		ExpandLimit:   0,
		Now:           func() time.Time { return acceptanceCheckedAt },
	})
	if err != nil {
		acceptanceFatalf(t, invariant, "create authorized service: %v", err)
	}
	return service
}

func acceptanceAuthorization(sessionID string) protocol.AuthorizationContext {
	return fixture.Authorization(fixture.Alice, sessionID)
}

func fixtureResource(id protocol.ResourceID, content string) protocol.ResourceHandle {
	resourceType := protocol.ResourceDocument
	if id == fixtureIntroID || id == fixtureDeniedCanaryID {
		resourceType = protocol.ResourceEntity
	}
	resource := acceptanceResource(id, resourceType, content)
	resource.AuthorizationID = string(resourceType) + ":" + string(id)
	return resource
}

func acceptanceResource(id protocol.ResourceID, resourceType protocol.ResourceType, content string) protocol.ResourceHandle {
	return protocol.ResourceHandle{
		ResourceID:              id,
		Type:                    resourceType,
		TenantID:                fixture.TenantID,
		KnowledgeBaseID:         fixture.KnowledgeBaseID,
		AuthorizationID:         "document:" + string(id),
		AuthorizationResourceID: id,
		ContentDigest:           protocol.NewContentDigest(content),
		Versions: protocol.ResourceVersions{
			Source:     acceptanceSourceVersion,
			Content:    acceptanceContentVersion,
			ACL:        acceptanceACLVersion,
			Index:      acceptanceIndexVersion,
			Graph:      acceptanceGraphVersion,
			Projection: acceptanceProjectionVersion,
		},
		ServingState: protocol.ServingActive,
	}
}

func fixtureCandidates() []kag.CandidateHandle {
	return []kag.CandidateHandle{
		{Resource: fixtureResource(fixtureIntroID, fixtureIntroContent), Score: 0.99},
		{Resource: fixtureResource(fixtureDeniedCanaryID, fixtureDeniedCanaryContent), Score: 0.98},
		{Resource: fixtureResource(fixtureOverviewID, fixtureOverviewContent), Score: 0.90},
	}
}

type acceptanceBackend struct {
	mu                sync.Mutex
	candidates        []kag.CandidateHandle
	retrieveErr       error
	retrieveRequests  []kag.RetrieveRequest
	retrieveLatencies []time.Duration
	expandCalls       int
	generateRequests  []kag.GenerateRequest
}

func newAcceptanceBackend(candidates ...kag.CandidateHandle) *acceptanceBackend {
	return &acceptanceBackend{candidates: append([]kag.CandidateHandle(nil), candidates...)}
}

func (b *acceptanceBackend) Discover(_ context.Context, request kag.DiscoverRequest) (kag.DiscoverResult, error) {
	b.mu.Lock()
	candidates := append([]kag.CandidateHandle(nil), b.candidates...)
	b.mu.Unlock()
	resources := make([]protocol.ResourceHandle, 0, len(candidates))
	for _, candidate := range candidates {
		if acceptanceContainsResourceType(request.ResourceTypes, candidate.Resource.Type) {
			resources = append(resources, candidate.Resource)
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	return kag.DiscoverResult{Mode: "acceptance-fixture", Resources: resources, Complete: true}, nil
}

func acceptanceContainsResourceType(types []protocol.ResourceType, target protocol.ResourceType) bool {
	for _, resourceType := range types {
		if resourceType == target {
			return true
		}
	}
	return false
}

func (b *acceptanceBackend) Retrieve(_ context.Context, request kag.RetrieveRequest) (kag.RetrieveResult, error) {
	started := time.Now()
	b.mu.Lock()
	b.retrieveRequests = append(b.retrieveRequests, request)
	candidates := append([]kag.CandidateHandle(nil), b.candidates...)
	err := b.retrieveErr
	b.retrieveLatencies = append(b.retrieveLatencies, time.Since(started))
	b.mu.Unlock()
	if err != nil {
		return kag.RetrieveResult{}, err
	}
	allowed := make(map[protocol.ResourceID]protocol.ResourceHandle, len(request.AllowedResources))
	for _, resource := range request.AllowedResources {
		allowed[resource.ResourceID] = resource
	}
	filtered := make([]kag.CandidateHandle, 0, len(candidates))
	for _, candidate := range candidates {
		if resource, ok := allowed[candidate.Resource.ResourceID]; ok && resource == candidate.Resource {
			filtered = append(filtered, candidate)
		}
	}
	return kag.RetrieveResult{Mode: "acceptance-fixture", Candidates: filtered}, nil
}

func (b *acceptanceBackend) Expand(context.Context, kag.ExpandRequest) (kag.ExpandResult, error) {
	b.mu.Lock()
	b.expandCalls++
	b.mu.Unlock()
	return kag.ExpandResult{}, fmt.Errorf("acceptance fixture expansion is disabled")
}

func (b *acceptanceBackend) Generate(_ context.Context, request kag.GenerateRequest) (kag.GenerateResult, error) {
	b.mu.Lock()
	b.generateRequests = append(b.generateRequests, cloneGenerateRequest(request))
	b.mu.Unlock()

	contents := make([]string, len(request.Evidence))
	result := kag.GenerateResult{Mode: "acceptance-fixture"}
	for index, evidence := range request.Evidence {
		contents[index] = evidence.Content
		result.Citations = append(result.Citations, kag.CitationHandle{
			Handle: evidence.CitationHandle, ResourceID: evidence.Resource.ResourceID,
		})
		result.EvidenceResourceIDs = append(result.EvidenceResourceIDs, evidence.Resource.ResourceID)
		result.Trace.ResourceIDs = append(result.Trace.ResourceIDs, evidence.Resource.ResourceID)
	}
	result.Answer = strings.Join(contents, " ")
	result.Trace.Count = len(result.Trace.ResourceIDs)
	return result, nil
}

type acceptanceBackendStats struct {
	retrieveRequests  []kag.RetrieveRequest
	retrieveLatencies []time.Duration
	expandCalls       int
	generateRequests  []kag.GenerateRequest
}

func (b *acceptanceBackend) stats() acceptanceBackendStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := acceptanceBackendStats{
		retrieveRequests:  append([]kag.RetrieveRequest(nil), b.retrieveRequests...),
		retrieveLatencies: append([]time.Duration(nil), b.retrieveLatencies...),
		expandCalls:       b.expandCalls,
		generateRequests:  make([]kag.GenerateRequest, len(b.generateRequests)),
	}
	for index, request := range b.generateRequests {
		stats.generateRequests[index] = cloneGenerateRequest(request)
	}
	return stats
}

func cloneGenerateRequest(request kag.GenerateRequest) kag.GenerateRequest {
	return request.Clone()
}

type acceptanceLoader struct {
	mu    sync.Mutex
	items map[protocol.ResourceID]protocol.EvidenceItem
	calls [][]protocol.ResourceHandle
}

func (l *acceptanceLoader) Load(ctx context.Context, handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	requested := append([]protocol.ResourceHandle(nil), handles...)
	l.mu.Lock()
	l.calls = append(l.calls, requested)
	l.mu.Unlock()

	items := make([]protocol.EvidenceItem, len(handles))
	for index, handle := range handles {
		item, ok := l.items[handle.ResourceID]
		if !ok {
			return nil, fmt.Errorf("acceptance loader has no resource %s", handle.ResourceID)
		}
		if item.Resource != handle {
			return nil, fmt.Errorf("acceptance loader exact handle mismatch for %s", handle.ResourceID)
		}
		items[index] = cloneEvidenceItem(item)
	}
	return items, nil
}

func (l *acceptanceLoader) recordedCalls() [][]protocol.ResourceHandle {
	l.mu.Lock()
	defer l.mu.Unlock()
	calls := make([][]protocol.ResourceHandle, len(l.calls))
	for index, call := range l.calls {
		calls[index] = append([]protocol.ResourceHandle(nil), call...)
	}
	return calls
}

func cloneEvidenceItem(item protocol.EvidenceItem) protocol.EvidenceItem {
	clone := item
	clone.Supports = make([]protocol.ProvenanceSupport, len(item.Supports))
	for index, support := range item.Supports {
		clone.Supports[index] = support
		clone.Supports[index].Evidence = append([]protocol.ResourceHandle(nil), support.Evidence...)
	}
	return clone
}

func acceptanceEvidenceItem(
	resource protocol.ResourceHandle,
	content string,
	mode protocol.DerivationMode,
	supports []protocol.ProvenanceSupport,
) protocol.EvidenceItem {
	return protocol.EvidenceItem{
		Resource:   resource,
		Content:    content,
		Derivation: mode,
		Supports:   supports,
		Citation: protocol.Citation{
			Handle: "citation_" + string(resource.ResourceID), Resource: resource,
		},
	}
}

func selfEvidenceItem(resource protocol.ResourceHandle, content string) protocol.EvidenceItem {
	return acceptanceEvidenceItem(resource, content, protocol.DerivationAnySupport, []protocol.ProvenanceSupport{{
		SupportID: "support_" + string(resource.ResourceID),
		Resource:  resource,
		Evidence:  []protocol.ResourceHandle{resource},
		Complete:  true,
	}})
}

type batchDecisionFunc func(context.Context, int, authz.BatchCheckRequest) ([]authz.Decision, error)

type recordingAuthorizer struct {
	mu        sync.Mutex
	delegate  authz.BatchChecker
	decide    batchDecisionFunc
	requests  []authz.BatchCheckRequest
	latencies []time.Duration
}

func (a *recordingAuthorizer) BatchCheck(ctx context.Context, request authz.BatchCheckRequest) ([]authz.Decision, error) {
	started := time.Now()
	a.mu.Lock()
	call := len(a.requests)
	copyRequest := request
	copyRequest.Checks = append([]authz.BatchCheckItem(nil), request.Checks...)
	a.requests = append(a.requests, copyRequest)
	a.mu.Unlock()

	var decisions []authz.Decision
	var err error
	if a.decide != nil {
		decisions, err = a.decide(ctx, call, request)
	} else {
		decisions, err = a.delegate.BatchCheck(ctx, request)
	}

	a.mu.Lock()
	a.latencies = append(a.latencies, time.Since(started))
	a.mu.Unlock()
	return decisions, err
}

type recordingAuthorizerStats struct {
	requests  []authz.BatchCheckRequest
	latencies []time.Duration
}

func (a *recordingAuthorizer) stats() recordingAuthorizerStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	stats := recordingAuthorizerStats{
		requests:  make([]authz.BatchCheckRequest, len(a.requests)),
		latencies: append([]time.Duration(nil), a.latencies...),
	}
	for index, request := range a.requests {
		stats.requests[index] = request
		stats.requests[index].Checks = append([]authz.BatchCheckItem(nil), request.Checks...)
	}
	return stats
}

func localRecordingAuthorizer(
	t testing.TB,
	invariant string,
	resources []protocol.ResourceHandle,
	allowed map[protocol.ResourceID]bool,
) *recordingAuthorizer {
	t.Helper()
	const organization = "organization:acceptance-tenant"
	tuples := []authz.Tuple{{
		User: "user:" + fixture.Alice, Relation: authz.RelationMember, Object: organization,
	}}
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if _, duplicate := seen[resource.AuthorizationID]; duplicate {
			continue
		}
		seen[resource.AuthorizationID] = struct{}{}
		tuples = append(tuples, authz.Tuple{
			User: organization, Relation: authz.RelationOrganization, Object: resource.AuthorizationID,
		})
		if allowed[resource.ResourceID] {
			tuples = append(tuples, authz.Tuple{
				User: "user:" + fixture.Alice, Relation: authz.RelationViewer, Object: resource.AuthorizationID,
			})
		}
	}
	local, err := authz.NewLocalAuthorizer(fixture.AuthorizationModelID, tuples)
	if err != nil {
		acceptanceFatalf(t, invariant, "create local policy oracle: %v", err)
	}
	return &recordingAuthorizer{delegate: local}
}

func acceptanceDecisions(request authz.BatchCheckRequest, allowed bool) []authz.Decision {
	decisions := make([]authz.Decision, len(request.Checks))
	for index, check := range request.Checks {
		decisions[index] = authz.Decision{
			CorrelationID:        check.CorrelationID,
			Allowed:              allowed,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions
}

func resourceIDs(items []protocol.EvidenceItem) []protocol.ResourceID {
	ids := make([]protocol.ResourceID, len(items))
	for index, item := range items {
		ids[index] = item.Resource.ResourceID
	}
	return ids
}

func evidenceIDs(evidence []kag.AuthorizedEvidence) []protocol.ResourceID {
	ids := make([]protocol.ResourceID, len(evidence))
	for index, item := range evidence {
		ids[index] = item.Resource.ResourceID
	}
	return ids
}

func containsResource(calls [][]protocol.ResourceHandle, resourceID protocol.ResourceID) bool {
	for _, call := range calls {
		for _, resource := range call {
			if resource.ResourceID == resourceID {
				return true
			}
		}
	}
	return false
}

func totalBatchChecks(requests []authz.BatchCheckRequest) int {
	total := 0
	for _, request := range requests {
		total += len(request.Checks)
	}
	return total
}

func maxDuration(values []time.Duration) time.Duration {
	var maximum time.Duration
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}

func percentileDuration(values []time.Duration, percentile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	rank := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(ordered) {
		rank = len(ordered) - 1
	}
	return ordered[rank]
}
