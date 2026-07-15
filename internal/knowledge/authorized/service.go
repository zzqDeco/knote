package authorized

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

var (
	errNoEvidence                   = errors.New("authorized query found no evidence")
	errIncompleteCandidateDiscovery = errors.New("authorized candidate discovery exceeded its hard limit")
)

const (
	defaultRetrieveLimit = 20
	defaultEvidenceLimit = 8
	maxPrimitiveLimit    = 100
)

type EvidenceLoader interface {
	Load(context.Context, []protocol.ResourceHandle) ([]protocol.EvidenceItem, error)
}

type Options struct {
	KAG              kag.PrimitiveBackend
	Authorizer       authz.BatchChecker
	Loader           EvidenceLoader
	Cache            *QueryCache
	Traversal        TraversalConfig
	RetrieverVersion string
	PromptVersion    string
	RetrieveLimit    int
	EvidenceLimit    int
	ExpandLimit      int
	Now              func() time.Time
	Telemetry        telemetry.Sink
}

type Service struct {
	kag              kag.PrimitiveBackend
	authorizer       authz.BatchChecker
	loader           EvidenceLoader
	cache            *QueryCache
	retrieverVersion string
	promptVersion    string
	retrieveLimit    int
	evidenceLimit    int
	traversal        traversalConfig
	traversalDigest  traversalPlanDigest
	now              func() time.Time
	telemetry        telemetry.Sink
}

type QueryResult struct {
	Generation kag.GenerateResult
	Evidence   protocol.EvidencePackage
	Traversal  *TraversalReport
}

func New(options Options) (*Service, error) {
	if options.KAG == nil {
		return nil, fmt.Errorf("authorized retrieval requires a KAG backend")
	}
	if options.Authorizer == nil {
		return nil, fmt.Errorf("authorized retrieval requires an authorizer")
	}
	if options.Loader == nil {
		return nil, fmt.Errorf("authorized retrieval requires an evidence loader")
	}
	if options.Cache != nil {
		if !options.Cache.initialized() {
			return nil, fmt.Errorf("authorized query cache is not initialized")
		}
		if err := validateTextToken("retriever_version", options.RetrieverVersion); err != nil {
			return nil, fmt.Errorf("authorized query cache: %w", err)
		}
		if err := validateTextToken("prompt_version", options.PromptVersion); err != nil {
			return nil, fmt.Errorf("authorized query cache: %w", err)
		}
	}
	if options.RetrieveLimit == 0 {
		options.RetrieveLimit = defaultRetrieveLimit
	}
	if options.EvidenceLimit == 0 {
		options.EvidenceLimit = defaultEvidenceLimit
	}
	if err := validateLimit("retrieve_limit", options.RetrieveLimit, false); err != nil {
		return nil, err
	}
	if err := validateLimit("evidence_limit", options.EvidenceLimit, false); err != nil {
		return nil, err
	}
	if options.ExpandLimit != 0 {
		return nil, fmt.Errorf("legacy untyped expand_limit is not supported; configure a typed traversal plan")
	}
	traversal, traversalDigest, err := normalizeTraversalConfig(options.Traversal)
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Telemetry == nil {
		options.Telemetry = telemetry.NopSink{}
	}
	return &Service{
		kag: options.KAG, authorizer: options.Authorizer, loader: options.Loader, cache: options.Cache,
		retrieverVersion: options.RetrieverVersion, promptVersion: options.PromptVersion,
		retrieveLimit: options.RetrieveLimit, evidenceLimit: options.EvidenceLimit,
		traversal: traversal, traversalDigest: traversalDigest,
		now: options.Now, telemetry: options.Telemetry,
	}, nil
}

func (s *Service) Query(ctx context.Context, request protocol.QueryRequest) (result QueryResult, err error) {
	if ctx == nil {
		return QueryResult{}, fmt.Errorf("authorized query requires a context")
	}
	if err := request.Validate(); err != nil {
		return QueryResult{}, fmt.Errorf("authorized query: %w", err)
	}
	queryContext := ctx
	var budget *traversalBudget
	if s.traversal.enabled {
		var cancel context.CancelFunc
		budget, queryContext, cancel = newTraversalBudget(ctx, s.traversal.limits, s.now)
		defer cancel()
		defer func() {
			report := budget.report()
			result.Traversal = &report
			_ = s.telemetry.Emit(ctx, traversalTelemetryRecord(report, result, err))
		}()
		if err := budget.check(); err != nil {
			return QueryResult{}, err
		}
	}
	useCache := s.cache != nil
	var cacheKey queryCacheKey
	if useCache && !s.traversal.enabled {
		cacheKey = newQueryCacheKey(
			request, s.retrieverVersion, s.promptVersion,
			s.retrieveLimit, s.evidenceLimit,
			traversalPlanDigest{}, traversalPlanDigest{},
		)
		if snapshot, ok := s.cache.get(cacheKey); ok {
			cached, err := s.revalidateCached(queryContext, request, snapshot.result, nil)
			if err == nil && s.cache.containsRevision(cacheKey, snapshot.revision) {
				return cached, nil
			}
			s.cache.deleteIfRevision(cacheKey, snapshot.revision)
		}
	}
	authorization := request.Authorization
	allowedResources, err := s.discoverAuthorizedResources(queryContext, authorization, budget)
	if err != nil {
		return QueryResult{}, err
	}
	retrieveRequest := kag.RetrieveRequest{
		Authorization:    authorization,
		Query:            request.Question,
		AllowedResources: allowedResources,
		Limit:            s.retrieveLimit,
	}
	retrieved, err := s.kag.Retrieve(queryContext, retrieveRequest)
	if err != nil {
		if budget != nil {
			return QueryResult{}, traversalExternalCallError(budget, err)
		}
		return QueryResult{}, fmt.Errorf("authorized query retrieve: %w", err)
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return QueryResult{}, err
		}
	}
	if err := retrieved.ValidateFor(retrieveRequest); err != nil {
		if budget != nil {
			return QueryResult{}, errInvalidTraversalResponse
		}
		return QueryResult{}, fmt.Errorf("authorized query retrieve result: %w", err)
	}
	if len(retrieved.Candidates) == 0 {
		return QueryResult{}, errNoEvidence
	}

	var selected []kag.CandidateHandle
	var traversalPaths []traversalPath
	var traversalGroups []traversalTerminalGroup
	var traversalPlan traversalPlanDigest
	if s.traversal.enabled {
		execution, err := s.executeTraversal(queryContext, authorization, retrieved.Candidates, budget)
		if err != nil {
			return QueryResult{}, err
		}
		traversalPlan = execution.planDigest
		traversalGroups = execution.terminalGroups()
		selected = traversalGroupCandidates(traversalGroups)
	} else {
		// Discovery authorized every exact resource before the provider ranked
		// it, and RetrieveResult.ValidateFor proved the provider stayed inside
		// that scope. The final evidence check below remains the live revocation
		// gate immediately before generation.
		selected = appendCandidates(nil, retrieved.Candidates, s.evidenceLimit)
	}
	if len(selected) == 0 {
		return QueryResult{}, errNoEvidence
	}

	handles := make([]protocol.ResourceHandle, len(selected))
	for index, candidate := range selected {
		handles[index] = candidate.Resource
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return QueryResult{}, err
		}
	}
	items, err := s.loadExact(queryContext, authorization, handles)
	if err != nil {
		if budget != nil {
			return QueryResult{}, traversalExternalCallError(budget, err)
		}
		return QueryResult{}, fmt.Errorf("authorized query load evidence: %w", err)
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return QueryResult{}, err
		}
	}
	var checked checkedEvidence
	if s.traversal.enabled {
		items, traversalPaths, checked, err = s.finalizeTraversalEvidence(
			queryContext, authorization, items, traversalGroups, s.evidenceLimit, budget,
		)
		if err == nil {
			budget.setCompletePaths(len(items))
		}
	} else {
		items, checked, err = s.checkEvidence(queryContext, authorization, "f", items)
	}
	if err != nil {
		if errors.Is(err, errNoEvidence) {
			return QueryResult{}, errNoEvidence
		}
		return QueryResult{}, fmt.Errorf("authorized query final evidence check: %w", err)
	}
	if useCache && s.traversal.enabled {
		pathDigest, err := digestTraversalPaths(traversalPaths)
		if err != nil {
			return QueryResult{}, errInvalidTraversalResponse
		}
		cacheKey = newQueryCacheKey(
			request, s.retrieverVersion, s.promptVersion,
			s.retrieveLimit, s.evidenceLimit,
			traversalPlan, pathDigest,
		)
		if snapshot, ok := s.cache.get(cacheKey); ok {
			cached, err := s.revalidateCached(queryContext, request, snapshot.result, budget)
			if err != nil {
				s.cache.deleteIfRevision(cacheKey, snapshot.revision)
				return QueryResult{}, err
			}
			if !s.cache.containsRevision(cacheKey, snapshot.revision) {
				return QueryResult{}, ErrProtectedContentUnavailable
			}
			budget.setCompletePaths(len(cached.Evidence.Items))
			return cached, nil
		}
	}
	// This is the final evidence authorization check. No content-bearing or graph
	// operation is allowed between this check and generation.
	checkedAt := s.now().UTC()
	if checkedAt.IsZero() {
		return QueryResult{}, fmt.Errorf("authorized query final evidence check returned a zero timestamp")
	}
	evidencePackage, err := buildEvidencePackage(authorization, items, checked, checkedAt)
	if err != nil {
		return QueryResult{}, fmt.Errorf("authorized query evidence package: %w", err)
	}
	if useCache && s.cache.containsInvalidatedResource(evidenceResourceIDs(checked.handles, checked.boundaries)) {
		return QueryResult{}, ErrProtectedContentUnavailable
	}

	generateRequest := newGenerateRequest(authorization, request.Question, items)
	if s.traversal.enabled {
		paths, err := generateTraversalPaths(traversalPaths)
		if err != nil || len(paths) != len(items) {
			return QueryResult{}, errInvalidTraversalResponse
		}
		generateRequest.Paths = paths
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return QueryResult{}, err
		}
	}
	generation, err := s.kag.Generate(queryContext, generateRequest)
	if err != nil {
		if budget != nil {
			return QueryResult{}, traversalExternalCallError(budget, err)
		}
		return QueryResult{}, fmt.Errorf("authorized query generate: %w", err)
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return QueryResult{}, err
		}
	}
	if err := generation.ValidateFor(generateRequest); err != nil {
		return QueryResult{}, fmt.Errorf("authorized query generate result: %w", err)
	}
	result = QueryResult{Generation: generation, Evidence: evidencePackage}
	if useCache && !s.cache.put(cacheKey, result) {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	return result, nil
}

func (s *Service) discoverAuthorizedResources(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	budget *traversalBudget,
) ([]protocol.ResourceHandle, error) {
	resourceTypes := []protocol.ResourceType{
		protocol.ResourceChunk,
		protocol.ResourceClaim,
		protocol.ResourceDerivedArtifact,
		protocol.ResourceDocument,
		protocol.ResourceEntity,
	}
	if s.traversal.enabled {
		resourceTypes = []protocol.ResourceType{protocol.ResourceEntity}
	}
	request := kag.DiscoverRequest{
		Authorization: authorization,
		ResourceTypes: resourceTypes,
		Limit:         maxPrimitiveLimit,
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return nil, err
		}
	}
	discovered, err := s.kag.Discover(ctx, request)
	if err != nil {
		if budget != nil {
			return nil, traversalExternalCallError(budget, err)
		}
		return nil, fmt.Errorf("authorized query discover: %w", err)
	}
	if budget != nil {
		if err := budget.check(); err != nil {
			return nil, err
		}
	}
	if err := discovered.ValidateFor(request); err != nil {
		if budget != nil {
			return nil, errInvalidTraversalResponse
		}
		return nil, fmt.Errorf("authorized query discover result: %w", err)
	}
	if !discovered.Complete {
		if budget != nil {
			return nil, errTraversalBudgetExceeded
		}
		return nil, errIncompleteCandidateDiscovery
	}
	if len(discovered.Resources) == 0 {
		return nil, errNoEvidence
	}

	if budget != nil {
		if err := budget.addResources(discovered.Resources); err != nil {
			return nil, err
		}
		checks, err := s.checkTraversalResources(
			ctx, authorization, "tr-discover", discovered.Resources, budget,
		)
		if err != nil {
			return nil, err
		}
		budget.recordHop(0, TraversalPhaseDiscovery, discovered.Resources, checks)
		allowed := make([]protocol.ResourceHandle, 0, len(discovered.Resources))
		for _, resource := range discovered.Resources {
			if checks[resource.AuthorizationID].allowed {
				allowed = append(allowed, resource)
			}
		}
		if len(allowed) == 0 {
			return nil, errNoEvidence
		}
		return allowed, nil
	}

	candidates := make([]kag.CandidateHandle, len(discovered.Resources))
	for index, resource := range discovered.Resources {
		candidates[index] = kag.CandidateHandle{Resource: resource}
	}
	allowed, err := s.filterAuthorizedCandidates(ctx, authorization, "pre-rank", candidates)
	if err != nil {
		return nil, fmt.Errorf("authorized query discovery authorization: %w", err)
	}
	if len(allowed) == 0 {
		return nil, errNoEvidence
	}
	resources := make([]protocol.ResourceHandle, len(allowed))
	for index, candidate := range allowed {
		resources[index] = candidate.Resource
	}
	return resources, nil
}

type checkedEvidence struct {
	handles    []protocol.ResourceHandle
	boundaries map[protocol.ResourceID]protocol.ResourceHandle
	projection string
	objects    map[string]objectCheck
}

func (s *Service) revalidateCached(
	ctx context.Context,
	request protocol.QueryRequest,
	cached QueryResult,
	budget *traversalBudget,
) (QueryResult, error) {
	original := authorizationFromPackage(cached.Evidence)
	if err := cached.Evidence.ValidateFor(original); err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	expectedFingerprint, err := protocol.NewVisibilityFingerprint(
		request.Authorization,
		cached.Evidence.ProjectionVersion,
	)
	if err != nil || expectedFingerprint != cached.Evidence.VisibilityFingerprint {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	originalGenerate := newGenerateRequest(original, request.Question, cached.Evidence.Items)
	if err := cached.Generation.ValidateFor(originalGenerate); err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	bindings, err := cachedDecisionBindings(request.Authorization, cached.Evidence)
	if err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	if budget != nil {
		budgetResources := append([]protocol.ResourceHandle(nil), bindings.handles...)
		for _, resource := range bindings.handles {
			budgetResources = append(budgetResources, bindings.boundaries[resource.ResourceID])
		}
		if err := budget.addResources(budgetResources); err != nil {
			return QueryResult{}, err
		}
	}
	if _, err := s.checkCachedDecisionBindings(
		ctx, request.Authorization, "cache", bindings, budget,
	); err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	handles := make([]protocol.ResourceHandle, len(cached.Evidence.Items))
	for index, item := range cached.Evidence.Items {
		handles[index] = item.Resource
	}
	loaded, err := s.loadExact(ctx, request.Authorization, handles)
	if err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	loaded, ok := reloadSelectedEvidenceItems(loaded, cached.Evidence.Items)
	if !ok {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	checked, err := s.checkCachedDecisionBindings(
		ctx, request.Authorization, "cache-final", bindings, budget,
	)
	if err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	checkedAt := s.now().UTC()
	if checkedAt.IsZero() {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	evidencePackage, err := buildEvidencePackage(request.Authorization, loaded, checked, checkedAt)
	if err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	generateRequest := newGenerateRequest(request.Authorization, request.Question, loaded)
	if err := cached.Generation.ValidateFor(generateRequest); err != nil {
		return QueryResult{}, ErrProtectedContentUnavailable
	}
	return QueryResult{
		Generation: cloneGeneration(cached.Generation),
		Evidence:   evidencePackage,
	}, nil
}

func cachedDecisionBindings(
	authorization protocol.AuthorizationContext,
	evidence protocol.EvidencePackage,
) (checkedEvidence, error) {
	if err := authorization.Validate(); err != nil || len(evidence.Decisions) == 0 {
		return checkedEvidence{}, ErrProtectedContentUnavailable
	}
	bindings := checkedEvidence{
		handles:    make([]protocol.ResourceHandle, 0, len(evidence.Decisions)),
		boundaries: make(map[protocol.ResourceID]protocol.ResourceHandle, len(evidence.Decisions)),
		projection: evidence.ProjectionVersion,
	}
	seen := make(map[protocol.ResourceID]protocol.ResourceHandle, len(evidence.Decisions))
	for _, decision := range evidence.Decisions {
		resource := decision.Resource
		boundary := decision.AuthorizationResource
		if err := resource.ValidateFor(authorization); err != nil ||
			boundary.ValidateFor(authorization) != nil ||
			resource.Versions.Projection != bindings.projection ||
			boundary.Versions.Projection != bindings.projection ||
			validateBoundary(resource, boundary) != nil {
			return checkedEvidence{}, ErrProtectedContentUnavailable
		}
		if existing, duplicate := seen[resource.ResourceID]; duplicate {
			if existing != resource || bindings.boundaries[resource.ResourceID] != boundary {
				return checkedEvidence{}, ErrProtectedContentUnavailable
			}
			continue
		}
		seen[resource.ResourceID] = resource
		bindings.handles = append(bindings.handles, resource)
		bindings.boundaries[resource.ResourceID] = boundary
	}
	return bindings, nil
}

func (s *Service) checkCachedDecisionBindings(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	bindings checkedEvidence,
	budget *traversalBudget,
) (checkedEvidence, error) {
	boundaries := make([]protocol.ResourceHandle, len(bindings.handles))
	for index, resource := range bindings.handles {
		boundary, ok := bindings.boundaries[resource.ResourceID]
		if !ok {
			return checkedEvidence{}, ErrProtectedContentUnavailable
		}
		boundaries[index] = boundary
	}
	var (
		checked map[string]objectCheck
		err     error
	)
	if budget == nil {
		checked, err = s.checkLiveObjects(ctx, authorization, stage, boundaries)
	} else {
		authorization.Consistency = protocol.ConsistencyHigherConsistency
		checked, err = s.checkTraversalResources(ctx, authorization, stage, boundaries, budget)
	}
	if err != nil {
		return checkedEvidence{}, err
	}
	objects := make(map[string]objectCheck, len(bindings.handles))
	for index, resource := range bindings.handles {
		result, ok := checked[boundaries[index].AuthorizationID]
		if !ok || !result.allowed {
			return checkedEvidence{}, ErrProtectedContentUnavailable
		}
		objects[resource.AuthorizationID] = result
	}
	bindings.objects = objects
	return bindings, nil
}

func (s *Service) checkEvidence(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	items []protocol.EvidenceItem,
) ([]protocol.EvidenceItem, checkedEvidence, error) {
	handles, _, _, err := collectEvidenceHandles(authorization, items)
	if err != nil {
		return nil, checkedEvidence{}, err
	}
	objects, err := s.checkObjects(ctx, authorization, stage, handles)
	if err != nil {
		return nil, checkedEvidence{}, err
	}
	selected := selectAuthorizedEvidenceItems(items, objects)
	if len(selected) == 0 {
		return nil, checkedEvidence{}, errNoEvidence
	}
	checked, err := checkedEvidenceForItems(authorization, selected, objects)
	if err != nil {
		return nil, checkedEvidence{}, err
	}
	return selected, checked, nil
}

func buildEvidencePackage(
	authorization protocol.AuthorizationContext,
	items []protocol.EvidenceItem,
	checked checkedEvidence,
	checkedAt time.Time,
) (protocol.EvidencePackage, error) {
	decisions := make([]protocol.AuthorizationDecision, len(checked.handles))
	for index, resource := range checked.handles {
		result := checked.objects[resource.AuthorizationID]
		decision := protocol.AuthorizationDecision{
			CorrelationID:         result.correlationID,
			RequestID:             authorization.RequestID,
			SessionID:             authorization.SessionID,
			PrincipalID:           authorization.PrincipalID,
			AgentID:               authorization.AgentID,
			TaskID:                authorization.TaskID,
			Relation:              protocol.EvidenceReadRelation,
			Resource:              resource,
			AuthorizationResource: checked.boundaries[resource.ResourceID],
			Outcome:               protocol.DecisionAllow,
			AuthorizationModelID:  authorization.AuthorizationModelID,
			IdentityWatermark:     authorization.IdentityWatermark,
			ACLWatermark:          authorization.ACLWatermark,
			Consistency:           authorization.Consistency,
			CheckedAt:             checkedAt,
		}
		if err := decision.ValidateFor(authorization); err != nil {
			return protocol.EvidencePackage{}, fmt.Errorf("authorization decision for resource %s: %w", resource.ResourceID, err)
		}
		decisions[index] = decision
	}
	fingerprint, err := protocol.NewVisibilityFingerprint(authorization, checked.projection)
	if err != nil {
		return protocol.EvidencePackage{}, fmt.Errorf("visibility fingerprint: %w", err)
	}
	result := protocol.EvidencePackage{
		Version:               protocol.SecurityContractVersion,
		TenantID:              authorization.TenantID,
		KnowledgeBaseID:       authorization.KnowledgeBaseID,
		PrincipalID:           authorization.PrincipalID,
		SessionID:             authorization.SessionID,
		RequestID:             authorization.RequestID,
		AgentID:               authorization.AgentID,
		TaskID:                authorization.TaskID,
		AuthorizationModelID:  authorization.AuthorizationModelID,
		IdentityWatermark:     authorization.IdentityWatermark,
		ACLWatermark:          authorization.ACLWatermark,
		Consistency:           authorization.Consistency,
		ProjectionVersion:     checked.projection,
		VisibilityFingerprint: fingerprint,
		Items:                 cloneEvidenceItems(items),
		Decisions:             decisions,
	}
	if err := result.ValidateFor(authorization); err != nil {
		return protocol.EvidencePackage{}, err
	}
	return result, nil
}

func newGenerateRequest(
	authorization protocol.AuthorizationContext,
	question string,
	items []protocol.EvidenceItem,
) kag.GenerateRequest {
	request := kag.GenerateRequest{
		Authorization: authorization,
		Question:      question,
		Evidence:      make([]kag.AuthorizedEvidence, len(items)),
	}
	for index, item := range items {
		request.Evidence[index] = kag.AuthorizedEvidence{
			Resource: item.Resource, Content: item.Content, CitationHandle: item.Citation.Handle,
		}
	}
	return request
}

func (s *Service) OpenCitation(
	ctx context.Context,
	current protocol.AuthorizationContext,
	evidencePackage protocol.EvidencePackage,
	citationHandle string,
) (protocol.EvidenceItem, error) {
	if ctx == nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	original := authorizationFromPackage(evidencePackage)
	if err := evidencePackage.ValidateFor(original); err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	if err := current.Validate(); err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	if err := validateCurrentCitationContext(current, original); err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	if err := validateTextToken("citation_handle", citationHandle); err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	var cited *protocol.EvidenceItem
	for index := range evidencePackage.Items {
		if evidencePackage.Items[index].Citation.Handle != citationHandle {
			continue
		}
		if cited != nil {
			return protocol.EvidenceItem{}, ErrCitationUnavailable
		}
		cited = &evidencePackage.Items[index]
	}
	if cited == nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	bindings, err := cachedDecisionBindings(current, evidencePackage)
	if err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	resourceIDs := evidenceResourceIDs(bindings.handles, bindings.boundaries)
	if s.cache != nil && s.cache.containsInvalidatedResource(resourceIDs) {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	if _, err := s.checkCachedDecisionBindings(ctx, current, "c", bindings, nil); err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	loaded, err := s.loadExact(ctx, current, []protocol.ResourceHandle{cited.Resource})
	if err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	selected, ok := reloadSelectedEvidenceItem(loaded[0], *cited)
	if !ok {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	if _, err := s.checkCachedDecisionBindings(ctx, current, "c-final", bindings, nil); err != nil {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	if s.cache != nil && s.cache.containsInvalidatedResource(resourceIDs) {
		return protocol.EvidenceItem{}, ErrCitationUnavailable
	}
	return selected, nil
}

type objectCheck struct {
	correlationID string
	allowed       bool
}

func (s *Service) filterAuthorizedCandidates(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	candidates []kag.CandidateHandle,
) ([]kag.CandidateHandle, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	handles := make([]protocol.ResourceHandle, len(candidates))
	for index, candidate := range candidates {
		handles[index] = candidate.Resource
	}
	checked, err := s.checkObjects(ctx, authorization, stage, handles)
	if err != nil {
		return nil, err
	}
	approved := make([]kag.CandidateHandle, 0, len(candidates))
	for _, candidate := range candidates {
		if checked[candidate.Resource.AuthorizationID].allowed {
			approved = append(approved, candidate)
		}
	}
	return approved, nil
}

func (s *Service) checkObjects(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	resources []protocol.ResourceHandle,
) (map[string]objectCheck, error) {
	if err := authorization.Validate(); err != nil {
		return nil, err
	}
	consistency, err := canonicalConsistency(authorization.Consistency)
	if err != nil {
		return nil, err
	}
	objects := make([]string, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		if err := resource.ValidateFor(authorization); err != nil {
			return nil, fmt.Errorf("resource %d: %w", index, err)
		}
		if _, duplicate := seen[resource.AuthorizationID]; duplicate {
			continue
		}
		seen[resource.AuthorizationID] = struct{}{}
		objects = append(objects, resource.AuthorizationID)
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("authorization check requires at least one resource")
	}
	result := make(map[string]objectCheck, len(objects))
	for start := 0; start < len(objects); start += authz.MaxBatchChecks {
		end := start + authz.MaxBatchChecks
		if end > len(objects) {
			end = len(objects)
		}
		request := authz.BatchCheckRequest{
			AuthorizationModelID: authorization.AuthorizationModelID,
			Consistency:          consistency,
			Checks:               make([]authz.BatchCheckItem, end-start),
		}
		expected := make(map[string]string, len(request.Checks))
		for index, object := range objects[start:end] {
			correlationID := deterministicCorrelationID(stage, start+index, object)
			request.Checks[index] = authz.BatchCheckItem{
				CorrelationID: correlationID,
				User:          "user:" + authorization.PrincipalID,
				Relation:      authz.RelationCanView,
				Object:        object,
			}
			expected[correlationID] = object
		}
		if err := request.Validate(); err != nil {
			return nil, fmt.Errorf("batch request: %w", err)
		}
		decisions, err := s.authorizer.BatchCheck(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("batch check: %w", err)
		}
		if len(decisions) != len(request.Checks) {
			return nil, fmt.Errorf("batch check returned %d decisions for %d checks", len(decisions), len(request.Checks))
		}
		seenDecisions := make(map[string]struct{}, len(decisions))
		for _, decision := range decisions {
			object, ok := expected[decision.CorrelationID]
			if !ok {
				return nil, fmt.Errorf("batch check returned unexpected correlation_id %q", decision.CorrelationID)
			}
			if _, duplicate := seenDecisions[decision.CorrelationID]; duplicate {
				return nil, fmt.Errorf("batch check returned duplicate correlation_id %q", decision.CorrelationID)
			}
			seenDecisions[decision.CorrelationID] = struct{}{}
			if decision.AuthorizationModelID != authorization.AuthorizationModelID {
				return nil, fmt.Errorf("batch check correlation_id %q returned authorization model %q", decision.CorrelationID, decision.AuthorizationModelID)
			}
			result[object] = objectCheck{correlationID: decision.CorrelationID, allowed: decision.Allowed}
		}
		for _, check := range request.Checks {
			if _, ok := seenDecisions[check.CorrelationID]; !ok {
				return nil, fmt.Errorf("batch check omitted correlation_id %q", check.CorrelationID)
			}
		}
	}
	return result, nil
}

func (s *Service) loadExact(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	requested []protocol.ResourceHandle,
) ([]protocol.EvidenceItem, error) {
	loaded, err := s.loader.Load(ctx, append([]protocol.ResourceHandle(nil), requested...))
	if err != nil {
		return nil, err
	}
	if len(loaded) != len(requested) {
		return nil, fmt.Errorf("loader returned %d items for %d handles", len(loaded), len(requested))
	}
	byID := make(map[protocol.ResourceID]protocol.EvidenceItem, len(loaded))
	for index, item := range loaded {
		if _, duplicate := byID[item.Resource.ResourceID]; duplicate {
			return nil, fmt.Errorf("loader returned duplicate resource %s", item.Resource.ResourceID)
		}
		byID[item.Resource.ResourceID] = item
		if err := validateLoadedItem(authorization, item); err != nil {
			return nil, fmt.Errorf("loader item %d: %w", index, err)
		}
	}
	ordered := make([]protocol.EvidenceItem, len(requested))
	for index, handle := range requested {
		item, ok := byID[handle.ResourceID]
		if !ok {
			return nil, fmt.Errorf("loader omitted resource %s", handle.ResourceID)
		}
		if item.Resource != handle {
			return nil, fmt.Errorf("loader changed resource handle %s", handle.ResourceID)
		}
		ordered[index] = item
	}
	return ordered, nil
}

func validateLoadedItem(authorization protocol.AuthorizationContext, item protocol.EvidenceItem) error {
	if err := item.Resource.ValidateFor(authorization); err != nil {
		return err
	}
	if strings.TrimSpace(item.Content) == "" {
		return fmt.Errorf("resource %s has empty content", item.Resource.ResourceID)
	}
	if protocol.NewContentDigest(item.Content) != item.Resource.ContentDigest {
		return fmt.Errorf("resource %s content does not match its handle", item.Resource.ResourceID)
	}
	mode := item.Derivation
	if item.Resource.Type == protocol.ResourceDerivedArtifact && mode == "" {
		mode = protocol.DerivationAllRequired
	}
	if err := protocol.ValidateProvenance(mode, item.Supports); err != nil {
		return err
	}
	for _, support := range item.Supports {
		if err := validateEvidenceHandle(authorization, item.Resource.Versions.Projection, support.Resource); err != nil {
			return err
		}
		for _, evidence := range support.Evidence {
			if err := validateEvidenceHandle(authorization, item.Resource.Versions.Projection, evidence); err != nil {
				return err
			}
		}
	}
	if err := validateTextToken("citation_handle", item.Citation.Handle); err != nil {
		return err
	}
	if item.Citation.Resource != item.Resource {
		return fmt.Errorf("citation resource does not match evidence resource %s", item.Resource.ResourceID)
	}
	return nil
}

func collectEvidenceHandles(
	authorization protocol.AuthorizationContext,
	items []protocol.EvidenceItem,
) ([]protocol.ResourceHandle, map[protocol.ResourceID]protocol.ResourceHandle, string, error) {
	ordered := make([]protocol.ResourceHandle, 0, len(items))
	seen := make(map[protocol.ResourceID]protocol.ResourceHandle)
	chunkBoundaries := make(map[protocol.ResourceID]protocol.ResourceHandle)
	projection := ""
	add := func(resource protocol.ResourceHandle) error {
		if err := resource.ValidateFor(authorization); err != nil {
			return err
		}
		if projection == "" {
			projection = resource.Versions.Projection
		} else if resource.Versions.Projection != projection {
			return fmt.Errorf("resource %s crosses projection %q", resource.ResourceID, projection)
		}
		if existing, duplicate := seen[resource.ResourceID]; duplicate {
			if existing != resource {
				return fmt.Errorf("resource %s has conflicting handles", resource.ResourceID)
			}
			return nil
		}
		seen[resource.ResourceID] = resource
		ordered = append(ordered, resource)
		return nil
	}
	recordChunkBoundary := func(resource protocol.ResourceHandle, supports []protocol.ProvenanceSupport) error {
		if resource.Type != protocol.ResourceChunk {
			return nil
		}
		boundary, err := boundaryFromSupports(resource, supports)
		if err != nil {
			return err
		}
		if existing, duplicate := chunkBoundaries[resource.ResourceID]; duplicate && existing != boundary {
			return fmt.Errorf("chunk %s has conflicting parent authorization boundaries", resource.ResourceID)
		}
		chunkBoundaries[resource.ResourceID] = boundary
		return nil
	}
	for _, item := range items {
		if err := add(item.Resource); err != nil {
			return nil, nil, "", err
		}
		for _, support := range item.Supports {
			if err := add(support.Resource); err != nil {
				return nil, nil, "", err
			}
			for _, evidence := range support.Evidence {
				if err := add(evidence); err != nil {
					return nil, nil, "", err
				}
			}
		}
		if item.Derivation == protocol.DerivationAnySupport {
			for _, support := range item.Supports {
				currentSupport := []protocol.ProvenanceSupport{support}
				if err := recordChunkBoundary(item.Resource, currentSupport); err != nil {
					return nil, nil, "", err
				}
				if err := recordChunkBoundary(support.Resource, currentSupport); err != nil {
					return nil, nil, "", err
				}
				for _, evidence := range support.Evidence {
					if err := recordChunkBoundary(evidence, currentSupport); err != nil {
						return nil, nil, "", err
					}
				}
			}
			continue
		}
		if err := recordChunkBoundary(item.Resource, item.Supports); err != nil {
			return nil, nil, "", err
		}
		for _, support := range item.Supports {
			if err := recordChunkBoundary(support.Resource, item.Supports); err != nil {
				return nil, nil, "", err
			}
			for _, evidence := range support.Evidence {
				if err := recordChunkBoundary(evidence, item.Supports); err != nil {
					return nil, nil, "", err
				}
			}
		}
	}
	boundaries := make(map[protocol.ResourceID]protocol.ResourceHandle, len(ordered))
	for _, resource := range ordered {
		boundary := resource
		if resource.Type == protocol.ResourceChunk {
			boundary = chunkBoundaries[resource.ResourceID]
		}
		if err := validateBoundary(resource, boundary); err != nil {
			return nil, nil, "", err
		}
		boundaries[resource.ResourceID] = boundary
	}
	return ordered, boundaries, projection, nil
}

func boundaryFromSupports(resource protocol.ResourceHandle, supports []protocol.ProvenanceSupport) (protocol.ResourceHandle, error) {
	if resource.Type != protocol.ResourceChunk {
		return resource, nil
	}
	var boundary protocol.ResourceHandle
	found := false
	consider := func(candidate protocol.ResourceHandle) error {
		if candidate.ResourceID != resource.AuthorizationResourceID {
			return nil
		}
		if found && boundary != candidate {
			return fmt.Errorf("chunk %s has conflicting parent authorization boundaries", resource.ResourceID)
		}
		boundary = candidate
		found = true
		return nil
	}
	for _, support := range supports {
		if err := consider(support.Resource); err != nil {
			return protocol.ResourceHandle{}, err
		}
		for _, evidence := range support.Evidence {
			if err := consider(evidence); err != nil {
				return protocol.ResourceHandle{}, err
			}
		}
	}
	if !found {
		return protocol.ResourceHandle{}, fmt.Errorf("chunk %s has no parent authorization boundary in provenance supports", resource.ResourceID)
	}
	return boundary, nil
}

func validateBoundary(resource, boundary protocol.ResourceHandle) error {
	decision := protocol.AuthorizationDecision{
		CorrelationID: "boundary", RequestID: "boundary", SessionID: "boundary", PrincipalID: "boundary",
		Relation: protocol.EvidenceReadRelation, Resource: resource, AuthorizationResource: boundary,
		Outcome: protocol.DecisionAllow, AuthorizationModelID: "boundary", IdentityWatermark: "boundary",
		ACLWatermark: "boundary", Consistency: protocol.ConsistencyHigherConsistency,
		CheckedAt: time.Unix(1, 0).UTC(),
	}
	if err := decision.Validate(); err != nil {
		return fmt.Errorf("resource %s authorization boundary: %w", resource.ResourceID, err)
	}
	return nil
}

func validateEvidenceHandle(authorization protocol.AuthorizationContext, projection string, resource protocol.ResourceHandle) error {
	if err := resource.ValidateFor(authorization); err != nil {
		return err
	}
	if resource.Versions.Projection != projection {
		return fmt.Errorf("resource %s crosses projection %q", resource.ResourceID, projection)
	}
	return nil
}

func appendCandidates(target, candidates []kag.CandidateHandle, limit int) []kag.CandidateHandle {
	seen := make(map[protocol.ResourceID]struct{}, len(target)+len(candidates))
	for _, candidate := range target {
		seen[candidate.Resource.ResourceID] = struct{}{}
	}
	for _, candidate := range candidates {
		if len(target) >= limit {
			break
		}
		if _, duplicate := seen[candidate.Resource.ResourceID]; duplicate {
			continue
		}
		seen[candidate.Resource.ResourceID] = struct{}{}
		target = append(target, candidate)
	}
	return target
}

func authorizationFromPackage(evidencePackage protocol.EvidencePackage) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version: evidencePackage.Version, TenantID: evidencePackage.TenantID,
		KnowledgeBaseID: evidencePackage.KnowledgeBaseID, PrincipalID: evidencePackage.PrincipalID,
		SessionID: evidencePackage.SessionID, RequestID: evidencePackage.RequestID,
		AgentID: evidencePackage.AgentID, TaskID: evidencePackage.TaskID,
		AuthorizationModelID: evidencePackage.AuthorizationModelID,
		IdentityWatermark:    evidencePackage.IdentityWatermark, ACLWatermark: evidencePackage.ACLWatermark,
		Consistency: evidencePackage.Consistency,
	}
}

func validateCurrentCitationContext(current, original protocol.AuthorizationContext) error {
	bindings := []struct {
		name, current, original string
	}{
		{"tenant_id", current.TenantID, original.TenantID},
		{"knowledge_base_id", current.KnowledgeBaseID, original.KnowledgeBaseID},
		{"principal_id", current.PrincipalID, original.PrincipalID},
		{"session_id", current.SessionID, original.SessionID},
		{"agent_id", current.AgentID, original.AgentID},
		{"task_id", current.TaskID, original.TaskID},
	}
	for _, binding := range bindings {
		if binding.current != binding.original {
			return fmt.Errorf("open citation current %s does not match evidence package", binding.name)
		}
	}
	return nil
}

func canonicalConsistency(value protocol.ConsistencyPreference) (authz.Consistency, error) {
	switch value {
	case protocol.ConsistencyMinimizeLatency:
		return authz.ConsistencyMinimizeLatency, nil
	case protocol.ConsistencyHigherConsistency:
		return authz.ConsistencyHigherConsistency, nil
	default:
		return "", fmt.Errorf("unsupported consistency preference %q", value)
	}
}

func deterministicCorrelationID(stage string, index int, object string) string {
	sum := sha256.Sum256([]byte(stage + "\x00" + object))
	return fmt.Sprintf("%s-%03d-%x", stage, index, sum[:8])
}

func validateLimit(name string, value int, allowZero bool) error {
	if allowZero && value == 0 {
		return nil
	}
	if value < 1 || value > maxPrimitiveLimit {
		return fmt.Errorf("%s must be between 1 and %d", name, maxPrimitiveLimit)
	}
	return nil
}

func validateTextToken(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s contains leading or trailing whitespace", name)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains control characters", name)
	}
	return nil
}
