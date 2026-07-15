package authorized

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

var (
	errTraversalBudgetExceeded  = errors.New("authorized traversal budget exceeded")
	errInvalidTraversalResponse = errors.New("authorized traversal response is invalid")
	errTraversalUnsupported     = errors.New("authorized traversal provider capability is unsupported")
	errTraversalUnavailable     = errors.New("authorized traversal provider is unavailable")
)

// TraversalConfig is trusted service configuration. It is deliberately not
// part of QueryRequest or any user/tool-facing input contract.
type TraversalConfig struct {
	Enabled          bool
	PredicateSources []protocol.ClaimPredicateSourceKey
	ResourceKinds    []protocol.GraphResourceKind
	Direction        protocol.TraversalDirection
	Fields           []protocol.GraphField
	Filters          []protocol.GraphFilter
	Order            []protocol.GraphOrder
	Limits           protocol.TraversalLimits
}

// TraversalPhase is a fixed, content-free authorization stage name suitable
// for operational metrics.
type TraversalPhase string

const (
	TraversalPhaseDiscovery TraversalPhase = "discovery"
	TraversalPhaseStart     TraversalPhase = "start"
	TraversalPhaseClaim     TraversalPhase = "claim"
	TraversalPhaseObject    TraversalPhase = "object"
)

// TraversalHopDrop reports aggregate authorization outcomes without resource
// identifiers, predicates, labels, or content.
type TraversalHopDrop struct {
	Hop            int            `json:"hop"`
	Phase          TraversalPhase `json:"phase"`
	CandidateCount int            `json:"candidate_count"`
	AllowedCount   int            `json:"allowed_count"`
	DroppedCount   int            `json:"dropped_count"`
}

// TraversalReport contains only bounded operational counters and durations.
// It is returned for the current query and is never persisted in QueryCache.
type TraversalReport struct {
	AuthorizedPathCompleteness float64            `json:"authorized_path_completeness"`
	SelectedPathCount          int                `json:"selected_path_count"`
	CompletePathCount          int                `json:"complete_path_count"`
	FinalFilterCandidateCount  int                `json:"final_filter_candidate_count"`
	FinalFilterAllowedCount    int                `json:"final_filter_allowed_count"`
	FinalFilterDroppedCount    int                `json:"final_filter_dropped_count"`
	HopDrops                   []TraversalHopDrop `json:"hop_drops"`
	BatchCheckRPCCount         int                `json:"batch_check_rpc_count"`
	BatchCheckLatency          time.Duration      `json:"batch_check_latency"`
	QueryLatency               time.Duration      `json:"query_latency"`
}

type traversalConfig struct {
	enabled          bool
	predicateSources []protocol.ClaimPredicateSourceKey
	resourceKinds    []protocol.GraphResourceKind
	direction        protocol.TraversalDirection
	fields           []protocol.GraphField
	filters          []protocol.GraphFilter
	order            []protocol.GraphOrder
	limits           protocol.TraversalLimits
}

// traversalPlanDigest is comparable so the later cache slice can add the
// trusted canonical plan template directly to query cache keys.
type traversalPlanDigest [sha256.Size]byte

func (s *Service) configuredTraversalPlanDigest() traversalPlanDigest {
	return s.traversalDigest
}

func normalizeTraversalConfig(config TraversalConfig) (traversalConfig, traversalPlanDigest, error) {
	if !config.Enabled {
		return traversalConfig{}, traversalPlanDigest{}, nil
	}
	if config.Direction != protocol.TraversalOutbound {
		return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal supports outbound direction only")
	}
	if config.Limits.MaxFrontierWidth > maxPrimitiveLimit {
		return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal max frontier width exceeds provider capability")
	}
	if config.Limits.MaxCandidatesPerHop > maxPrimitiveLimit {
		return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal max candidates per hop exceeds provider capability")
	}
	for _, kind := range config.ResourceKinds {
		if kind != protocol.GraphResourceEntity && kind != protocol.GraphResourceClaim {
			return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal resource kind exceeds provider capability")
		}
	}
	if !containsTraversalKind(config.ResourceKinds, protocol.GraphResourceEntity) {
		return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal requires the provider entity capability")
	}

	order := append([]protocol.GraphOrder(nil), config.Order...)
	if len(order) == 0 {
		order = []protocol.GraphOrder{{
			Key: protocol.GraphSortClaimID, Direction: protocol.GraphSortAscending, Priority: 0,
		}}
	}
	for _, item := range order {
		if item.Key == protocol.GraphSortPredicateKey {
			return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal cannot rank by predicate key")
		}
	}

	dummyQuery := protocol.GraphQuery{
		Version:           protocol.GraphQueryContractVersion,
		Operation:         protocol.GraphOperationTraverseClaims,
		ProjectionVersion: "prj_00000000000000000000000000000000",
		IdentityVersion:   protocol.GraphBindingContractVersion,
		StartResourceIDs:  []protocol.ResourceID{"res_00000000000000000000000000000000"},
		PredicateSources:  append([]protocol.ClaimPredicateSourceKey(nil), config.PredicateSources...),
		ResourceKinds:     append([]protocol.GraphResourceKind(nil), config.ResourceKinds...),
		Direction:         config.Direction,
		Fields:            append([]protocol.GraphField(nil), config.Fields...),
		Filters:           cloneGraphFilters(config.Filters),
		Order:             order,
		Limits:            config.Limits,
	}
	descriptor, err := protocol.CompileGraphQuery(dummyQuery)
	if err != nil {
		return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal configuration is invalid: %w", err)
	}

	normalized := traversalConfig{
		enabled:          true,
		predicateSources: sortedUnique(config.PredicateSources),
		resourceKinds:    append([]protocol.GraphResourceKind(nil), descriptor.Parameters.ResourceKinds...),
		direction:        descriptor.Parameters.Direction,
		fields:           append([]protocol.GraphField(nil), descriptor.Parameters.Fields...),
		filters:          cloneGraphFilters(descriptor.Parameters.Filters),
		order:            append([]protocol.GraphOrder(nil), descriptor.Parameters.Order...),
		limits:           descriptor.Parameters.Limits,
	}
	digest, err := digestTraversalPlanTemplate(descriptor.Parameters)
	if err != nil {
		return traversalConfig{}, traversalPlanDigest{}, fmt.Errorf("authorized traversal configuration digest: %w", err)
	}
	return normalized, digest, nil
}

func cloneGraphFilters(filters []protocol.GraphFilter) []protocol.GraphFilter {
	cloned := make([]protocol.GraphFilter, len(filters))
	for index, filter := range filters {
		cloned[index] = filter
		cloned[index].ResourceIDs = append([]protocol.ResourceID(nil), filter.ResourceIDs...)
		cloned[index].Derivations = append([]protocol.DerivationMode(nil), filter.Derivations...)
	}
	return cloned
}

func sortedUnique[T ~string](values []T) []T {
	if len(values) == 0 {
		return nil
	}
	result := append([]T(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write]
}

func containsTraversalKind(kinds []protocol.GraphResourceKind, target protocol.GraphResourceKind) bool {
	for _, kind := range kinds {
		if kind == target {
			return true
		}
	}
	return false
}

func digestTraversalPlanTemplate(plan protocol.TraversalPlan) (traversalPlanDigest, error) {
	template := struct {
		Version                      int
		PredicateAllowlistVersion    int
		ResourceKindAllowlistVersion int
		IdentityVersion              int
		PredicateKeys                []protocol.ClaimPredicateKey
		ResourceKinds                []protocol.GraphResourceKind
		Direction                    protocol.TraversalDirection
		Fields                       []protocol.GraphField
		Filters                      []protocol.GraphFilter
		Order                        []protocol.GraphOrder
		Limits                       protocol.TraversalLimits
	}{
		Version: plan.Version, PredicateAllowlistVersion: plan.PredicateAllowlistVersion,
		ResourceKindAllowlistVersion: plan.ResourceKindAllowlistVersion,
		IdentityVersion:              plan.IdentityVersion,
		PredicateKeys:                plan.PredicateKeys,
		ResourceKinds:                plan.ResourceKinds,
		Direction:                    plan.Direction,
		Fields:                       plan.Fields,
		Filters:                      plan.Filters,
		Order:                        plan.Order,
		Limits:                       plan.Limits,
	}
	encoded, err := json.Marshal(template)
	if err != nil {
		return traversalPlanDigest{}, err
	}
	return traversalPlanDigest(sha256.Sum256(encoded)), nil
}

func digestTraversalDescriptor(descriptor protocol.GraphOperationDescriptor) (traversalPlanDigest, error) {
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return traversalPlanDigest{}, err
	}
	return traversalPlanDigest(sha256.Sum256(encoded)), nil
}

type traversalBudget struct {
	parent            context.Context
	context           context.Context
	limits            protocol.TraversalLimits
	now               func() time.Time
	startedAt         time.Time
	batchChecks       int
	batchCheckLatency time.Duration
	selectedPaths     int
	completePaths     int
	finalCandidates   int
	finalAllowed      int
	hopDrops          []TraversalHopDrop
	resources         map[protocol.ResourceID]protocol.ResourceHandle
}

func newTraversalBudget(
	parent context.Context,
	limits protocol.TraversalLimits,
	now func() time.Time,
) (*traversalBudget, context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(limits.MaxWallClockMillis)*time.Millisecond)
	budget := &traversalBudget{
		parent: parent, context: ctx, limits: limits, now: now, startedAt: now().UTC(),
		resources: make(map[protocol.ResourceID]protocol.ResourceHandle, limits.MaxTotalResources),
	}
	return budget, ctx, cancel
}

func (b *traversalBudget) recordBatchCheckLatency(startedAt time.Time) {
	elapsed := b.now().UTC().Sub(startedAt)
	if elapsed > 0 {
		b.batchCheckLatency += elapsed
	}
}

func (b *traversalBudget) recordHop(
	hop int,
	phase TraversalPhase,
	resources []protocol.ResourceHandle,
	checks map[string]objectCheck,
) {
	allowed := 0
	for _, resource := range resources {
		if checks[resource.AuthorizationID].allowed {
			allowed++
		}
	}
	b.hopDrops = append(b.hopDrops, TraversalHopDrop{
		Hop: hop, Phase: phase, CandidateCount: len(resources),
		AllowedCount: allowed, DroppedCount: len(resources) - allowed,
	})
}

func (b *traversalBudget) setSelectedPaths(count int) {
	b.selectedPaths = count
}

func (b *traversalBudget) setCompletePaths(count int) {
	b.completePaths = count
}

func (b *traversalBudget) setFinalFilter(candidateCount, allowedCount int) {
	b.finalCandidates = candidateCount
	b.finalAllowed = allowedCount
}

func (b *traversalBudget) report() TraversalReport {
	latency := b.now().UTC().Sub(b.startedAt)
	if latency < 0 {
		latency = 0
	}
	completeness := 0.0
	if b.selectedPaths > 0 {
		completeness = float64(b.completePaths) / float64(b.selectedPaths)
	}
	return TraversalReport{
		AuthorizedPathCompleteness: completeness,
		SelectedPathCount:          b.selectedPaths,
		CompletePathCount:          b.completePaths,
		FinalFilterCandidateCount:  b.finalCandidates,
		FinalFilterAllowedCount:    b.finalAllowed,
		FinalFilterDroppedCount:    b.finalCandidates - b.finalAllowed,
		HopDrops:                   append([]TraversalHopDrop(nil), b.hopDrops...),
		BatchCheckRPCCount:         b.batchChecks,
		BatchCheckLatency:          b.batchCheckLatency,
		QueryLatency:               latency,
	}
}

func traversalTelemetryRecord(report TraversalReport, result QueryResult, queryErr error) telemetry.Record {
	var hopCandidates, hopAllowed, hopDropped int
	for _, drop := range report.HopDrops {
		hopCandidates += drop.CandidateCount
		hopAllowed += drop.AllowedCount
		hopDropped += drop.DroppedCount
	}
	outcome := telemetry.OutcomeAllowed
	switch {
	case queryErr == nil:
	case errors.Is(queryErr, errNoEvidence):
		outcome = telemetry.OutcomeNotFound
		if traversalReportShowsAuthorizationDenial(report) {
			outcome = telemetry.OutcomeDenied
		}
	case errors.Is(queryErr, errTraversalBudgetExceeded), errors.Is(queryErr, context.DeadlineExceeded):
		outcome = telemetry.OutcomeBudgetExceeded
	case errors.Is(queryErr, errTraversalUnsupported), errors.Is(queryErr, errTraversalUnavailable):
		outcome = telemetry.OutcomeProviderUnavailable
	default:
		outcome = telemetry.OutcomeFailed
	}
	budgetResult := telemetry.BudgetPass
	if report.QueryLatency > time.Second {
		budgetResult = telemetry.BudgetFail
	}
	return telemetry.Record{
		ContractVersion: telemetry.ContractVersion1,
		MetricScope:     telemetry.MetricScopeOperational,
		Event:           telemetry.EventPermissionedQuery,
		Stage:           telemetry.StageTraversal,
		Outcome:         outcome,
		Budget: telemetry.Budget{
			Name: telemetry.BudgetLocalHardLatency, Result: budgetResult,
		},
		Counts: telemetry.Counts{
			Samples: 1, Candidates: uint64(hopCandidates), Allowed: uint64(hopAllowed), Dropped: uint64(hopDropped),
			EvidenceItems: uint64(len(result.Evidence.Items)), SelectedPaths: uint64(report.SelectedPathCount),
			CompletePaths: uint64(report.CompletePathCount), BatchCheckRPCs: uint64(report.BatchCheckRPCCount),
			FinalFilterCandidates: uint64(report.FinalFilterCandidateCount),
			FinalFilterAllowed:    uint64(report.FinalFilterAllowedCount),
			FinalFilterDropped:    uint64(report.FinalFilterDroppedCount),
		},
		Rates: telemetry.Rates{
			AuthorizedPathCompleteness: report.AuthorizedPathCompleteness,
			HopAuthorizationDrop:       telemetryRate(hopDropped, hopCandidates),
			PostFilterDrop:             telemetryRate(report.FinalFilterDroppedCount, report.FinalFilterCandidateCount),
		},
		Durations: telemetry.Durations{
			Latency:           uint64(report.QueryLatency / time.Millisecond),
			BatchCheckLatency: uint64(report.BatchCheckLatency / time.Millisecond),
		},
	}
}

func traversalReportShowsAuthorizationDenial(report TraversalReport) bool {
	if report.FinalFilterCandidateCount > 0 && report.FinalFilterAllowedCount == 0 {
		return true
	}
	for _, drop := range report.HopDrops {
		if drop.CandidateCount > 0 && drop.AllowedCount == 0 {
			return true
		}
	}
	return false
}

func telemetryRate(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func (b *traversalBudget) check() error {
	if err := b.parent.Err(); err != nil {
		return err
	}
	if err := b.context.Err(); err != nil {
		return errTraversalBudgetExceeded
	}
	return nil
}

func (b *traversalBudget) reserveBatchCheck() error {
	if err := b.check(); err != nil {
		return err
	}
	if b.batchChecks >= b.limits.MaxBatchChecks {
		return errTraversalBudgetExceeded
	}
	b.batchChecks++
	return nil
}

func (b *traversalBudget) addResources(resources []protocol.ResourceHandle) error {
	if err := b.check(); err != nil {
		return err
	}
	for _, resource := range resources {
		if existing, ok := b.resources[resource.ResourceID]; ok {
			if existing != resource {
				return errInvalidTraversalResponse
			}
			continue
		}
		if len(b.resources) >= b.limits.MaxTotalResources {
			return errTraversalBudgetExceeded
		}
		b.resources[resource.ResourceID] = resource
	}
	return b.check()
}

func traversalExternalCallError(budget *traversalBudget, callErr error) error {
	if err := budget.check(); err != nil {
		return err
	}
	if errors.Is(callErr, kag.ErrUnsupportedPrimitive) {
		return errTraversalUnsupported
	}
	return errTraversalUnavailable
}

type traversalClaimBinding struct {
	ParentResourceID protocol.ResourceID
	ClaimResourceID  protocol.ResourceID
	ObjectResourceID protocol.ResourceID
	PredicateKey     protocol.ClaimPredicateKey
}

type traversalPath struct {
	candidate kag.CandidateHandle
	resources []protocol.ResourceHandle
	claims    []traversalClaimBinding
	score     float64
}

func newTraversalPath(candidate kag.CandidateHandle) traversalPath {
	return traversalPath{
		candidate: candidate,
		resources: []protocol.ResourceHandle{candidate.Resource},
		score:     candidate.Score,
	}
}

func (path traversalPath) withClaim(candidate kag.CandidateHandle, edge kag.ExpansionHandle) traversalPath {
	result := cloneTraversalPath(path)
	result.resources = append(result.resources, candidate.Resource)
	result.score *= candidate.Score
	result.candidate = kag.CandidateHandle{Resource: candidate.Resource, Score: result.score}
	result.claims = append(result.claims, traversalClaimBinding{
		ParentResourceID: edge.FromResourceID,
		ClaimResourceID:  edge.ClaimResourceID,
		PredicateKey:     edge.PredicateKey,
	})
	return result
}

func (path traversalPath) withObject(candidate kag.CandidateHandle, edge kag.ExpansionHandle) traversalPath {
	result := cloneTraversalPath(path)
	result.resources = append(result.resources, candidate.Resource)
	result.score *= candidate.Score
	result.candidate = kag.CandidateHandle{Resource: candidate.Resource, Score: result.score}
	result.claims[len(result.claims)-1].ObjectResourceID = edge.ToResourceID
	return result
}

func cloneTraversalPath(path traversalPath) traversalPath {
	path.resources = append([]protocol.ResourceHandle(nil), path.resources...)
	path.claims = append([]traversalClaimBinding(nil), path.claims...)
	return path
}

func (path traversalPath) contains(resourceID protocol.ResourceID) bool {
	for _, resource := range path.resources {
		if resource.ResourceID == resourceID {
			return true
		}
	}
	return false
}

func (path traversalPath) key() string {
	parts := make([]string, len(path.resources))
	for index, resource := range path.resources {
		parts[index] = string(resource.ResourceID)
	}
	return strings.Join(parts, "\x00")
}

type traversalResult struct {
	operation  protocol.GraphOperationDescriptor
	planDigest traversalPlanDigest
	terminals  []traversalPath
}

type traversalTerminalGroup struct {
	candidate kag.CandidateHandle
	paths     []traversalPath
}

func (result traversalResult) terminalGroups() []traversalTerminalGroup {
	indices := make(map[protocol.ResourceID]int, len(result.terminals))
	groups := make([]traversalTerminalGroup, 0, len(result.terminals))
	for _, path := range result.terminals {
		resourceID := path.candidate.Resource.ResourceID
		index, ok := indices[resourceID]
		if !ok {
			index = len(groups)
			indices[resourceID] = index
			groups = append(groups, traversalTerminalGroup{candidate: path.candidate})
		}
		groups[index].paths = append(groups[index].paths, cloneTraversalPath(path))
	}
	for index := range groups {
		sortTraversalPaths(groups[index].paths)
		groups[index].candidate = groups[index].paths[0].candidate
	}
	sort.Slice(groups, func(i, j int) bool {
		return traversalPathLess(groups[i].paths[0], groups[j].paths[0])
	})
	return groups
}

func (result traversalResult) resourceIDs() []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{})
	var resourceIDs []protocol.ResourceID
	for _, path := range result.terminals {
		for _, resource := range path.resources {
			if _, ok := seen[resource.ResourceID]; ok {
				continue
			}
			seen[resource.ResourceID] = struct{}{}
			resourceIDs = append(resourceIDs, resource.ResourceID)
		}
	}
	sort.Slice(resourceIDs, func(i, j int) bool { return resourceIDs[i] < resourceIDs[j] })
	return resourceIDs
}

func digestTraversalPaths(paths []traversalPath) (traversalPlanDigest, error) {
	if len(paths) == 0 {
		return traversalPlanDigest{}, errInvalidTraversalResponse
	}
	type cachePath struct {
		Resources []protocol.ResourceHandle `json:"resources"`
		Claims    []traversalClaimBinding   `json:"claims"`
		Score     float64                   `json:"score"`
	}
	canonical := make([]cachePath, len(paths))
	for index, path := range paths {
		if len(path.resources) == 0 {
			return traversalPlanDigest{}, errInvalidTraversalResponse
		}
		canonical[index] = cachePath{
			Resources: append([]protocol.ResourceHandle(nil), path.resources...),
			Claims:    append([]traversalClaimBinding(nil), path.claims...),
			Score:     path.score,
		}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return traversalPlanDigest{}, err
	}
	return traversalPlanDigest(sha256.Sum256(encoded)), nil
}

func traversalGroupCandidates(groups []traversalTerminalGroup) []kag.CandidateHandle {
	candidates := make([]kag.CandidateHandle, len(groups))
	for index, group := range groups {
		candidates[index] = group.candidate
	}
	return candidates
}

func generateTraversalPaths(paths []traversalPath) ([]kag.GeneratePath, error) {
	if len(paths) == 0 {
		return nil, errInvalidTraversalResponse
	}
	result := make([]kag.GeneratePath, len(paths))
	for index, path := range paths {
		generated := kag.GeneratePath{
			Resources:     append([]protocol.ResourceHandle(nil), path.resources...),
			ClaimBindings: make([]kag.GeneratePathClaimBinding, len(path.claims)),
		}
		for claimIndex, claim := range path.claims {
			generated.ClaimBindings[claimIndex] = kag.GeneratePathClaimBinding{
				ParentResourceID: claim.ParentResourceID,
				ClaimResourceID:  claim.ClaimResourceID,
				ObjectResourceID: claim.ObjectResourceID,
				PredicateKey:     claim.PredicateKey,
			}
		}
		if err := generated.Validate(); err != nil {
			return nil, errInvalidTraversalResponse
		}
		result[index] = generated
	}
	return result, nil
}

func (s *Service) executeTraversal(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	retrieved []kag.CandidateHandle,
	budget *traversalBudget,
) (traversalResult, error) {
	if err := budget.addResources(candidateResources(retrieved)); err != nil {
		return traversalResult{}, err
	}
	startChecks, err := s.checkTraversalResources(ctx, authorization, "tr-start", candidateResources(retrieved), budget)
	if err != nil {
		return traversalResult{}, err
	}
	budget.recordHop(0, TraversalPhaseStart, candidateResources(retrieved), startChecks)
	approved := make([]kag.CandidateHandle, 0, len(retrieved))
	for _, candidate := range retrieved {
		if !startChecks[candidate.Resource.AuthorizationID].allowed {
			continue
		}
		if candidate.Resource.Type != protocol.ResourceEntity {
			return traversalResult{}, errInvalidTraversalResponse
		}
		approved = append(approved, candidate)
	}
	if len(approved) == 0 {
		return traversalResult{}, errNoEvidence
	}
	if len(approved) > protocol.MaxGraphStartResources || len(approved) > s.traversal.limits.MaxFrontierWidth {
		return traversalResult{}, errTraversalBudgetExceeded
	}
	projection := approved[0].Resource.Versions.Projection
	startResourceIDs := make([]protocol.ResourceID, len(approved))
	for index, candidate := range approved {
		if candidate.Resource.Versions.Projection != projection {
			return traversalResult{}, errInvalidTraversalResponse
		}
		startResourceIDs[index] = candidate.Resource.ResourceID
	}
	operation, err := protocol.CompileGraphQuery(protocol.GraphQuery{
		Version:           protocol.GraphQueryContractVersion,
		Operation:         protocol.GraphOperationTraverseClaims,
		ProjectionVersion: projection,
		IdentityVersion:   protocol.GraphBindingContractVersion,
		StartResourceIDs:  startResourceIDs,
		PredicateSources:  append([]protocol.ClaimPredicateSourceKey(nil), s.traversal.predicateSources...),
		ResourceKinds:     append([]protocol.GraphResourceKind(nil), s.traversal.resourceKinds...),
		Direction:         s.traversal.direction,
		Fields:            append([]protocol.GraphField(nil), s.traversal.fields...),
		Filters:           cloneGraphFilters(s.traversal.filters),
		Order:             append([]protocol.GraphOrder(nil), s.traversal.order...),
		Limits:            s.traversal.limits,
	})
	if err != nil {
		return traversalResult{}, fmt.Errorf("authorized traversal plan: %w", err)
	}
	planDigest, err := digestTraversalDescriptor(operation)
	if err != nil {
		return traversalResult{}, errInvalidTraversalResponse
	}

	frontier := make([]traversalPath, len(approved))
	visitedObjects := make(map[protocol.ResourceID]struct{}, len(approved))
	for index, candidate := range approved {
		frontier[index] = newTraversalPath(candidate)
		visitedObjects[candidate.Resource.ResourceID] = struct{}{}
	}
	if s.traversal.limits.MaxDepth == 0 {
		terminals := canonicalTerminalPaths(frontier)
		return traversalResult{operation: operation, planDigest: planDigest, terminals: terminals}, nil
	}

	terminals := make([]traversalPath, 0)
	for depth := 0; depth < s.traversal.limits.MaxDepth && len(frontier) > 0; depth++ {
		if err := budget.check(); err != nil {
			return traversalResult{}, err
		}
		if len(frontier) > s.traversal.limits.MaxFrontierWidth {
			return traversalResult{}, errTraversalBudgetExceeded
		}

		claimFrontier, err := pathCandidates(frontier)
		if err != nil {
			return traversalResult{}, err
		}
		claimRequest := kag.ExpandRequest{
			Authorization: authorization,
			Operation:     operation,
			Phase:         kag.ExpandPhaseEntityToClaim,
			Frontier:      claimFrontier,
			// Scan body-free handles at the fixed provider bound. The trusted
			// candidate limit is applied only after authorization below.
			Limit: maxPrimitiveLimit,
		}
		claimResult, err := s.callTraversalExpand(ctx, claimRequest, budget)
		if err != nil {
			return traversalResult{}, err
		}
		claimChecks, err := s.checkTraversalResources(
			ctx, authorization, "tr-claim", candidateResources(claimResult.Candidates), budget,
		)
		if err != nil {
			return traversalResult{}, err
		}
		budget.recordHop(depth+1, TraversalPhaseClaim, candidateResources(claimResult.Candidates), claimChecks)
		claimResult = filterTraversalExpandResult(claimResult, claimChecks)
		if len(claimResult.Candidates) > s.traversal.limits.MaxCandidatesPerHop {
			return traversalResult{}, errTraversalBudgetExceeded
		}
		if err := claimResult.ValidateFor(claimRequest); err != nil {
			return traversalResult{}, errInvalidTraversalResponse
		}
		claimPaths, parents, err := bindClaimPaths(frontier, claimResult)
		if err != nil {
			return traversalResult{}, err
		}
		if len(claimPaths) == 0 {
			terminals = append(terminals, frontier...)
			frontier = nil
			break
		}
		if len(claimPaths) > s.traversal.limits.MaxFrontierWidth {
			return traversalResult{}, errTraversalBudgetExceeded
		}
		claimFrontier, err = pathCandidates(claimPaths)
		if err != nil {
			return traversalResult{}, err
		}
		objectRequest := kag.ExpandRequest{
			Authorization: authorization,
			Operation:     operation,
			Phase:         kag.ExpandPhaseClaimToObject,
			Frontier:      claimFrontier,
			Limit:         maxPrimitiveLimit,
		}
		objectResult, err := s.callTraversalExpand(ctx, objectRequest, budget)
		if err != nil {
			return traversalResult{}, err
		}
		objectChecks, err := s.checkTraversalResources(
			ctx, authorization, "tr-object", candidateResources(objectResult.Candidates), budget,
		)
		if err != nil {
			return traversalResult{}, err
		}
		budget.recordHop(depth+1, TraversalPhaseObject, candidateResources(objectResult.Candidates), objectChecks)
		objectResult = filterTraversalExpandResult(objectResult, objectChecks)
		if len(objectResult.Candidates) > s.traversal.limits.MaxCandidatesPerHop {
			return traversalResult{}, errTraversalBudgetExceeded
		}
		if err := objectResult.ValidateFor(objectRequest); err != nil {
			return traversalResult{}, errInvalidTraversalResponse
		}
		next, advancedPaths, err := bindObjectPaths(claimPaths, parents, objectResult, visitedObjects)
		if err != nil {
			return traversalResult{}, err
		}
		for _, parent := range frontier {
			if _, advanced := advancedPaths[parent.key()]; !advanced {
				terminals = append(terminals, parent)
			}
		}
		if len(next) > s.traversal.limits.MaxFrontierWidth {
			return traversalResult{}, errTraversalBudgetExceeded
		}
		for _, path := range next {
			visitedObjects[path.candidate.Resource.ResourceID] = struct{}{}
		}
		frontier = next
	}
	terminals = append(terminals, frontier...)
	terminals = canonicalTerminalPaths(terminals)
	if len(terminals) == 0 {
		return traversalResult{}, errNoEvidence
	}
	return traversalResult{operation: operation, planDigest: planDigest, terminals: terminals}, nil
}

func (s *Service) callTraversalExpand(
	ctx context.Context,
	request kag.ExpandRequest,
	budget *traversalBudget,
) (kag.ExpandResult, error) {
	if len(request.Frontier) > budget.limits.MaxFrontierWidth {
		return kag.ExpandResult{}, errTraversalBudgetExceeded
	}
	if err := budget.check(); err != nil {
		return kag.ExpandResult{}, err
	}
	result, err := s.kag.Expand(ctx, request)
	if err != nil {
		return kag.ExpandResult{}, traversalExternalCallError(budget, err)
	}
	if err := budget.check(); err != nil {
		return kag.ExpandResult{}, err
	}
	if len(result.Candidates) > request.Limit {
		return kag.ExpandResult{}, errTraversalBudgetExceeded
	}
	if err := validateTraversalCandidateSet(result.Candidates, request); err != nil {
		return kag.ExpandResult{}, errInvalidTraversalResponse
	}
	if err := budget.addResources(candidateResources(result.Candidates)); err != nil {
		return kag.ExpandResult{}, err
	}
	return result, nil
}

func validateTraversalCandidateSet(candidates []kag.CandidateHandle, request kag.ExpandRequest) error {
	for _, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			return err
		}
		if err := candidate.Resource.ValidateFor(request.Authorization); err != nil {
			return err
		}
	}
	return nil
}

func filterTraversalExpandResult(
	result kag.ExpandResult,
	checks map[string]objectCheck,
) kag.ExpandResult {
	allowed := make(map[protocol.ResourceID]struct{}, len(result.Candidates))
	filtered := kag.ExpandResult{Mode: result.Mode}
	for _, candidate := range result.Candidates {
		if !checks[candidate.Resource.AuthorizationID].allowed {
			continue
		}
		allowed[candidate.Resource.ResourceID] = struct{}{}
		filtered.Candidates = append(filtered.Candidates, candidate)
	}
	for _, expansion := range result.Expansions {
		if _, ok := allowed[expansion.ToResourceID]; ok {
			filtered.Expansions = append(filtered.Expansions, expansion)
		}
	}
	return filtered
}

func bindClaimPaths(
	frontier []traversalPath,
	result kag.ExpandResult,
) ([]traversalPath, map[protocol.ResourceID]protocol.ResourceID, error) {
	byParent := make(map[protocol.ResourceID][]traversalPath, len(frontier))
	for _, path := range frontier {
		resourceID := path.candidate.Resource.ResourceID
		if previous := byParent[resourceID]; len(previous) > 0 && previous[0].candidate.Resource != path.candidate.Resource {
			return nil, nil, errInvalidTraversalResponse
		}
		byParent[resourceID] = append(byParent[resourceID], path)
	}
	byClaim := make(map[protocol.ResourceID]kag.CandidateHandle, len(result.Candidates))
	for _, candidate := range result.Candidates {
		byClaim[candidate.Resource.ResourceID] = candidate
	}
	pathsByKey := make(map[string]traversalPath, len(result.Expansions))
	parents := make(map[protocol.ResourceID]protocol.ResourceID, len(result.Expansions))
	for _, edge := range result.Expansions {
		parentPaths, ok := byParent[edge.FromResourceID]
		claim, claimOK := byClaim[edge.ToResourceID]
		if !ok || !claimOK || edge.ClaimResourceID != claim.Resource.ResourceID {
			return nil, nil, errInvalidTraversalResponse
		}
		if previous, duplicate := parents[edge.ClaimResourceID]; duplicate && previous != edge.FromResourceID {
			return nil, nil, errInvalidTraversalResponse
		}
		parents[edge.ClaimResourceID] = edge.FromResourceID
		for _, parent := range parentPaths {
			if parent.contains(edge.ClaimResourceID) {
				return nil, nil, errInvalidTraversalResponse
			}
			path := parent.withClaim(claim, edge)
			if existing, duplicate := pathsByKey[path.key()]; !duplicate || traversalPathLess(path, existing) {
				pathsByKey[path.key()] = path
			}
		}
	}
	paths := make([]traversalPath, 0, len(pathsByKey))
	for _, path := range pathsByKey {
		paths = append(paths, path)
	}
	sortTraversalPaths(paths)
	return paths, parents, nil
}

func bindObjectPaths(
	claimPaths []traversalPath,
	parents map[protocol.ResourceID]protocol.ResourceID,
	result kag.ExpandResult,
	visited map[protocol.ResourceID]struct{},
) ([]traversalPath, map[string]struct{}, error) {
	byClaim := make(map[protocol.ResourceID][]traversalPath, len(claimPaths))
	for _, path := range claimPaths {
		resourceID := path.candidate.Resource.ResourceID
		if previous := byClaim[resourceID]; len(previous) > 0 && previous[0].candidate.Resource != path.candidate.Resource {
			return nil, nil, errInvalidTraversalResponse
		}
		byClaim[resourceID] = append(byClaim[resourceID], path)
	}
	byObject := make(map[protocol.ResourceID]kag.CandidateHandle, len(result.Candidates))
	for _, candidate := range result.Candidates {
		byObject[candidate.Resource.ResourceID] = candidate
	}
	pathsByKey := make(map[string]traversalPath)
	advancedPaths := make(map[string]struct{})
	for _, edge := range result.Expansions {
		paths, ok := byClaim[edge.FromResourceID]
		object, objectOK := byObject[edge.ToResourceID]
		parentID, parentOK := parents[edge.ClaimResourceID]
		if !ok || !objectOK || !parentOK || edge.ClaimResourceID != edge.FromResourceID {
			return nil, nil, errInvalidTraversalResponse
		}
		for _, claimPath := range paths {
			if len(claimPath.claims) == 0 || len(claimPath.resources) < 2 {
				return nil, nil, errInvalidTraversalResponse
			}
			binding := claimPath.claims[len(claimPath.claims)-1]
			if binding.ParentResourceID != parentID || binding.PredicateKey != edge.PredicateKey {
				return nil, nil, errInvalidTraversalResponse
			}
			if claimPath.contains(edge.ToResourceID) {
				continue
			}
			if _, seen := visited[edge.ToResourceID]; seen {
				continue
			}
			path := claimPath.withObject(object, edge)
			parentPathKey := traversalResourcePathKey(claimPath.resources[:len(claimPath.resources)-1])
			advancedPaths[parentPathKey] = struct{}{}
			if existing, duplicate := pathsByKey[path.key()]; !duplicate || traversalPathLess(path, existing) {
				pathsByKey[path.key()] = path
			}
		}
	}
	resultPaths := make([]traversalPath, 0, len(pathsByKey))
	for _, path := range pathsByKey {
		resultPaths = append(resultPaths, path)
	}
	sortTraversalPaths(resultPaths)
	return resultPaths, advancedPaths, nil
}

func canonicalTerminalPaths(paths []traversalPath) []traversalPath {
	best := make(map[string]traversalPath, len(paths))
	for _, path := range paths {
		if path.candidate.Resource.Type == protocol.ResourceClaim {
			continue
		}
		key := path.key()
		if existing, duplicate := best[key]; !duplicate || traversalPathLess(path, existing) {
			best[key] = path
		}
	}
	result := make([]traversalPath, 0, len(best))
	for _, path := range best {
		result = append(result, path)
	}
	sortTraversalPaths(result)
	return result
}

func sortTraversalPaths(paths []traversalPath) {
	sort.Slice(paths, func(i, j int) bool { return traversalPathLess(paths[i], paths[j]) })
}

func traversalPathLess(left, right traversalPath) bool {
	if left.score != right.score {
		return left.score > right.score
	}
	if left.candidate.Resource.ResourceID != right.candidate.Resource.ResourceID {
		return left.candidate.Resource.ResourceID < right.candidate.Resource.ResourceID
	}
	return left.key() < right.key()
}

func pathCandidates(paths []traversalPath) ([]kag.CandidateHandle, error) {
	byResource := make(map[protocol.ResourceID]kag.CandidateHandle, len(paths))
	for _, path := range paths {
		resourceID := path.candidate.Resource.ResourceID
		if existing, duplicate := byResource[resourceID]; duplicate {
			if existing.Resource != path.candidate.Resource {
				return nil, errInvalidTraversalResponse
			}
			if path.candidate.Score > existing.Score {
				byResource[resourceID] = path.candidate
			}
			continue
		}
		byResource[resourceID] = path.candidate
	}
	candidates := make([]kag.CandidateHandle, 0, len(byResource))
	for _, candidate := range byResource {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Resource.ResourceID < candidates[j].Resource.ResourceID
	})
	return candidates, nil
}

func traversalResourcePathKey(resources []protocol.ResourceHandle) string {
	parts := make([]string, len(resources))
	for index, resource := range resources {
		parts[index] = string(resource.ResourceID)
	}
	return strings.Join(parts, "\x00")
}

func candidateResources(candidates []kag.CandidateHandle) []protocol.ResourceHandle {
	resources := make([]protocol.ResourceHandle, len(candidates))
	for index, candidate := range candidates {
		resources[index] = candidate.Resource
	}
	return resources
}

func (s *Service) checkTraversalResources(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	resources []protocol.ResourceHandle,
	budget *traversalBudget,
) (map[string]objectCheck, error) {
	if len(resources) == 0 {
		return map[string]objectCheck{}, nil
	}
	consistency, err := canonicalConsistency(authorization.Consistency)
	if err != nil {
		return nil, errInvalidTraversalResponse
	}
	ordered := append([]protocol.ResourceHandle(nil), resources...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].ResourceID != ordered[j].ResourceID {
			return ordered[i].ResourceID < ordered[j].ResourceID
		}
		return ordered[i].AuthorizationID < ordered[j].AuthorizationID
	})
	objects := make([]string, 0, len(ordered))
	seen := make(map[string]struct{}, len(ordered))
	for _, resource := range ordered {
		if err := resource.ValidateFor(authorization); err != nil {
			return nil, errInvalidTraversalResponse
		}
		if _, duplicate := seen[resource.AuthorizationID]; duplicate {
			continue
		}
		seen[resource.AuthorizationID] = struct{}{}
		objects = append(objects, resource.AuthorizationID)
	}
	result := make(map[string]objectCheck, len(objects))
	for start := 0; start < len(objects); start += authz.MaxBatchChecks {
		end := start + authz.MaxBatchChecks
		if end > len(objects) {
			end = len(objects)
		}
		if err := budget.reserveBatchCheck(); err != nil {
			return nil, err
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
			return nil, errInvalidTraversalResponse
		}
		startedAt := budget.now().UTC()
		decisions, callErr := s.authorizer.BatchCheck(ctx, request)
		budget.recordBatchCheckLatency(startedAt)
		if err := budget.check(); err != nil {
			return nil, err
		}
		if callErr != nil {
			if errors.Is(callErr, authz.ErrInvalidRequest) || errors.Is(callErr, authz.ErrModelMismatch) {
				return nil, errInvalidTraversalResponse
			}
			continue
		}
		chunk, ok := validateTraversalDecisions(decisions, expected, authorization.AuthorizationModelID)
		if !ok {
			continue
		}
		for object, checked := range chunk {
			result[object] = checked
		}
	}
	return result, budget.check()
}

func validateTraversalDecisions(
	decisions []authz.Decision,
	expected map[string]string,
	modelID string,
) (map[string]objectCheck, bool) {
	if len(decisions) != len(expected) {
		return nil, false
	}
	result := make(map[string]objectCheck, len(decisions))
	seen := make(map[string]struct{}, len(decisions))
	for _, decision := range decisions {
		object, ok := expected[decision.CorrelationID]
		if !ok || decision.AuthorizationModelID != modelID {
			return nil, false
		}
		if _, duplicate := seen[decision.CorrelationID]; duplicate {
			return nil, false
		}
		seen[decision.CorrelationID] = struct{}{}
		result[object] = objectCheck{correlationID: decision.CorrelationID, allowed: decision.Allowed}
	}
	if len(seen) != len(expected) {
		return nil, false
	}
	return result, true
}

type traversalItemAuthorization struct {
	handles    []protocol.ResourceHandle
	boundaries map[protocol.ResourceID]protocol.ResourceHandle
}

func (s *Service) finalizeTraversalEvidence(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	items []protocol.EvidenceItem,
	groups []traversalTerminalGroup,
	limit int,
	budget *traversalBudget,
) ([]protocol.EvidenceItem, []traversalPath, checkedEvidence, error) {
	if len(items) == 0 || len(items) != len(groups) || limit < 1 || len(groups[0].paths) == 0 {
		return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
	}
	projection := groups[0].paths[0].candidate.Resource.Versions.Projection
	allHandles := make([]protocol.ResourceHandle, 0)
	seenHandles := make(map[protocol.ResourceID]protocol.ResourceHandle)
	appendExact := func(resource protocol.ResourceHandle) error {
		if resource.Versions.Projection != projection {
			return errInvalidTraversalResponse
		}
		if existing, duplicate := seenHandles[resource.ResourceID]; duplicate {
			if existing != resource {
				return errInvalidTraversalResponse
			}
			return nil
		}
		seenHandles[resource.ResourceID] = resource
		allHandles = append(allHandles, resource)
		return nil
	}
	for _, group := range groups {
		if len(group.paths) == 0 || group.candidate.Resource.ResourceID != group.paths[0].candidate.Resource.ResourceID {
			return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
		}
		for _, path := range group.paths {
			for _, resource := range path.resources {
				if err := appendExact(resource); err != nil {
					return nil, nil, checkedEvidence{}, err
				}
			}
		}
	}
	for _, item := range items {
		handles, _, itemProjection, err := collectEvidenceHandles(authorization, []protocol.EvidenceItem{item})
		if err != nil || itemProjection != projection {
			return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
		}
		for _, resource := range handles {
			if err := appendExact(resource); err != nil {
				return nil, nil, checkedEvidence{}, err
			}
		}
	}
	if err := budget.addResources(allHandles); err != nil {
		return nil, nil, checkedEvidence{}, err
	}
	checks, err := s.checkTraversalResources(ctx, authorization, "tr-final", allHandles, budget)
	if err != nil {
		return nil, nil, checkedEvidence{}, err
	}

	type survivingTraversalItem struct {
		item          protocol.EvidenceItem
		path          traversalPath
		authorization traversalItemAuthorization
	}
	survivors := make([]survivingTraversalItem, 0, len(groups))
	consideredPaths := 0
	for index, group := range groups {
		selectedItem, itemAllowed := selectAuthorizedEvidenceItem(items[index], checks)
		var selectedAuthorization traversalItemAuthorization
		if itemAllowed {
			handles, boundaries, itemProjection, err := collectEvidenceHandles(
				authorization, []protocol.EvidenceItem{selectedItem},
			)
			if err != nil || itemProjection != projection {
				return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
			}
			selectedAuthorization = traversalItemAuthorization{handles: handles, boundaries: boundaries}
		}
		for _, path := range group.paths {
			consideredPaths++
			if !itemAllowed || !traversalHandlesAllowed(path.resources, checks) {
				continue
			}
			survivors = append(survivors, survivingTraversalItem{
				item: selectedItem, path: cloneTraversalPath(path), authorization: selectedAuthorization,
			})
			break
		}
	}
	budget.setSelectedPaths(consideredPaths)
	budget.setFinalFilter(len(groups), len(survivors))
	if len(survivors) == 0 {
		return nil, nil, checkedEvidence{}, errNoEvidence
	}
	sort.Slice(survivors, func(i, j int) bool {
		return traversalPathLess(survivors[i].path, survivors[j].path)
	})
	if len(survivors) > limit {
		survivors = survivors[:limit]
	}
	survivingItems := make([]protocol.EvidenceItem, len(survivors))
	survivingPaths := make([]traversalPath, len(survivors))
	for index, survivor := range survivors {
		survivingItems[index] = survivor.item
		survivingPaths[index] = cloneTraversalPath(survivor.path)
	}

	ordered := make([]protocol.ResourceHandle, 0)
	boundaries := make(map[protocol.ResourceID]protocol.ResourceHandle)
	seenHandles = make(map[protocol.ResourceID]protocol.ResourceHandle)
	appendSurviving := func(resource protocol.ResourceHandle) error {
		if existing, duplicate := seenHandles[resource.ResourceID]; duplicate {
			if existing != resource {
				return errInvalidTraversalResponse
			}
			return nil
		}
		seenHandles[resource.ResourceID] = resource
		ordered = append(ordered, resource)
		return nil
	}
	for _, survivor := range survivors {
		path := survivor.path
		for _, resource := range path.resources {
			if err := appendSurviving(resource); err != nil {
				return nil, nil, checkedEvidence{}, err
			}
		}
		for _, resource := range survivor.authorization.handles {
			if err := appendSurviving(resource); err != nil {
				return nil, nil, checkedEvidence{}, err
			}
		}
		for resourceID, boundary := range survivor.authorization.boundaries {
			if existing, duplicate := boundaries[resourceID]; duplicate && existing != boundary {
				return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
			}
			boundaries[resourceID] = boundary
		}
	}
	for _, resource := range ordered {
		if _, ok := boundaries[resource.ResourceID]; ok {
			continue
		}
		boundary := resource
		if resource.Type == protocol.ResourceChunk {
			parent, ok := seenHandles[resource.AuthorizationResourceID]
			if !ok {
				return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
			}
			boundary = parent
		}
		if err := validateBoundary(resource, boundary); err != nil {
			return nil, nil, checkedEvidence{}, errInvalidTraversalResponse
		}
		boundaries[resource.ResourceID] = boundary
	}
	return survivingItems, survivingPaths, checkedEvidence{
		handles: ordered, boundaries: boundaries, projection: projection, objects: checks,
	}, nil
}

func traversalHandlesAllowed(handles []protocol.ResourceHandle, checks map[string]objectCheck) bool {
	for _, resource := range handles {
		if !checks[resource.AuthorizationID].allowed {
			return false
		}
	}
	return true
}
