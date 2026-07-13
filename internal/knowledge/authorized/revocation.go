package authorized

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	// ErrProtectedContentUnavailable is the generic fail-closed replay/cache error.
	ErrProtectedContentUnavailable = errors.New("protected content is unavailable")
	// ErrCitationUnavailable is the generic fail-closed citation error.
	ErrCitationUnavailable = errors.New("citation is unavailable")
	// ErrRevocationUnavailable is the generic revocation application error.
	ErrRevocationUnavailable = errors.New("revocation could not be applied")
)

// LiveAuthorizationDecision deliberately contains only opaque resource IDs and
// the current decision. It is safe to use for replay filtering and operations
// reporting because it cannot carry protected content.
type LiveAuthorizationDecision struct {
	ResourceID              protocol.ResourceID      `json:"resource_id"`
	AuthorizationResourceID protocol.ResourceID      `json:"authorization_resource_id"`
	Outcome                 protocol.DecisionOutcome `json:"outcome"`
}

// LiveAuthorizationReport summarizes one higher-consistency authorization pass.
type LiveAuthorizationReport struct {
	CheckedAt     time.Time                      `json:"checked_at"`
	Consistency   protocol.ConsistencyPreference `json:"consistency"`
	ResourceCount int                            `json:"resource_count"`
	AllowedCount  int                            `json:"allowed_count"`
	DeniedCount   int                            `json:"denied_count"`
	Decisions     []LiveAuthorizationDecision    `json:"decisions"`
}

func (r LiveAuthorizationReport) Allowed() bool {
	return r.ResourceCount > 0 && r.AllowedCount == r.ResourceCount && r.DeniedCount == 0
}

// RevocationRequest binds one durable revocation timestamp to protected metadata.
type RevocationRequest struct {
	Authorization protocol.AuthorizationContext
	Binding       protocol.ProtectedContentBinding
	ResourceIDs   []protocol.ResourceID
	RevokedAt     time.Time
}

// RevocationReport contains operational and authorization metadata only. It
// excludes authorization contexts, cache keys, queries, evidence, and answers.
type RevocationReport struct {
	RevokedAt                time.Time                   `json:"revoked_at"`
	ObservedAt               time.Time                   `json:"observed_at"`
	CheckedAt                time.Time                   `json:"checked_at"`
	PropagationLatency       time.Duration               `json:"propagation_latency"`
	ProtectedResourceCount   int                         `json:"protected_resource_count"`
	InvalidatedResourceCount int                         `json:"invalidated_resource_count"`
	RemovedEntryCount        int                         `json:"removed_entry_count"`
	AllowedCount             int                         `json:"allowed_count"`
	DeniedCount              int                         `json:"denied_count"`
	Decisions                []LiveAuthorizationDecision `json:"decisions"`
}

// RevocationCoordinator is the application entrypoint for a durable revocation
// event. It shares the Service authorizer and applies cache tombstones before
// reporting the current higher-consistency decisions.
type RevocationCoordinator struct {
	service *Service
	cache   *QueryCache
}

func NewRevocationCoordinator(service *Service) (*RevocationCoordinator, error) {
	if service == nil || service.authorizer == nil || service.now == nil {
		return nil, errors.New("revocation coordinator requires an authorized service")
	}
	if service.cache == nil || !service.cache.initialized() {
		return nil, errors.New("revocation coordinator requires an authorized query cache")
	}
	return &RevocationCoordinator{service: service, cache: service.cache}, nil
}

// AuthorizeProtectedContent is the shared replay-filtering entrypoint. A deny,
// malformed binding, stale exact handle, or authorizer failure is always
// returned as the same generic availability error.
func (s *Service) AuthorizeProtectedContent(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) (LiveAuthorizationReport, error) {
	if s == nil || s.loader == nil {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	if err := binding.ValidateFor(current); err != nil {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	resourceIDs := protectedBindingResourceIDs(binding)
	if s.cache != nil && s.cache.containsInvalidatedResource(resourceIDs) {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	report, err := s.liveAuthorizationReport(ctx, current, binding, "replay")
	if err != nil || !report.Allowed() {
		return report, ErrProtectedContentUnavailable
	}
	handles := make([]protocol.ResourceHandle, len(binding.Resources))
	for index, resource := range binding.Resources {
		handles[index] = resource.Resource
	}
	loaded, err := s.loadExact(ctx, current, handles)
	if err != nil {
		return report, ErrProtectedContentUnavailable
	}
	_, boundaries, _, err := collectEvidenceHandles(current, loaded)
	if err != nil {
		return report, ErrProtectedContentUnavailable
	}
	for _, resource := range binding.Resources {
		if boundaries[resource.Resource.ResourceID] != resource.AuthorizationResource {
			return report, ErrProtectedContentUnavailable
		}
	}
	report, err = s.liveAuthorizationReport(ctx, current, binding, "replay")
	if err != nil || !report.Allowed() {
		return report, ErrProtectedContentUnavailable
	}
	if s.cache != nil && s.cache.containsInvalidatedResource(resourceIDs) {
		return report, ErrProtectedContentUnavailable
	}
	return report, nil
}

func protectedBindingResourceIDs(binding protocol.ProtectedContentBinding) []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{}, len(binding.Resources)*2)
	for _, resource := range binding.Resources {
		seen[resource.Resource.ResourceID] = struct{}{}
		seen[resource.AuthorizationResource.ResourceID] = struct{}{}
	}
	result := make([]protocol.ResourceID, 0, len(seen))
	for resourceID := range seen {
		result = append(result, resourceID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func evidenceResourceIDs(
	handles []protocol.ResourceHandle,
	boundaries map[protocol.ResourceID]protocol.ResourceHandle,
) []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{}, len(handles)*2)
	for _, handle := range handles {
		seen[handle.ResourceID] = struct{}{}
		if boundary, ok := boundaries[handle.ResourceID]; ok {
			seen[boundary.ResourceID] = struct{}{}
		}
	}
	result := make([]protocol.ResourceID, 0, len(seen))
	for resourceID := range seen {
		result = append(result, resourceID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (c *RevocationCoordinator) AuthorizeProtectedContent(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) (LiveAuthorizationReport, error) {
	if c == nil || c.service == nil {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	return c.service.AuthorizeProtectedContent(ctx, current, binding)
}

// Apply tombstones the explicitly revoked exact resource or authorization
// boundary before making a live authorization decision. This ordering prevents
// an already-running query from repopulating or returning a revoked cache value
// even when its visibility watermarks have not changed.
func (c *RevocationCoordinator) Apply(ctx context.Context, request RevocationRequest) (RevocationReport, error) {
	if c == nil || c.service == nil || c.cache == nil || ctx == nil || request.RevokedAt.IsZero() {
		return RevocationReport{}, ErrRevocationUnavailable
	}
	if err := request.Binding.ValidateFor(request.Authorization); err != nil {
		return RevocationReport{}, ErrRevocationUnavailable
	}

	resourceIDs, err := validatedRevocationResourceIDs(request.Binding, request.ResourceIDs)
	if err != nil {
		return RevocationReport{}, ErrRevocationUnavailable
	}
	var observedAt time.Time
	var propagationLatency time.Duration
	removedEntries := 0
	for _, resourceID := range resourceIDs {
		result, err := c.cache.InvalidateResource(resourceID, request.RevokedAt)
		if err != nil {
			return RevocationReport{}, ErrRevocationUnavailable
		}
		if result.ObservedAt.After(observedAt) {
			observedAt = result.ObservedAt
		}
		if result.PropagationLatency > propagationLatency {
			propagationLatency = result.PropagationLatency
		}
		removedEntries += result.RemovedEntries
	}

	live, err := c.service.liveAuthorizationReport(ctx, request.Authorization, request.Binding, "revoke")
	if err != nil {
		return RevocationReport{}, ErrRevocationUnavailable
	}
	return RevocationReport{
		RevokedAt:                request.RevokedAt.UTC(),
		ObservedAt:               observedAt,
		CheckedAt:                live.CheckedAt,
		PropagationLatency:       propagationLatency,
		ProtectedResourceCount:   live.ResourceCount,
		InvalidatedResourceCount: len(resourceIDs),
		RemovedEntryCount:        removedEntries,
		AllowedCount:             live.AllowedCount,
		DeniedCount:              live.DeniedCount,
		Decisions:                append([]LiveAuthorizationDecision(nil), live.Decisions...),
	}, nil
}

func (s *Service) liveAuthorizationReport(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
	stage string,
) (LiveAuthorizationReport, error) {
	if s == nil || s.authorizer == nil || s.now == nil || ctx == nil {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	if err := binding.ValidateFor(current); err != nil {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	boundaries := make([]protocol.ResourceHandle, len(binding.Resources))
	for index, resource := range binding.Resources {
		boundaries[index] = resource.AuthorizationResource
	}
	checked, err := s.checkLiveObjects(ctx, current, stage, boundaries)
	if err != nil {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}
	checkedAt := s.now().UTC()
	if checkedAt.IsZero() {
		return LiveAuthorizationReport{}, ErrProtectedContentUnavailable
	}

	report := LiveAuthorizationReport{
		CheckedAt: checkedAt, Consistency: protocol.ConsistencyHigherConsistency,
		ResourceCount: len(binding.Resources),
		Decisions:     make([]LiveAuthorizationDecision, len(binding.Resources)),
	}
	for index, resource := range binding.Resources {
		outcome := protocol.DecisionDeny
		if checked[resource.AuthorizationResource.AuthorizationID].allowed {
			outcome = protocol.DecisionAllow
			report.AllowedCount++
		} else {
			report.DeniedCount++
		}
		report.Decisions[index] = LiveAuthorizationDecision{
			ResourceID: resource.Resource.ResourceID, AuthorizationResourceID: resource.AuthorizationResource.ResourceID,
			Outcome: outcome,
		}
	}
	return report, nil
}

func (s *Service) checkLiveObjects(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	resources []protocol.ResourceHandle,
) (map[string]objectCheck, error) {
	if ctx == nil {
		return nil, ErrProtectedContentUnavailable
	}
	authorization.Consistency = protocol.ConsistencyHigherConsistency
	return s.checkObjects(ctx, authorization, stage, resources)
}

func (s *Service) checkLiveEvidence(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	stage string,
	items []protocol.EvidenceItem,
) (checkedEvidence, error) {
	handles, boundaries, projection, err := collectEvidenceHandles(authorization, items)
	if err != nil {
		return checkedEvidence{}, err
	}
	objects, err := s.checkLiveObjects(ctx, authorization, stage, handles)
	if err != nil {
		return checkedEvidence{}, err
	}
	for _, resource := range handles {
		if !objects[resource.AuthorizationID].allowed {
			return checkedEvidence{}, ErrProtectedContentUnavailable
		}
	}
	return checkedEvidence{
		handles: handles, boundaries: boundaries, projection: projection, objects: objects,
	}, nil
}

func validatedRevocationResourceIDs(
	binding protocol.ProtectedContentBinding,
	requested []protocol.ResourceID,
) ([]protocol.ResourceID, error) {
	if len(requested) == 0 {
		return nil, ErrRevocationUnavailable
	}
	bound := make(map[protocol.ResourceID]struct{}, len(binding.Resources)*2)
	for _, resource := range binding.Resources {
		bound[resource.Resource.ResourceID] = struct{}{}
		bound[resource.AuthorizationResource.ResourceID] = struct{}{}
	}
	seen := make(map[protocol.ResourceID]struct{}, len(requested))
	for _, resourceID := range requested {
		if err := resourceID.Validate(); err != nil {
			return nil, ErrRevocationUnavailable
		}
		if _, ok := bound[resourceID]; !ok {
			return nil, ErrRevocationUnavailable
		}
		seen[resourceID] = struct{}{}
	}
	result := make([]protocol.ResourceID, 0, len(seen))
	for resourceID := range seen {
		result = append(result, resourceID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}
