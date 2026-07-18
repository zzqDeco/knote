package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type AuthoritativeResource struct {
	ResourceID      protocol.ResourceID    `json:"resource_id"`
	SourceWatermark string                 `json:"source_watermark"`
	ContentDigest   protocol.ContentDigest `json:"content_digest"`
	ACLWatermark    string                 `json:"acl_watermark"`
	ACLDigest       protocol.ContentDigest `json:"acl_digest"`
}

func (r AuthoritativeResource) Validate() error {
	if err := r.ResourceID.Validate(); err != nil {
		return err
	}
	if err := validateOpaqueID("source_watermark", r.SourceWatermark); err != nil {
		return err
	}
	if err := r.ContentDigest.Validate(); err != nil {
		return fmt.Errorf("content_digest: %w", err)
	}
	if err := validateOpaqueID("acl_watermark", r.ACLWatermark); err != nil {
		return err
	}
	if err := r.ACLDigest.Validate(); err != nil {
		return fmt.Errorf("acl_digest: %w", err)
	}
	return nil
}

type AuthoritativeSnapshot struct {
	Version         string                  `json:"version"`
	TenantID        string                  `json:"tenant_id"`
	ConnectorID     string                  `json:"connector_id"`
	SourceWatermark string                  `json:"source_watermark"`
	ACLWatermark    string                  `json:"acl_watermark"`
	CapturedAt      time.Time               `json:"captured_at"`
	Resources       []AuthoritativeResource `json:"resources"`
}

func (s AuthoritativeSnapshot) Validate() error {
	if s.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported authoritative snapshot version %q", s.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", s.TenantID},
		{"connector_id", s.ConnectorID},
		{"source_watermark", s.SourceWatermark},
		{"acl_watermark", s.ACLWatermark},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validateUTC("captured_at", s.CapturedAt); err != nil {
		return err
	}
	if s.Resources == nil {
		return fmt.Errorf("authoritative resources must use an explicit empty list")
	}
	var previous protocol.ResourceID
	for index, resource := range s.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("authoritative resource %d: %w", index, err)
		}
		if index > 0 && resource.ResourceID <= previous {
			return fmt.Errorf("authoritative resources must be sorted and unique")
		}
		previous = resource.ResourceID
	}
	return nil
}

type ProjectedResource struct {
	ResourceID      protocol.ResourceID    `json:"resource_id"`
	SourceWatermark string                 `json:"source_watermark"`
	ContentDigest   protocol.ContentDigest `json:"content_digest"`
}

func (r ProjectedResource) Validate() error {
	if err := r.ResourceID.Validate(); err != nil {
		return err
	}
	if err := validateOpaqueID("source_watermark", r.SourceWatermark); err != nil {
		return err
	}
	return r.ContentDigest.Validate()
}

type ProjectedACL struct {
	ResourceID   protocol.ResourceID    `json:"resource_id"`
	ACLWatermark string                 `json:"acl_watermark"`
	ACLDigest    protocol.ContentDigest `json:"acl_digest"`
}

func (a ProjectedACL) Validate() error {
	if err := a.ResourceID.Validate(); err != nil {
		return err
	}
	if err := validateOpaqueID("acl_watermark", a.ACLWatermark); err != nil {
		return err
	}
	return a.ACLDigest.Validate()
}

type ProjectionSnapshot struct {
	Version                string              `json:"version"`
	TenantID               string              `json:"tenant_id"`
	ConnectorID            string              `json:"connector_id"`
	ProjectionBaseSequence uint64              `json:"projection_base_sequence"`
	Resources              []ProjectedResource `json:"resources"`
	ACLs                   []ProjectedACL      `json:"acls"`
}

func (s ProjectionSnapshot) Validate() error {
	if s.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported projection snapshot version %q", s.Version)
	}
	if err := validateOpaqueID("tenant_id", s.TenantID); err != nil {
		return err
	}
	if err := validateOpaqueID("connector_id", s.ConnectorID); err != nil {
		return err
	}
	if s.Resources == nil || s.ACLs == nil {
		return fmt.Errorf("projection resources and ACLs must use explicit empty lists")
	}
	var previousResource protocol.ResourceID
	for index, resource := range s.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("projected resource %d: %w", index, err)
		}
		if index > 0 && resource.ResourceID <= previousResource {
			return fmt.Errorf("projected resources must be sorted and unique")
		}
		previousResource = resource.ResourceID
	}
	var previousACL protocol.ResourceID
	for index, acl := range s.ACLs {
		if err := acl.Validate(); err != nil {
			return fmt.Errorf("projected ACL %d: %w", index, err)
		}
		if index > 0 && acl.ResourceID <= previousACL {
			return fmt.Errorf("projected ACLs must be sorted and unique")
		}
		previousACL = acl.ResourceID
	}
	return nil
}

type ReconciliationPlan struct {
	Version             string                 `json:"version"`
	TenantID            string                 `json:"tenant_id"`
	ConnectorID         string                 `json:"connector_id"`
	SourceWatermark     string                 `json:"source_watermark"`
	ACLWatermark        string                 `json:"acl_watermark"`
	MissingResources    []protocol.ResourceID  `json:"missing_resources"`
	ChangedResources    []protocol.ResourceID  `json:"changed_resources"`
	StaleResources      []protocol.ResourceID  `json:"stale_resources"`
	MissingACLs         []protocol.ResourceID  `json:"missing_acls"`
	ChangedACLs         []protocol.ResourceID  `json:"changed_acls"`
	StaleACLs           []protocol.ResourceID  `json:"stale_acls"`
	TombstonedResources []protocol.ResourceID  `json:"tombstoned_resources"`
	Digest              protocol.ContentDigest `json:"digest"`
}

func (p ReconciliationPlan) Noop() bool {
	return len(p.MissingResources) == 0 && len(p.ChangedResources) == 0 && len(p.StaleResources) == 0 &&
		len(p.MissingACLs) == 0 && len(p.ChangedACLs) == 0 && len(p.StaleACLs) == 0
}

// ReconciliationProjector is intentionally independent from Catalog and
// OpenFGA. Implementations translate this content-free plan into a candidate
// projection; serving publication remains a separate operation. A callback can
// repeat after an ambiguous crash, so implementations must apply each request
// idempotently by IdempotencyKey.
type ReconciliationProjector interface {
	ApplyReconciliation(context.Context, ReconciliationApplyRequest) error
}

type ReconciliationProjectorFunc func(context.Context, ReconciliationApplyRequest) error

func (f ReconciliationProjectorFunc) ApplyReconciliation(ctx context.Context, request ReconciliationApplyRequest) error {
	return f(ctx, request)
}

func PlanReconciliation(
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
	tombstones []protocol.ConnectorTombstone,
) (ReconciliationPlan, error) {
	tombstoneIDs, err := validateReconciliationTombstones(authoritative, tombstones)
	if err != nil {
		return ReconciliationPlan{}, err
	}
	return planReconciliation(authoritative, projected, tombstoneIDs)
}

func planReconciliation(
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
	terminalResourceIDs []protocol.ResourceID,
) (ReconciliationPlan, error) {
	if err := authoritative.Validate(); err != nil {
		return ReconciliationPlan{}, err
	}
	if err := projected.Validate(); err != nil {
		return ReconciliationPlan{}, err
	}
	if authoritative.TenantID != projected.TenantID || authoritative.ConnectorID != projected.ConnectorID {
		return ReconciliationPlan{}, fmt.Errorf("authoritative and projected snapshots cross connector scope")
	}
	tombstoneIDs := append([]protocol.ResourceID{}, terminalResourceIDs...)
	var previous protocol.ResourceID
	for index, resourceID := range tombstoneIDs {
		if err := resourceID.Validate(); err != nil {
			return ReconciliationPlan{}, err
		}
		if index > 0 && resourceID <= previous {
			return ReconciliationPlan{}, fmt.Errorf("terminal reconciliation resources must be sorted and unique")
		}
		previous = resourceID
	}

	plan := ReconciliationPlan{
		Version: ConnectorCoreVersion, TenantID: authoritative.TenantID,
		ConnectorID: authoritative.ConnectorID, SourceWatermark: authoritative.SourceWatermark,
		ACLWatermark:     authoritative.ACLWatermark,
		MissingResources: []protocol.ResourceID{}, ChangedResources: []protocol.ResourceID{},
		StaleResources: []protocol.ResourceID{}, MissingACLs: []protocol.ResourceID{},
		ChangedACLs: []protocol.ResourceID{}, StaleACLs: []protocol.ResourceID{},
		TombstonedResources: tombstoneIDs,
	}
	authoritativeByID := make(map[protocol.ResourceID]AuthoritativeResource, len(authoritative.Resources))
	projectedResourcesByID := make(map[protocol.ResourceID]ProjectedResource, len(projected.Resources))
	projectedACLsByID := make(map[protocol.ResourceID]ProjectedACL, len(projected.ACLs))
	for _, resource := range authoritative.Resources {
		if containsResourceID(tombstoneIDs, resource.ResourceID) {
			return ReconciliationPlan{}, fmt.Errorf("%w: authoritative snapshot contains %s", ErrTombstoneResurrection, resource.ResourceID)
		}
		authoritativeByID[resource.ResourceID] = resource
	}
	for _, resource := range projected.Resources {
		projectedResourcesByID[resource.ResourceID] = resource
	}
	for _, acl := range projected.ACLs {
		projectedACLsByID[acl.ResourceID] = acl
	}

	for _, resource := range authoritative.Resources {
		projectedResource, exists := projectedResourcesByID[resource.ResourceID]
		if !exists {
			plan.MissingResources = append(plan.MissingResources, resource.ResourceID)
		} else if projectedResource.SourceWatermark != resource.SourceWatermark ||
			projectedResource.ContentDigest != resource.ContentDigest {
			plan.ChangedResources = append(plan.ChangedResources, resource.ResourceID)
		}
		projectedACL, exists := projectedACLsByID[resource.ResourceID]
		if !exists {
			plan.MissingACLs = append(plan.MissingACLs, resource.ResourceID)
		} else if projectedACL.ACLWatermark != resource.ACLWatermark || projectedACL.ACLDigest != resource.ACLDigest {
			plan.ChangedACLs = append(plan.ChangedACLs, resource.ResourceID)
		}
	}
	for _, resource := range projected.Resources {
		if _, exists := authoritativeByID[resource.ResourceID]; !exists {
			plan.StaleResources = append(plan.StaleResources, resource.ResourceID)
		}
	}
	for _, acl := range projected.ACLs {
		if _, exists := authoritativeByID[acl.ResourceID]; !exists {
			plan.StaleACLs = append(plan.StaleACLs, acl.ResourceID)
		}
	}
	terminalAndPlanned := append([]protocol.ResourceID{}, plan.TombstonedResources...)
	terminalAndPlanned = append(terminalAndPlanned, reconciliationRemovalIDs(plan)...)
	sort.Slice(terminalAndPlanned, func(i, j int) bool { return terminalAndPlanned[i] < terminalAndPlanned[j] })
	plan.TombstonedResources = plan.TombstonedResources[:0]
	for _, resourceID := range terminalAndPlanned {
		if len(plan.TombstonedResources) == 0 ||
			plan.TombstonedResources[len(plan.TombstonedResources)-1] != resourceID {
			plan.TombstonedResources = append(plan.TombstonedResources, resourceID)
		}
	}

	digest, err := reconciliationDigest(plan)
	if err != nil {
		return ReconciliationPlan{}, err
	}
	plan.Digest = digest
	return plan, nil
}

func (p *Processor) PlanReconciliation(
	ref ConnectorRef,
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
) (ReconciliationPlan, error) {
	if p == nil || p.store == nil {
		return ReconciliationPlan{}, fmt.Errorf("connector processor is required")
	}
	if err := validateReconciliationScope(ref, authoritative, projected); err != nil {
		return ReconciliationPlan{}, err
	}
	var plan ReconciliationPlan
	err := p.store.withLock(func() error {
		preparation, err := p.prepareReconciliationLocked(ref, authoritative, projected, nil)
		if err != nil {
			return err
		}
		plan = preparation.request.Plan
		return nil
	})
	return plan, err
}

// Reconcile derives the only plan a projector may receive from the registered
// connector scope and its durable tombstones. A nil return error means the
// projector accepted the candidate plan; it does not mean serving publication
// occurred.
func (p *Processor) Reconcile(
	ctx context.Context,
	ref ConnectorRef,
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
	projector ReconciliationProjector,
) (ReconciliationPlan, error) {
	if p == nil || p.store == nil {
		return ReconciliationPlan{}, fmt.Errorf("connector processor is required")
	}
	if ctx == nil {
		return ReconciliationPlan{}, fmt.Errorf("reconciliation context is required")
	}
	if isNilReconciliationProjector(projector) {
		return ReconciliationPlan{}, fmt.Errorf("reconciliation projector is required")
	}
	if err := ctx.Err(); err != nil {
		return ReconciliationPlan{}, err
	}
	if err := validateReconciliationScope(ref, authoritative, projected); err != nil {
		return ReconciliationPlan{}, err
	}
	var plan ReconciliationPlan
	err := p.store.withConnectorLock(ctx, ref, func() error {
		var reservation ReconciliationReservation
		var preparation reconciliationPreparation
		alreadyApplied := false
		needsReservation := false
		if err := p.store.withLock(func() error {
			if err := p.requireQuiescentConnectorLocked(ref); err != nil {
				return err
			}
			var err error
			preparation, err = p.prepareReconciliationLocked(ref, authoritative, projected, nil)
			if err != nil {
				return err
			}
			request := preparation.request
			plan = request.Plan
			requestDigest, err := canonicalContentDigest(request)
			if err != nil {
				return err
			}
			reservation = ReconciliationReservation{
				Version: ConnectorCoreVersion, Request: request, RequestDigest: requestDigest,
			}
			hasPending := false
			var pending ReconciliationReservation
			if found, err := p.store.readOptionalJSON(p.store.reconciliationPendingPath(ref), &pending); err != nil {
				return err
			} else if found {
				hasPending = true
				if err := pending.Validate(); err != nil {
					return fmt.Errorf("%w: pending reconciliation: %v", ErrStoreIntegrity, err)
				}
				if pending.RequestDigest != reservation.RequestDigest ||
					!reconciliationRequestsEqual(pending.Request, reservation.Request) {
					return ErrPendingReconciliation
				}
				reservation = pending
				plan = pending.Request.Plan
			}
			var receipt ReconciliationReservationReceipt
			if found, err := p.store.readOptionalJSON(
				p.store.reconciliationReservationReceiptPath(ref, reservation.RequestDigest), &receipt,
			); err != nil {
				return err
			} else if found {
				if err := receipt.ValidateFor(reservation); err != nil {
					return fmt.Errorf("%w: reconciliation receipt: %v", ErrStoreIntegrity, err)
				}
				alreadyApplied = true
				return p.store.removeFileDurably(p.store.reconciliationPendingPath(ref))
			}
			if hasPending {
				return nil
			}
			needsReservation = true
			return nil
		}); err != nil {
			return err
		}
		if alreadyApplied {
			return nil
		}
		if needsReservation {
			createdAt, err := p.now()
			if err != nil {
				return err
			}
			reservation.CreatedAt = createdAt
			if err := reservation.Validate(); err != nil {
				return err
			}
			if err := p.store.withLock(func() error {
				if err := p.requireQuiescentConnectorLocked(ref); err != nil {
					return err
				}
				current, err := p.prepareReconciliationLocked(ref, authoritative, projected, nil)
				if err != nil {
					return err
				}
				if !reconciliationRequestsEqual(current.request, reservation.Request) {
					return ErrPendingReconciliation
				}
				if err := p.store.claimReconciliationResourceOwnershipsLocked(
					ref, current.registration, current.unownedAuthoritative,
					nil, "", reservation.RequestDigest, createdAt,
				); err != nil {
					return err
				}
				return p.store.writeJSONOnce(p.store.reconciliationPendingPath(ref), reservation)
			}); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := projector.ApplyReconciliation(ctx, cloneReconciliationRequest(reservation.Request)); err != nil {
			return fmt.Errorf("apply connector reconciliation: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		appliedAt, err := p.now()
		if err != nil {
			return err
		}
		derivedTombstones, err := newReconciliationTombstones(
			reservation.Request, reservation.RequestDigest,
		)
		if err != nil {
			return err
		}
		receipt := ReconciliationReservationReceipt{
			Version: ConnectorCoreVersion, TenantID: reservation.Request.SourceOwnership.TenantID,
			ConnectorID: reservation.Request.SourceOwnership.ConnectorID,
			SourceID:    reservation.Request.SourceOwnership.SourceID, PlanDigest: reservation.Request.Plan.Digest,
			RequestDigest: reservation.RequestDigest, Request: cloneReconciliationRequest(reservation.Request),
			DerivedTombstones: derivedTombstones, AppliedAt: appliedAt,
		}
		if err := receipt.ValidateFor(reservation); err != nil {
			return err
		}
		return p.store.withLock(func() error {
			var pending ReconciliationReservation
			found, err := p.store.readOptionalJSON(p.store.reconciliationPendingPath(ref), &pending)
			if err != nil {
				return err
			}
			if !found || pending.RequestDigest != reservation.RequestDigest ||
				!reconciliationRequestsEqual(pending.Request, reservation.Request) {
				return ErrPendingReconciliation
			}
			if err := p.store.writeJSONOnce(
				p.store.reconciliationReservationReceiptPath(ref, reservation.RequestDigest), receipt,
			); err != nil {
				return err
			}
			return p.store.removeFileDurably(p.store.reconciliationPendingPath(ref))
		})
	})
	if err != nil {
		return ReconciliationPlan{}, err
	}
	return plan, nil
}

func (p *Processor) requireQuiescentConnectorLocked(ref ConnectorRef) error {
	state, err := p.store.loadStateLocked(ref, true)
	if err != nil {
		return err
	}
	checkpointSequence := uint64(0)
	if state.cursor.Checkpoint != nil {
		checkpointSequence = state.cursor.Checkpoint.LastSequence
	}
	servingSequence := uint64(0)
	if state.cursor.Serving != nil {
		servingSequence = state.cursor.Serving.Sequence
	}
	if state.cursor.Blocked != nil || state.cursor.AppendedSequence != checkpointSequence ||
		checkpointSequence != servingSequence {
		return ErrPendingEvent
	}
	return nil
}

type reconciliationPreparation struct {
	registration         Registration
	request              ReconciliationApplyRequest
	unownedAuthoritative []protocol.ResourceID
}

func (p *Processor) prepareReconciliationLocked(
	ref ConnectorRef,
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
	snapshot *SnapshotReconciliationBinding,
) (reconciliationPreparation, error) {
	state, err := p.store.loadStateLocked(ref, true)
	if err != nil {
		return reconciliationPreparation{}, err
	}
	checkpointSequence := uint64(0)
	if state.cursor.Checkpoint != nil {
		checkpointSequence = state.cursor.Checkpoint.LastSequence
	}
	if projected.ProjectionBaseSequence != checkpointSequence {
		return reconciliationPreparation{}, ErrProjectionBaseMismatch
	}
	if snapshot != nil {
		if snapshot.Sequence == 0 {
			return reconciliationPreparation{}, ErrSnapshotReconciliationRequired
		}
		if projected.ProjectionBaseSequence != snapshot.Sequence-1 {
			return reconciliationPreparation{}, ErrProjectionBaseMismatch
		}
	}
	terminalIDs := committedTerminalResourceIDs(state)
	plan, err := planReconciliation(authoritative, projected, terminalIDs)
	if err != nil {
		return reconciliationPreparation{}, err
	}
	resourceIDs := reconciliationSnapshotResourceIDs(authoritative, projected, plan)
	authoritativeIDs := make(map[protocol.ResourceID]struct{}, len(authoritative.Resources))
	for _, resource := range authoritative.Resources {
		authoritativeIDs[resource.ResourceID] = struct{}{}
	}
	unowned := make([]protocol.ResourceID, 0)
	for _, resourceID := range resourceIDs {
		ownership, found, err := p.store.loadResourceOwnershipOptionalLocked(ref, resourceID)
		if err != nil {
			return reconciliationPreparation{}, err
		}
		if found {
			if err := validateResourceOwnershipForRegistration(ownership, state.registration); err != nil {
				return reconciliationPreparation{}, err
			}
			continue
		}
		if _, claimable := authoritativeIDs[resourceID]; !claimable {
			return reconciliationPreparation{}, ErrResourceOwnershipRequired
		}
		unowned = append(unowned, resourceID)
	}
	authoritativeDigest, err := authoritativeSnapshotDigest(authoritative)
	if err != nil {
		return reconciliationPreparation{}, err
	}
	projectedDigest, err := projectionSnapshotDigest(projected)
	if err != nil {
		return reconciliationPreparation{}, err
	}
	request := ReconciliationApplyRequest{
		Version: ConnectorCoreVersion, SourceOwnership: sourceOwnershipFor(state.registration),
		OwnedResourceIDs:            append([]protocol.ResourceID{}, resourceIDs...),
		AuthoritativeSnapshotDigest: authoritativeDigest, ProjectedSnapshotDigest: projectedDigest,
		AuthoritativeCapturedAt: authoritative.CapturedAt,
		AuthoritativeResources:  append([]AuthoritativeResource{}, authoritative.Resources...),
		ProjectionBaseSequence:  projected.ProjectionBaseSequence, Plan: plan, Snapshot: snapshot,
	}
	if err := bindReconciliationIdempotencyKey(&request); err != nil {
		return reconciliationPreparation{}, err
	}
	if err := request.Validate(); err != nil {
		return reconciliationPreparation{}, err
	}
	return reconciliationPreparation{
		registration: state.registration, request: request, unownedAuthoritative: unowned,
	}, nil
}

func validateReconciliationScope(
	ref ConnectorRef,
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if authoritative.TenantID != ref.Scope.TenantID || authoritative.ConnectorID != ref.ConnectorID ||
		projected.TenantID != ref.Scope.TenantID || projected.ConnectorID != ref.ConnectorID {
		return fmt.Errorf("reconciliation snapshots cross the registered connector scope")
	}
	return nil
}

func ReconciliationJSON(plan ReconciliationPlan) ([]byte, error) {
	if err := validateReconciliationPlan(plan); err != nil {
		return nil, err
	}
	return deterministicJSON(plan)
}

func authoritativeSnapshotDigest(snapshot AuthoritativeSnapshot) (protocol.ContentDigest, error) {
	if err := snapshot.Validate(); err != nil {
		return "", err
	}
	return canonicalContentDigest(snapshot)
}

func projectionSnapshotDigest(snapshot ProjectionSnapshot) (protocol.ContentDigest, error) {
	if err := snapshot.Validate(); err != nil {
		return "", err
	}
	return canonicalContentDigest(snapshot)
}

func reconciliationSnapshotResourceIDs(
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
	plan ReconciliationPlan,
) []protocol.ResourceID {
	resourceIDs := reconciliationPlanResourceIDs(plan)
	for _, resource := range authoritative.Resources {
		resourceIDs = append(resourceIDs, resource.ResourceID)
	}
	for _, resource := range projected.Resources {
		resourceIDs = append(resourceIDs, resource.ResourceID)
	}
	for _, acl := range projected.ACLs {
		resourceIDs = append(resourceIDs, acl.ResourceID)
	}
	sort.Slice(resourceIDs, func(i, j int) bool { return resourceIDs[i] < resourceIDs[j] })
	unique := resourceIDs[:0]
	for _, resourceID := range resourceIDs {
		if len(unique) == 0 || unique[len(unique)-1] != resourceID {
			unique = append(unique, resourceID)
		}
	}
	return unique
}

func cloneReconciliationRequest(request ReconciliationApplyRequest) ReconciliationApplyRequest {
	clone := request
	clone.OwnedResourceIDs = append([]protocol.ResourceID{}, request.OwnedResourceIDs...)
	clone.AuthoritativeResources = append([]AuthoritativeResource{}, request.AuthoritativeResources...)
	clone.Plan = cloneReconciliationPlan(request.Plan)
	if request.Snapshot != nil {
		snapshot := *request.Snapshot
		clone.Snapshot = &snapshot
	}
	return clone
}

func validateReconciliationTombstones(
	snapshot AuthoritativeSnapshot,
	tombstones []protocol.ConnectorTombstone,
) ([]protocol.ResourceID, error) {
	canonical := append([]protocol.ConnectorTombstone(nil), tombstones...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].ResourceID != canonical[j].ResourceID {
			return canonical[i].ResourceID < canonical[j].ResourceID
		}
		return canonical[i].Sequence < canonical[j].Sequence
	})
	resourceIDs := []protocol.ResourceID{}
	for _, tombstone := range canonical {
		if tombstone.Version != protocol.EnterpriseContractVersion ||
			tombstone.TenantID != snapshot.TenantID || tombstone.ConnectorID != snapshot.ConnectorID {
			return nil, fmt.Errorf("reconciliation tombstone crosses connector scope")
		}
		if err := tombstone.EventFingerprint.Validate(); err != nil {
			return nil, err
		}
		if err := tombstone.ResourceID.Validate(); err != nil {
			return nil, err
		}
		for _, field := range []struct {
			name  string
			value string
		}{
			{"event_id", tombstone.EventID},
			{"idempotency_key", tombstone.IdempotencyKey},
			{"source_watermark", tombstone.SourceWatermark},
			{"acl_watermark", tombstone.ACLWatermark},
			{"reason_code", tombstone.ReasonCode},
		} {
			if err := validateOpaqueID(field.name, field.value); err != nil {
				return nil, err
			}
		}
		if tombstone.Sequence == 0 {
			return nil, fmt.Errorf("reconciliation tombstone sequence must be greater than zero")
		}
		if err := validateUTC("deleted_at", tombstone.DeletedAt); err != nil {
			return nil, err
		}
		if len(resourceIDs) == 0 || resourceIDs[len(resourceIDs)-1] != tombstone.ResourceID {
			resourceIDs = append(resourceIDs, tombstone.ResourceID)
		}
	}
	return resourceIDs, nil
}

func validateReconciliationPlan(plan ReconciliationPlan) error {
	if plan.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported reconciliation plan version %q", plan.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", plan.TenantID},
		{"connector_id", plan.ConnectorID},
		{"source_watermark", plan.SourceWatermark},
		{"acl_watermark", plan.ACLWatermark},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name   string
		values []protocol.ResourceID
	}{
		{"missing_resources", plan.MissingResources},
		{"changed_resources", plan.ChangedResources},
		{"stale_resources", plan.StaleResources},
		{"missing_acls", plan.MissingACLs},
		{"changed_acls", plan.ChangedACLs},
		{"stale_acls", plan.StaleACLs},
		{"tombstoned_resources", plan.TombstonedResources},
	} {
		if field.values == nil {
			return fmt.Errorf("%s must use an explicit empty list", field.name)
		}
		var previous protocol.ResourceID
		for index, resourceID := range field.values {
			if err := resourceID.Validate(); err != nil {
				return err
			}
			if index > 0 && resourceID <= previous {
				return fmt.Errorf("%s must be sorted and unique", field.name)
			}
			previous = resourceID
		}
	}
	if err := plan.Digest.Validate(); err != nil {
		return err
	}
	expected, err := reconciliationDigest(plan)
	if err != nil {
		return err
	}
	if plan.Digest != expected {
		return fmt.Errorf("reconciliation plan digest does not match its contents")
	}
	return nil
}

func reconciliationDigest(plan ReconciliationPlan) (protocol.ContentDigest, error) {
	plan.Digest = ""
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return protocol.NewContentDigest(string(data)), nil
}

func containsResourceID(values []protocol.ResourceID, expected protocol.ResourceID) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= expected })
	return index < len(values) && values[index] == expected
}

func cloneReconciliationPlan(plan ReconciliationPlan) ReconciliationPlan {
	clone := plan
	clone.MissingResources = append([]protocol.ResourceID{}, plan.MissingResources...)
	clone.ChangedResources = append([]protocol.ResourceID{}, plan.ChangedResources...)
	clone.StaleResources = append([]protocol.ResourceID{}, plan.StaleResources...)
	clone.MissingACLs = append([]protocol.ResourceID{}, plan.MissingACLs...)
	clone.ChangedACLs = append([]protocol.ResourceID{}, plan.ChangedACLs...)
	clone.StaleACLs = append([]protocol.ResourceID{}, plan.StaleACLs...)
	clone.TombstonedResources = append([]protocol.ResourceID{}, plan.TombstonedResources...)
	return clone
}

func isNilReconciliationProjector(projector ReconciliationProjector) bool {
	if projector == nil {
		return true
	}
	value := reflect.ValueOf(projector)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
