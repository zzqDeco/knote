package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type SourceOwnership struct {
	Version     string `json:"version"`
	TenantID    string `json:"tenant_id"`
	ConnectorID string `json:"connector_id"`
	SourceID    string `json:"source_id"`
}

func (o SourceOwnership) Validate() error {
	if o.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported source ownership version %q", o.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", o.TenantID},
		{"connector_id", o.ConnectorID},
		{"source_id", o.SourceID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

func (o SourceOwnership) ValidateForEvent(event protocol.ConnectorEventEnvelope) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if o.TenantID != event.TenantID || o.ConnectorID != event.ConnectorID {
		return fmt.Errorf("source ownership crosses the event scope")
	}
	return nil
}

func sourceOwnershipFor(registration Registration) SourceOwnership {
	return SourceOwnership{
		Version: ConnectorCoreVersion, TenantID: registration.Scope.TenantID,
		ConnectorID: registration.ConnectorID, SourceID: registration.SourceID,
	}
}

type ResourceOwnership struct {
	Version                   string                             `json:"version"`
	TenantID                  string                             `json:"tenant_id"`
	ResourceID                protocol.ResourceID                `json:"resource_id"`
	ConnectorID               string                             `json:"connector_id"`
	SourceID                  string                             `json:"source_id"`
	BoundEventID              string                             `json:"bound_event_id,omitempty"`
	BoundFingerprint          protocol.ConnectorEventFingerprint `json:"bound_event_fingerprint,omitempty"`
	BoundSequence             uint64                             `json:"bound_sequence,omitempty"`
	BoundReconciliationDigest protocol.ContentDigest             `json:"bound_reconciliation_digest,omitempty"`
	BoundAt                   time.Time                          `json:"bound_at"`
}

type ReconciliationOwnershipClaim struct {
	Version          string                             `json:"version"`
	TenantID         string                             `json:"tenant_id"`
	ConnectorID      string                             `json:"connector_id"`
	SourceID         string                             `json:"source_id"`
	ResourceIDs      []protocol.ResourceID              `json:"resource_ids"`
	BoundEventID     string                             `json:"bound_event_id,omitempty"`
	BoundFingerprint protocol.ConnectorEventFingerprint `json:"bound_event_fingerprint,omitempty"`
	BoundSequence    uint64                             `json:"bound_sequence,omitempty"`
	RequestDigest    protocol.ContentDigest             `json:"request_digest,omitempty"`
	BoundAt          time.Time                          `json:"bound_at"`
}

func (c ReconciliationOwnershipClaim) Validate() error {
	if c.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported reconciliation ownership claim version %q", c.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", c.TenantID},
		{"connector_id", c.ConnectorID},
		{"source_id", c.SourceID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	if len(c.ResourceIDs) == 0 {
		return fmt.Errorf("reconciliation ownership claim requires at least one resource")
	}
	var previous protocol.ResourceID
	for index, resourceID := range c.ResourceIDs {
		if err := resourceID.Validate(); err != nil {
			return err
		}
		if index > 0 && resourceID <= previous {
			return fmt.Errorf("reconciliation ownership claim resources must be sorted and unique")
		}
		previous = resourceID
	}
	eventBound := c.BoundEventID != "" || c.BoundFingerprint != "" || c.BoundSequence != 0
	requestBound := c.RequestDigest != ""
	if eventBound == requestBound {
		return fmt.Errorf("reconciliation ownership claim requires exactly one durable binding")
	}
	if eventBound {
		if err := validateOpaqueID("bound_event_id", c.BoundEventID); err != nil {
			return err
		}
		if err := c.BoundFingerprint.Validate(); err != nil {
			return err
		}
		if c.BoundSequence == 0 {
			return fmt.Errorf("reconciliation ownership claim sequence must be greater than zero")
		}
	} else if err := c.RequestDigest.Validate(); err != nil {
		return err
	}
	return validateUTC("bound_at", c.BoundAt)
}

func (c ReconciliationOwnershipClaim) Ownership(resourceID protocol.ResourceID) (ResourceOwnership, error) {
	if err := c.Validate(); err != nil {
		return ResourceOwnership{}, err
	}
	if !containsResourceID(c.ResourceIDs, resourceID) {
		return ResourceOwnership{}, ErrResourceOwnershipRequired
	}
	ownership := ResourceOwnership{
		Version: ConnectorCoreVersion, TenantID: c.TenantID, ResourceID: resourceID,
		ConnectorID: c.ConnectorID, SourceID: c.SourceID,
		BoundEventID: c.BoundEventID, BoundFingerprint: c.BoundFingerprint,
		BoundSequence: c.BoundSequence, BoundReconciliationDigest: c.RequestDigest,
		BoundAt: c.BoundAt,
	}
	if err := ownership.Validate(); err != nil {
		return ResourceOwnership{}, err
	}
	return ownership, nil
}

func (o ResourceOwnership) Validate() error {
	if o.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported resource ownership version %q", o.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", o.TenantID},
		{"connector_id", o.ConnectorID},
		{"source_id", o.SourceID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	if err := o.ResourceID.Validate(); err != nil {
		return err
	}
	eventBound := o.BoundEventID != "" || o.BoundFingerprint != "" || o.BoundSequence != 0
	reconciliationBound := o.BoundReconciliationDigest != ""
	if eventBound == reconciliationBound {
		return fmt.Errorf("resource ownership requires exactly one durable binding")
	}
	if eventBound {
		if err := validateOpaqueID("bound_event_id", o.BoundEventID); err != nil {
			return err
		}
		if err := o.BoundFingerprint.Validate(); err != nil {
			return err
		}
		if o.BoundSequence == 0 {
			return fmt.Errorf("resource ownership bound_sequence must be greater than zero")
		}
	} else if err := o.BoundReconciliationDigest.Validate(); err != nil {
		return err
	}
	return validateUTC("bound_at", o.BoundAt)
}

type ReconciliationTombstone struct {
	Version                     string                             `json:"version"`
	TenantID                    string                             `json:"tenant_id"`
	ConnectorID                 string                             `json:"connector_id"`
	SourceID                    string                             `json:"source_id"`
	ResourceID                  protocol.ResourceID                `json:"resource_id"`
	RequestDigest               protocol.ContentDigest             `json:"request_digest"`
	AuthoritativeSnapshotDigest protocol.ContentDigest             `json:"authoritative_snapshot_digest"`
	ProjectedSnapshotDigest     protocol.ContentDigest             `json:"projected_snapshot_digest"`
	PlanDigest                  protocol.ContentDigest             `json:"plan_digest"`
	SourceWatermark             string                             `json:"source_watermark"`
	ACLWatermark                string                             `json:"acl_watermark"`
	ProjectionBaseSequence      uint64                             `json:"projection_base_sequence"`
	SnapshotEventFingerprint    protocol.ConnectorEventFingerprint `json:"snapshot_event_fingerprint,omitempty"`
	SnapshotSequence            uint64                             `json:"snapshot_sequence,omitempty"`
	DeletedAt                   time.Time                          `json:"deleted_at"`
}

func (t ReconciliationTombstone) Validate() error {
	if t.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported reconciliation tombstone version %q", t.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", t.TenantID},
		{"connector_id", t.ConnectorID},
		{"source_id", t.SourceID},
		{"source_watermark", t.SourceWatermark},
		{"acl_watermark", t.ACLWatermark},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	if err := t.ResourceID.Validate(); err != nil {
		return err
	}
	for _, digest := range []protocol.ContentDigest{
		t.RequestDigest, t.AuthoritativeSnapshotDigest, t.ProjectedSnapshotDigest, t.PlanDigest,
	} {
		if err := digest.Validate(); err != nil {
			return err
		}
	}
	eventBound := t.SnapshotEventFingerprint != "" || t.SnapshotSequence != 0
	if eventBound {
		if err := t.SnapshotEventFingerprint.Validate(); err != nil {
			return err
		}
		if t.SnapshotSequence == 0 {
			return fmt.Errorf("snapshot reconciliation tombstone sequence must be greater than zero")
		}
	}
	return validateUTC("deleted_at", t.DeletedAt)
}

func (t ReconciliationTombstone) ValidateFor(request ReconciliationApplyRequest, requestDigest protocol.ContentDigest) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if t.TenantID != request.SourceOwnership.TenantID || t.ConnectorID != request.SourceOwnership.ConnectorID ||
		t.SourceID != request.SourceOwnership.SourceID || t.RequestDigest != requestDigest ||
		t.AuthoritativeSnapshotDigest != request.AuthoritativeSnapshotDigest ||
		t.ProjectedSnapshotDigest != request.ProjectedSnapshotDigest || t.PlanDigest != request.Plan.Digest ||
		t.SourceWatermark != request.Plan.SourceWatermark || t.ACLWatermark != request.Plan.ACLWatermark ||
		t.ProjectionBaseSequence != request.ProjectionBaseSequence {
		return fmt.Errorf("reconciliation tombstone does not match its exact request")
	}
	if !containsResourceID(reconciliationRemovalIDs(request.Plan), t.ResourceID) {
		return fmt.Errorf("reconciliation tombstone resource is not an authoritative removal")
	}
	if request.Snapshot == nil {
		if t.SnapshotEventFingerprint != "" || t.SnapshotSequence != 0 {
			return fmt.Errorf("standalone reconciliation tombstone contains snapshot event identity")
		}
	} else if t.SnapshotEventFingerprint != request.Snapshot.EventFingerprint ||
		t.SnapshotSequence != request.Snapshot.Sequence {
		return fmt.Errorf("reconciliation tombstone does not match its snapshot event")
	}
	return nil
}

func (o ResourceOwnership) ValidateForEvent(
	event protocol.ConnectorEventEnvelope,
	source SourceOwnership,
) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := source.ValidateForEvent(event); err != nil {
		return err
	}
	if o.TenantID != source.TenantID || o.ConnectorID != source.ConnectorID || o.SourceID != source.SourceID ||
		o.ResourceID != event.ResourceID {
		return ErrResourceOwnership
	}
	return nil
}

type SnapshotReconciliationIntent struct {
	Version                     string                             `json:"version"`
	TenantID                    string                             `json:"tenant_id"`
	ConnectorID                 string                             `json:"connector_id"`
	SourceID                    string                             `json:"source_id"`
	EventID                     string                             `json:"event_id"`
	EventFingerprint            protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Sequence                    uint64                             `json:"sequence"`
	IdempotencyKey              protocol.ContentDigest             `json:"idempotency_key"`
	AuthoritativeSnapshotDigest protocol.ContentDigest             `json:"authoritative_snapshot_digest"`
	AuthoritativeCapturedAt     time.Time                          `json:"authoritative_captured_at"`
	AuthoritativeResources      []AuthoritativeResource            `json:"authoritative_resources"`
	SourceWatermark             string                             `json:"source_watermark"`
	ACLWatermark                string                             `json:"acl_watermark"`
	ProjectionBaseDigest        protocol.ContentDigest             `json:"projection_base_digest"`
	ProjectionBaseSequence      uint64                             `json:"projection_base_sequence"`
	PlanDigest                  protocol.ContentDigest             `json:"plan_digest"`
	OwnedResourceIDs            []protocol.ResourceID              `json:"owned_resource_ids"`
	Plan                        ReconciliationPlan                 `json:"plan"`
	CreatedAt                   time.Time                          `json:"created_at"`
}

func (i SnapshotReconciliationIntent) ValidateForEvent(event protocol.ConnectorEventEnvelope) error {
	if i.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported snapshot reconciliation intent version %q", i.Version)
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.Kind != protocol.ConnectorSnapshotComplete {
		return fmt.Errorf("snapshot reconciliation intent requires snapshot_complete event")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", i.TenantID},
		{"connector_id", i.ConnectorID},
		{"source_id", i.SourceID},
		{"event_id", i.EventID},
		{"source_watermark", i.SourceWatermark},
		{"acl_watermark", i.ACLWatermark},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	expectedFingerprint, err := protocol.NewConnectorEventFingerprint(event)
	if err != nil {
		return err
	}
	if i.TenantID != event.TenantID || i.ConnectorID != event.ConnectorID || i.EventID != event.EventID ||
		i.EventFingerprint != expectedFingerprint || i.Sequence != event.Sequence ||
		i.SourceWatermark != event.SourceWatermark || i.ACLWatermark != event.ACLWatermark {
		return fmt.Errorf("snapshot reconciliation intent does not match its event")
	}
	if err := i.AuthoritativeSnapshotDigest.Validate(); err != nil {
		return err
	}
	if err := validateUTC("authoritative_captured_at", i.AuthoritativeCapturedAt); err != nil {
		return err
	}
	if i.AuthoritativeSnapshotDigest != event.PayloadDigest {
		return fmt.Errorf("snapshot event payload digest does not match the authoritative snapshot")
	}
	authoritative := AuthoritativeSnapshot{
		Version: ConnectorCoreVersion, TenantID: i.TenantID, ConnectorID: i.ConnectorID,
		SourceWatermark: i.SourceWatermark, ACLWatermark: i.ACLWatermark,
		CapturedAt: i.AuthoritativeCapturedAt, Resources: i.AuthoritativeResources,
	}
	authoritativeDigest, err := authoritativeSnapshotDigest(authoritative)
	if err != nil {
		return err
	}
	if authoritativeDigest != i.AuthoritativeSnapshotDigest {
		return fmt.Errorf("snapshot authoritative resources do not match the authoritative snapshot digest")
	}
	if err := i.ProjectionBaseDigest.Validate(); err != nil {
		return err
	}
	if i.ProjectionBaseSequence != event.Sequence-1 {
		return ErrProjectionBaseMismatch
	}
	if err := validateReconciliationPlan(i.Plan); err != nil {
		return err
	}
	if i.PlanDigest != i.Plan.Digest || i.Plan.TenantID != event.TenantID ||
		i.Plan.ConnectorID != event.ConnectorID || i.Plan.SourceWatermark != event.SourceWatermark ||
		i.Plan.ACLWatermark != event.ACLWatermark {
		return fmt.Errorf("snapshot reconciliation plan does not match its event or intent")
	}
	if i.OwnedResourceIDs == nil {
		return fmt.Errorf("snapshot owned_resource_ids must use an explicit empty list")
	}
	var previous protocol.ResourceID
	for index, resourceID := range i.OwnedResourceIDs {
		if err := resourceID.Validate(); err != nil {
			return err
		}
		if index > 0 && resourceID <= previous {
			return fmt.Errorf("snapshot owned_resource_ids must be sorted and unique")
		}
		previous = resourceID
	}
	for _, resourceID := range reconciliationPlanResourceIDs(i.Plan) {
		if !containsResourceID(i.OwnedResourceIDs, resourceID) {
			return fmt.Errorf("snapshot reconciliation resource %s lacks trusted ownership", resourceID)
		}
	}
	if err := validateUTC("created_at", i.CreatedAt); err != nil {
		return err
	}
	return reconciliationRequestForSnapshotIntent(i).Validate()
}

type SnapshotReconciliationBinding struct {
	EventID                     string                             `json:"event_id"`
	EventFingerprint            protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Sequence                    uint64                             `json:"sequence"`
	AuthoritativeSnapshotDigest protocol.ContentDigest             `json:"authoritative_snapshot_digest"`
	SourceWatermark             string                             `json:"source_watermark"`
	ACLWatermark                string                             `json:"acl_watermark"`
	ProjectionBaseDigest        protocol.ContentDigest             `json:"projection_base_digest"`
	ProjectionBaseSequence      uint64                             `json:"projection_base_sequence"`
	PlanDigest                  protocol.ContentDigest             `json:"plan_digest"`
}

func snapshotBindingFor(intent SnapshotReconciliationIntent) SnapshotReconciliationBinding {
	return SnapshotReconciliationBinding{
		EventID: intent.EventID, EventFingerprint: intent.EventFingerprint, Sequence: intent.Sequence,
		AuthoritativeSnapshotDigest: intent.AuthoritativeSnapshotDigest,
		SourceWatermark:             intent.SourceWatermark, ACLWatermark: intent.ACLWatermark,
		ProjectionBaseDigest: intent.ProjectionBaseDigest, ProjectionBaseSequence: intent.ProjectionBaseSequence,
		PlanDigest: intent.PlanDigest,
	}
}

func reconciliationRequestForSnapshotIntent(intent SnapshotReconciliationIntent) ReconciliationApplyRequest {
	binding := snapshotBindingFor(intent)
	return ReconciliationApplyRequest{
		Version: ConnectorCoreVersion,
		SourceOwnership: SourceOwnership{
			Version: ConnectorCoreVersion, TenantID: intent.TenantID,
			ConnectorID: intent.ConnectorID, SourceID: intent.SourceID,
		},
		OwnedResourceIDs:            append([]protocol.ResourceID{}, intent.OwnedResourceIDs...),
		IdempotencyKey:              intent.IdempotencyKey,
		AuthoritativeSnapshotDigest: intent.AuthoritativeSnapshotDigest,
		AuthoritativeCapturedAt:     intent.AuthoritativeCapturedAt,
		AuthoritativeResources:      append([]AuthoritativeResource{}, intent.AuthoritativeResources...),
		ProjectedSnapshotDigest:     intent.ProjectionBaseDigest,
		ProjectionBaseSequence:      intent.ProjectionBaseSequence,
		Plan:                        cloneReconciliationPlan(intent.Plan), Snapshot: &binding,
	}
}

func (b SnapshotReconciliationBinding) ValidateFor(plan ReconciliationPlan) error {
	if err := validateOpaqueID("event_id", b.EventID); err != nil {
		return err
	}
	if err := b.EventFingerprint.Validate(); err != nil {
		return err
	}
	if b.Sequence == 0 {
		return fmt.Errorf("snapshot reconciliation sequence must be greater than zero")
	}
	if err := b.AuthoritativeSnapshotDigest.Validate(); err != nil {
		return err
	}
	if err := validateOpaqueID("source_watermark", b.SourceWatermark); err != nil {
		return err
	}
	if err := validateOpaqueID("acl_watermark", b.ACLWatermark); err != nil {
		return err
	}
	if err := b.ProjectionBaseDigest.Validate(); err != nil {
		return err
	}
	if b.ProjectionBaseSequence != b.Sequence-1 {
		return ErrProjectionBaseMismatch
	}
	if b.PlanDigest != plan.Digest || b.SourceWatermark != plan.SourceWatermark || b.ACLWatermark != plan.ACLWatermark {
		return fmt.Errorf("snapshot reconciliation binding does not match its plan")
	}
	return nil
}

type ReconciliationApplyRequest struct {
	Version                     string                         `json:"version"`
	SourceOwnership             SourceOwnership                `json:"source_ownership"`
	OwnedResourceIDs            []protocol.ResourceID          `json:"owned_resource_ids"`
	IdempotencyKey              protocol.ContentDigest         `json:"idempotency_key"`
	AuthoritativeSnapshotDigest protocol.ContentDigest         `json:"authoritative_snapshot_digest"`
	AuthoritativeCapturedAt     time.Time                      `json:"authoritative_captured_at"`
	AuthoritativeResources      []AuthoritativeResource        `json:"authoritative_resources"`
	ProjectedSnapshotDigest     protocol.ContentDigest         `json:"projected_snapshot_digest"`
	ProjectionBaseSequence      uint64                         `json:"projection_base_sequence"`
	Plan                        ReconciliationPlan             `json:"plan"`
	Snapshot                    *SnapshotReconciliationBinding `json:"snapshot,omitempty"`
}

func (r ReconciliationApplyRequest) Validate() error {
	if r.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported reconciliation apply request version %q", r.Version)
	}
	if err := r.SourceOwnership.Validate(); err != nil {
		return err
	}
	if err := validateReconciliationPlan(r.Plan); err != nil {
		return err
	}
	if r.SourceOwnership.TenantID != r.Plan.TenantID || r.SourceOwnership.ConnectorID != r.Plan.ConnectorID {
		return fmt.Errorf("reconciliation source ownership crosses the plan scope")
	}
	if err := r.AuthoritativeSnapshotDigest.Validate(); err != nil {
		return err
	}
	if err := validateUTC("authoritative_captured_at", r.AuthoritativeCapturedAt); err != nil {
		return err
	}
	authoritative := AuthoritativeSnapshot{
		Version:  ConnectorCoreVersion,
		TenantID: r.SourceOwnership.TenantID, ConnectorID: r.SourceOwnership.ConnectorID,
		SourceWatermark: r.Plan.SourceWatermark, ACLWatermark: r.Plan.ACLWatermark,
		CapturedAt: r.AuthoritativeCapturedAt, Resources: r.AuthoritativeResources,
	}
	authoritativeDigest, err := authoritativeSnapshotDigest(authoritative)
	if err != nil {
		return err
	}
	if authoritativeDigest != r.AuthoritativeSnapshotDigest {
		return fmt.Errorf("reconciliation authoritative resources do not match the authoritative snapshot digest")
	}
	if err := r.ProjectedSnapshotDigest.Validate(); err != nil {
		return err
	}
	if r.OwnedResourceIDs == nil {
		return fmt.Errorf("owned_resource_ids must use an explicit empty list")
	}
	var previous protocol.ResourceID
	for index, resourceID := range r.OwnedResourceIDs {
		if err := resourceID.Validate(); err != nil {
			return err
		}
		if index > 0 && resourceID <= previous {
			return fmt.Errorf("owned_resource_ids must be sorted and unique")
		}
		previous = resourceID
	}
	for _, resourceID := range reconciliationPlanResourceIDs(r.Plan) {
		if !containsResourceID(r.OwnedResourceIDs, resourceID) {
			return fmt.Errorf("reconciliation resource %s lacks trusted source ownership", resourceID)
		}
	}
	if r.Snapshot != nil {
		if err := r.Snapshot.ValidateFor(r.Plan); err != nil {
			return err
		}
		if r.Snapshot.AuthoritativeSnapshotDigest != r.AuthoritativeSnapshotDigest ||
			r.Snapshot.ProjectionBaseDigest != r.ProjectedSnapshotDigest ||
			r.Snapshot.ProjectionBaseSequence != r.ProjectionBaseSequence {
			return fmt.Errorf("snapshot reconciliation request digests or base sequence do not match its event")
		}
	}
	return validateReconciliationIdempotencyKey(r)
}

type SnapshotReconciliationReceipt struct {
	Version                     string                             `json:"version"`
	TenantID                    string                             `json:"tenant_id"`
	ConnectorID                 string                             `json:"connector_id"`
	SourceID                    string                             `json:"source_id"`
	EventID                     string                             `json:"event_id"`
	EventFingerprint            protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Sequence                    uint64                             `json:"sequence"`
	AuthoritativeSnapshotDigest protocol.ContentDigest             `json:"authoritative_snapshot_digest"`
	SourceWatermark             string                             `json:"source_watermark"`
	ACLWatermark                string                             `json:"acl_watermark"`
	ProjectionBaseDigest        protocol.ContentDigest             `json:"projection_base_digest"`
	ProjectionBaseSequence      uint64                             `json:"projection_base_sequence"`
	PlanDigest                  protocol.ContentDigest             `json:"plan_digest"`
	RequestDigest               protocol.ContentDigest             `json:"request_digest"`
	DerivedTombstones           []ReconciliationTombstone          `json:"derived_tombstones"`
	AppliedAt                   time.Time                          `json:"applied_at"`
}

func (r SnapshotReconciliationReceipt) ValidateFor(
	intent SnapshotReconciliationIntent,
	request ReconciliationApplyRequest,
) error {
	if r.Version != ConnectorCoreVersion || r.TenantID != intent.TenantID || r.ConnectorID != intent.ConnectorID ||
		r.SourceID != intent.SourceID || r.EventID != intent.EventID || r.EventFingerprint != intent.EventFingerprint ||
		r.Sequence != intent.Sequence || r.AuthoritativeSnapshotDigest != intent.AuthoritativeSnapshotDigest ||
		r.SourceWatermark != intent.SourceWatermark || r.ACLWatermark != intent.ACLWatermark ||
		r.ProjectionBaseDigest != intent.ProjectionBaseDigest ||
		r.ProjectionBaseSequence != intent.ProjectionBaseSequence || r.PlanDigest != intent.PlanDigest {
		return fmt.Errorf("snapshot reconciliation receipt does not match its intent")
	}
	requestDigest, err := canonicalContentDigest(request)
	if err != nil {
		return err
	}
	if r.RequestDigest != requestDigest {
		return fmt.Errorf("snapshot reconciliation receipt request digest does not match")
	}
	if !request.AuthoritativeCapturedAt.Equal(intent.AuthoritativeCapturedAt) {
		return fmt.Errorf("snapshot reconciliation request captured_at does not match its intent")
	}
	if err := validateReconciliationTombstoneSet(r.DerivedTombstones, request, requestDigest); err != nil {
		return err
	}
	return validateUTC("applied_at", r.AppliedAt)
}

type ReconciliationReservation struct {
	Version       string                     `json:"version"`
	Request       ReconciliationApplyRequest `json:"request"`
	RequestDigest protocol.ContentDigest     `json:"request_digest"`
	CreatedAt     time.Time                  `json:"created_at"`
}

func (r ReconciliationReservation) Validate() error {
	if err := r.validateBinding(); err != nil {
		return err
	}
	return validateUTC("created_at", r.CreatedAt)
}

func (r ReconciliationReservation) validateBinding() error {
	if r.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported reconciliation reservation version %q", r.Version)
	}
	if err := r.Request.Validate(); err != nil {
		return err
	}
	digest, err := canonicalContentDigest(r.Request)
	if err != nil {
		return err
	}
	if r.RequestDigest != digest {
		return fmt.Errorf("reconciliation reservation digest does not match its request")
	}
	return nil
}

type ReconciliationReservationReceipt struct {
	Version           string                     `json:"version"`
	TenantID          string                     `json:"tenant_id"`
	ConnectorID       string                     `json:"connector_id"`
	SourceID          string                     `json:"source_id"`
	ApplicationOrder  uint64                     `json:"application_order"`
	PlanDigest        protocol.ContentDigest     `json:"plan_digest"`
	RequestDigest     protocol.ContentDigest     `json:"request_digest"`
	Request           ReconciliationApplyRequest `json:"request"`
	DerivedTombstones []ReconciliationTombstone  `json:"derived_tombstones"`
	AppliedAt         time.Time                  `json:"applied_at"`
}

func (r ReconciliationReservationReceipt) ValidateFor(reservation ReconciliationReservation) error {
	if err := reservation.validateBinding(); err != nil {
		return err
	}
	if r.ApplicationOrder == 0 {
		return fmt.Errorf("reconciliation receipt application order is required")
	}
	source := reservation.Request.SourceOwnership
	if r.Version != ConnectorCoreVersion || r.TenantID != source.TenantID ||
		r.ConnectorID != source.ConnectorID || r.SourceID != source.SourceID ||
		r.PlanDigest != reservation.Request.Plan.Digest || r.RequestDigest != reservation.RequestDigest ||
		!reconciliationRequestsEqual(r.Request, reservation.Request) {
		return fmt.Errorf("reconciliation reservation receipt does not match its intent")
	}
	if err := validateReconciliationTombstoneSet(
		r.DerivedTombstones, reservation.Request, reservation.RequestDigest,
	); err != nil {
		return err
	}
	return validateUTC("applied_at", r.AppliedAt)
}

func (r ReconciliationReservationReceipt) Validate() error {
	reservation := ReconciliationReservation{
		Version: ConnectorCoreVersion, Request: r.Request, RequestDigest: r.RequestDigest,
		CreatedAt: r.AppliedAt,
	}
	return r.ValidateFor(reservation)
}

type PublicationIntent struct {
	Version           string                             `json:"version"`
	TenantID          string                             `json:"tenant_id"`
	ConnectorID       string                             `json:"connector_id"`
	SourceID          string                             `json:"source_id"`
	EventID           string                             `json:"event_id"`
	EventFingerprint  protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Sequence          uint64                             `json:"sequence"`
	Eligibility       ServingEligibility                 `json:"eligibility"`
	EligibilityDigest protocol.ContentDigest             `json:"eligibility_digest"`
	CreatedAt         time.Time                          `json:"created_at"`
}

func (i PublicationIntent) Validate() error {
	if i.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported publication intent version %q", i.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", i.TenantID},
		{"connector_id", i.ConnectorID},
		{"source_id", i.SourceID},
		{"event_id", i.EventID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	if err := i.EventFingerprint.Validate(); err != nil {
		return err
	}
	if err := i.Eligibility.Validate(); err != nil {
		return err
	}
	if i.TenantID != i.Eligibility.TenantID || i.ConnectorID != i.Eligibility.ConnectorID ||
		i.EventID != i.Eligibility.EventID || i.EventFingerprint != i.Eligibility.Fingerprint ||
		i.Sequence != i.Eligibility.Sequence {
		return fmt.Errorf("publication intent does not match its eligibility")
	}
	digest, err := canonicalContentDigest(i.Eligibility)
	if err != nil {
		return err
	}
	if i.EligibilityDigest != digest {
		return fmt.Errorf("publication eligibility digest does not match its contents")
	}
	return validateUTC("created_at", i.CreatedAt)
}

type PublicationReceipt struct {
	Version           string                             `json:"version"`
	TenantID          string                             `json:"tenant_id"`
	ConnectorID       string                             `json:"connector_id"`
	SourceID          string                             `json:"source_id"`
	EventID           string                             `json:"event_id"`
	EventFingerprint  protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Sequence          uint64                             `json:"sequence"`
	EligibilityDigest protocol.ContentDigest             `json:"eligibility_digest"`
	SourceWatermark   string                             `json:"source_watermark"`
	ACLWatermark      string                             `json:"acl_watermark"`
	PublishedAt       time.Time                          `json:"published_at"`
}

func (r PublicationReceipt) ValidateFor(intent PublicationIntent) error {
	if r.Version != ConnectorCoreVersion || r.TenantID != intent.TenantID ||
		r.ConnectorID != intent.ConnectorID || r.SourceID != intent.SourceID ||
		r.EventID != intent.EventID || r.EventFingerprint != intent.EventFingerprint ||
		r.Sequence != intent.Sequence || r.EligibilityDigest != intent.EligibilityDigest ||
		r.SourceWatermark != intent.Eligibility.Checkpoint.SourceWatermark ||
		r.ACLWatermark != intent.Eligibility.Checkpoint.ACLWatermark {
		return fmt.Errorf("publication receipt does not match its intent")
	}
	return validateUTC("published_at", r.PublishedAt)
}

func (e ServingEligibility) Validate() error {
	if e.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported serving eligibility version %q", e.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenant_id", e.TenantID},
		{"connector_id", e.ConnectorID},
		{"event_id", e.EventID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	if err := e.Fingerprint.Validate(); err != nil {
		return err
	}
	if err := e.Checkpoint.Validate(); err != nil {
		return err
	}
	if e.TenantID != e.Checkpoint.TenantID || e.ConnectorID != e.Checkpoint.ConnectorID ||
		e.EventID != e.Checkpoint.CommittedEventID || e.Fingerprint != e.Checkpoint.CommittedEventFingerprint ||
		e.Sequence != e.Checkpoint.LastSequence {
		return fmt.Errorf("serving eligibility does not match its checkpoint")
	}
	if err := e.OutputDigest.Validate(); err != nil {
		return err
	}
	if e.ReconciliationTombstones == nil {
		return fmt.Errorf("reconciliation_tombstones must use an explicit empty list")
	}
	var previous protocol.ResourceID
	for index, tombstone := range e.ReconciliationTombstones {
		if err := tombstone.Validate(); err != nil {
			return err
		}
		if index > 0 && tombstone.ResourceID <= previous {
			return fmt.Errorf("reconciliation_tombstones must be sorted and unique")
		}
		previous = tombstone.ResourceID
	}
	return validateUTC("eligible_at", e.EligibleAt)
}

func canonicalContentDigest(value any) (protocol.ContentDigest, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return protocol.NewContentDigest(string(data)), nil
}

func bindReconciliationIdempotencyKey(request *ReconciliationApplyRequest) error {
	if request == nil {
		return fmt.Errorf("reconciliation apply request is required")
	}
	request.IdempotencyKey = ""
	digest, err := canonicalContentDigest(*request)
	if err != nil {
		return err
	}
	request.IdempotencyKey = digest
	return nil
}

func validateReconciliationIdempotencyKey(request ReconciliationApplyRequest) error {
	if err := request.IdempotencyKey.Validate(); err != nil {
		return fmt.Errorf("idempotency_key: %w", err)
	}
	actual := request.IdempotencyKey
	request.IdempotencyKey = ""
	expected, err := canonicalContentDigest(request)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("reconciliation idempotency key does not bind the exact request")
	}
	return nil
}

func reconciliationPlanResourceIDs(plan ReconciliationPlan) []protocol.ResourceID {
	values := make([]protocol.ResourceID, 0,
		len(plan.MissingResources)+len(plan.ChangedResources)+len(plan.StaleResources)+
			len(plan.MissingACLs)+len(plan.ChangedACLs)+len(plan.StaleACLs)+len(plan.TombstonedResources))
	values = append(values, plan.MissingResources...)
	values = append(values, plan.ChangedResources...)
	values = append(values, plan.StaleResources...)
	values = append(values, plan.MissingACLs...)
	values = append(values, plan.ChangedACLs...)
	values = append(values, plan.StaleACLs...)
	values = append(values, plan.TombstonedResources...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func reconciliationRemovalIDs(plan ReconciliationPlan) []protocol.ResourceID {
	values := append([]protocol.ResourceID{}, plan.StaleResources...)
	values = append(values, plan.StaleACLs...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func newReconciliationTombstones(
	request ReconciliationApplyRequest,
	requestDigest protocol.ContentDigest,
) ([]ReconciliationTombstone, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if err := requestDigest.Validate(); err != nil {
		return nil, err
	}
	tombstones := make([]ReconciliationTombstone, 0, len(reconciliationRemovalIDs(request.Plan)))
	for _, resourceID := range reconciliationRemovalIDs(request.Plan) {
		tombstone := ReconciliationTombstone{
			Version: ConnectorCoreVersion, TenantID: request.SourceOwnership.TenantID,
			ConnectorID: request.SourceOwnership.ConnectorID, SourceID: request.SourceOwnership.SourceID,
			ResourceID: resourceID, RequestDigest: requestDigest,
			AuthoritativeSnapshotDigest: request.AuthoritativeSnapshotDigest,
			ProjectedSnapshotDigest:     request.ProjectedSnapshotDigest, PlanDigest: request.Plan.Digest,
			SourceWatermark: request.Plan.SourceWatermark, ACLWatermark: request.Plan.ACLWatermark,
			ProjectionBaseSequence: request.ProjectionBaseSequence, DeletedAt: request.AuthoritativeCapturedAt,
		}
		if request.Snapshot != nil {
			tombstone.SnapshotEventFingerprint = request.Snapshot.EventFingerprint
			tombstone.SnapshotSequence = request.Snapshot.Sequence
		}
		if err := tombstone.ValidateFor(request, requestDigest); err != nil {
			return nil, err
		}
		tombstones = append(tombstones, tombstone)
	}
	return tombstones, nil
}

func validateReconciliationTombstoneSet(
	tombstones []ReconciliationTombstone,
	request ReconciliationApplyRequest,
	requestDigest protocol.ContentDigest,
) error {
	if tombstones == nil {
		return fmt.Errorf("derived_tombstones must use an explicit empty list")
	}
	expected := reconciliationRemovalIDs(request.Plan)
	if len(tombstones) != len(expected) {
		return fmt.Errorf("derived reconciliation tombstones do not match authoritative removals")
	}
	for index, tombstone := range tombstones {
		if tombstone.ResourceID != expected[index] {
			return fmt.Errorf("derived reconciliation tombstones must be sorted and exact")
		}
		if err := tombstone.ValidateFor(request, requestDigest); err != nil {
			return err
		}
		if !tombstone.DeletedAt.Equal(request.AuthoritativeCapturedAt) {
			return fmt.Errorf("derived reconciliation tombstone time does not match its authoritative snapshot")
		}
	}
	return nil
}

func reconciliationRequestsEqual(first, second ReconciliationApplyRequest) bool {
	firstJSON, firstErr := json.Marshal(first)
	secondJSON, secondErr := json.Marshal(second)
	return firstErr == nil && secondErr == nil && bytes.Equal(firstJSON, secondJSON)
}

func cloneReconciliationTombstones(values []ReconciliationTombstone) []ReconciliationTombstone {
	return append([]ReconciliationTombstone{}, values...)
}
