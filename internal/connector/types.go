package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	ConnectorCoreVersion = protocol.EnterpriseContractVersion
	DefaultMaxAttempts   = uint32(3)
	maximumMaxAttempts   = uint32(100)
)

var (
	ErrNotRegistered                   = errors.New("connector is not registered")
	ErrRegistrationConflict            = errors.New("connector registration conflicts with persisted ownership")
	ErrOwnershipMismatch               = errors.New("connector ownership does not match")
	ErrJournalConflict                 = errors.New("connector journal conflicts with persisted state")
	ErrSequenceGap                     = errors.New("connector event leaves a sequence gap")
	ErrStaleEvent                      = errors.New("connector event is older than the authoritative checkpoint")
	ErrPendingEvent                    = errors.New("connector has an unfinished event")
	ErrDeadLettered                    = errors.New("connector event is dead-lettered")
	ErrStoreIntegrity                  = errors.New("connector store integrity check failed")
	ErrTombstoneResurrection           = errors.New("connector event would resurrect a tombstoned resource")
	ErrNotServingEligible              = errors.New("connector event is not serving eligible")
	ErrSnapshotReconciliationRequired  = errors.New("snapshot completion requires durable reconciliation")
	ErrReconciliationProjectorRequired = errors.New("snapshot reconciliation projector is required")
	ErrPublisherRequired               = errors.New("connector publisher is required")
	ErrPublicationOrder                = errors.New("connector publication is not the exact next eligible sequence")
	ErrStalePublication                = errors.New("connector publication sequence is already published")
	ErrPublicationConflict             = errors.New("connector publication conflicts with durable intent")
	ErrResourceOwnership               = errors.New("resource is owned by another connector source")
	ErrResourceOwnershipRequired       = errors.New("resource has no connector source ownership")
	ErrPendingReconciliation           = errors.New("connector has a pending reconciliation")
	ErrProjectionBaseMismatch          = errors.New("projection snapshot base does not match the connector checkpoint")
)

// ConnectorRef is the trusted handle required for every connector operation.
// OwnerID is operator/configuration input, never connector-controlled input.
type ConnectorRef struct {
	Scope       protocol.TenantScope `json:"scope"`
	ConnectorID string               `json:"connector_id"`
	OwnerID     string               `json:"owner_id"`
}

func (r ConnectorRef) Validate() error {
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if err := validateOpaqueID("connector_id", r.ConnectorID); err != nil {
		return err
	}
	return validateOpaqueID("owner_id", r.OwnerID)
}

type Registration struct {
	Version      string               `json:"version"`
	Scope        protocol.TenantScope `json:"scope"`
	ConnectorID  string               `json:"connector_id"`
	OwnerID      string               `json:"owner_id"`
	SourceID     string               `json:"source_id"`
	RegisteredAt time.Time            `json:"registered_at"`
}

func (r Registration) Validate() error {
	if r.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported connector registration version %q", r.Version)
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"connector_id", r.ConnectorID},
		{"owner_id", r.OwnerID},
		{"source_id", r.SourceID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}
	return validateUTC("registered_at", r.RegisteredAt)
}

func (r Registration) Ref() ConnectorRef {
	return ConnectorRef{Scope: r.Scope, ConnectorID: r.ConnectorID, OwnerID: r.OwnerID}
}

func (r Registration) ValidateRef(ref ConnectorRef) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if r.Scope != ref.Scope || r.ConnectorID != ref.ConnectorID || r.OwnerID != ref.OwnerID {
		return ErrOwnershipMismatch
	}
	return nil
}

type PipelineStage string

const (
	StageAppend             PipelineStage = "append"
	StageApply              PipelineStage = "apply"
	StageReceipt            PipelineStage = "receipt"
	StageCheckpoint         PipelineStage = "checkpoint"
	StageServingEligibility PipelineStage = "serving_eligibility"
	StageReconciliation     PipelineStage = "reconciliation"
	StagePublicationIntent  PipelineStage = "publication_intent"
	StagePublished          PipelineStage = "published"
	StageDeadLetter         PipelineStage = "dead_letter"
)

func (s PipelineStage) Validate() error {
	switch s {
	case StageAppend, StageApply, StageReceipt, StageCheckpoint, StageServingEligibility,
		StageReconciliation, StagePublicationIntent, StagePublished, StageDeadLetter:
		return nil
	default:
		return fmt.Errorf("unsupported connector pipeline stage %q", s)
	}
}

func failureStageForEvent(event protocol.ConnectorEventEnvelope) PipelineStage {
	if event.Kind == protocol.ConnectorSnapshotComplete {
		return StageReconciliation
	}
	return StageApply
}

type FaultPoint string

const (
	FaultBeforeAppend                FaultPoint = "before_append"
	FaultAfterAppend                 FaultPoint = "after_append"
	FaultBeforeApply                 FaultPoint = "before_apply"
	FaultAfterApply                  FaultPoint = "after_apply"
	FaultBeforeReceipt               FaultPoint = "before_receipt"
	FaultAfterReceipt                FaultPoint = "after_receipt"
	FaultBeforeCheckpoint            FaultPoint = "before_checkpoint"
	FaultAfterCheckpoint             FaultPoint = "after_checkpoint"
	FaultBeforeServingEligibility    FaultPoint = "before_serving_eligibility"
	FaultAfterServingEligibility     FaultPoint = "after_serving_eligibility"
	FaultBeforeDeadLetter            FaultPoint = "before_dead_letter"
	FaultAfterDeadLetter             FaultPoint = "after_dead_letter"
	FaultBeforeReconciliation        FaultPoint = "before_reconciliation"
	FaultAfterReconciliation         FaultPoint = "after_reconciliation"
	FaultBeforeReconciliationReceipt FaultPoint = "before_reconciliation_receipt"
	FaultAfterReconciliationReceipt  FaultPoint = "after_reconciliation_receipt"
	FaultBeforePublish               FaultPoint = "before_publish"
	FaultAfterPublish                FaultPoint = "after_publish"
	FaultBeforePublicationIntent     FaultPoint = "before_publication_intent"
	FaultAfterPublicationIntent      FaultPoint = "after_publication_intent"
	FaultBeforePublicationReceipt    FaultPoint = "before_publication_receipt"
	FaultAfterPublicationReceipt     FaultPoint = "after_publication_receipt"
)

type FaultInjector interface {
	Inject(FaultPoint, protocol.ConnectorEventEnvelope) error
}

type FaultInjectorFunc func(FaultPoint, protocol.ConnectorEventEnvelope) error

func (f FaultInjectorFunc) Inject(point FaultPoint, event protocol.ConnectorEventEnvelope) error {
	return f(point, event)
}

type RetryPolicy struct {
	MaxAttempts uint32 `json:"max_attempts"`
}

func (p RetryPolicy) Validate() error {
	if p.MaxAttempts == 0 || p.MaxAttempts > maximumMaxAttempts {
		return fmt.Errorf("max_attempts must be between 1 and %d", maximumMaxAttempts)
	}
	return nil
}

type ProjectionComponentState string

const (
	ProjectionPending   ProjectionComponentState = "pending"
	ProjectionSucceeded ProjectionComponentState = "succeeded"
	ProjectionFailed    ProjectionComponentState = "failed"
)

func (s ProjectionComponentState) Validate() error {
	switch s {
	case ProjectionPending, ProjectionSucceeded, ProjectionFailed:
		return nil
	default:
		return fmt.Errorf("unsupported projection component state %q", s)
	}
}

// ProjectionStatus is deliberately explicit. Every component must be
// confirmed before a content or ACL event can become serving eligible.
type ProjectionStatus struct {
	Content         ProjectionComponentState `json:"content"`
	ACL             ProjectionComponentState `json:"acl"`
	Catalog         ProjectionComponentState `json:"catalog"`
	Graph           ProjectionComponentState `json:"graph"`
	Index           ProjectionComponentState `json:"index"`
	Tuples          ProjectionComponentState `json:"tuples"`
	Cache           ProjectionComponentState `json:"cache"`
	Citations       ProjectionComponentState `json:"citations"`
	SessionEvidence ProjectionComponentState `json:"session_evidence"`
}

func SucceededProjectionStatus() ProjectionStatus {
	return ProjectionStatus{
		Content: ProjectionSucceeded, ACL: ProjectionSucceeded, Catalog: ProjectionSucceeded,
		Graph: ProjectionSucceeded, Index: ProjectionSucceeded, Tuples: ProjectionSucceeded,
		Cache: ProjectionSucceeded, Citations: ProjectionSucceeded, SessionEvidence: ProjectionSucceeded,
	}
}

func (s ProjectionStatus) Validate() error {
	components := []struct {
		name  string
		state ProjectionComponentState
	}{
		{"content", s.Content},
		{"acl", s.ACL},
		{"catalog", s.Catalog},
		{"graph", s.Graph},
		{"index", s.Index},
		{"tuples", s.Tuples},
		{"cache", s.Cache},
		{"citations", s.Citations},
		{"session_evidence", s.SessionEvidence},
	}
	for _, component := range components {
		if err := component.state.Validate(); err != nil {
			return fmt.Errorf("%s projection: %w", component.name, err)
		}
	}
	return nil
}

func (s ProjectionStatus) Ready() bool {
	return s == SucceededProjectionStatus()
}

type ApplyRequest struct {
	Version           string                             `json:"version"`
	Event             protocol.ConnectorEventEnvelope    `json:"event"`
	EventFingerprint  protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Attempt           uint32                             `json:"attempt"`
	SourceOwnership   SourceOwnership                    `json:"source_ownership"`
	ResourceOwnership ResourceOwnership                  `json:"resource_ownership"`
	Tombstone         *protocol.ConnectorTombstone       `json:"tombstone,omitempty"`
}

func (r ApplyRequest) Validate() error {
	if r.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported connector apply request version %q", r.Version)
	}
	if err := r.Event.Validate(); err != nil {
		return err
	}
	expected, err := protocol.NewConnectorEventFingerprint(r.Event)
	if err != nil {
		return err
	}
	if r.EventFingerprint != expected {
		return fmt.Errorf("connector apply request fingerprint does not match the event")
	}
	if r.Attempt == 0 {
		return fmt.Errorf("connector apply attempt must be greater than zero")
	}
	if r.Event.Kind == protocol.ConnectorSnapshotComplete {
		return ErrSnapshotReconciliationRequired
	}
	if err := r.SourceOwnership.ValidateForEvent(r.Event); err != nil {
		return err
	}
	if err := r.ResourceOwnership.ValidateForEvent(r.Event, r.SourceOwnership); err != nil {
		return err
	}
	if r.Event.Kind == protocol.ConnectorResourceTombstone {
		if r.Tombstone == nil {
			return fmt.Errorf("tombstone event requires an apply tombstone")
		}
		if err := r.Tombstone.ValidateFor(r.Event); err != nil {
			return err
		}
	} else if r.Tombstone != nil {
		return fmt.Errorf("non-tombstone event must not contain an apply tombstone")
	}
	return nil
}

type ApplyResult struct {
	Version          string                             `json:"version"`
	TenantID         string                             `json:"tenant_id"`
	ConnectorID      string                             `json:"connector_id"`
	EventID          string                             `json:"event_id"`
	EventFingerprint protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	IdempotencyKey   string                             `json:"idempotency_key"`
	Sequence         uint64                             `json:"sequence"`
	OutputDigest     protocol.ContentDigest             `json:"output_digest"`
	Status           ProjectionStatus                   `json:"status"`
}

func NewSuccessfulApplyResult(request ApplyRequest, outputDigest protocol.ContentDigest) (ApplyResult, error) {
	if err := request.Validate(); err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{
		Version: ConnectorCoreVersion, TenantID: request.Event.TenantID,
		ConnectorID: request.Event.ConnectorID, EventID: request.Event.EventID,
		EventFingerprint: request.EventFingerprint, IdempotencyKey: request.Event.IdempotencyKey,
		Sequence: request.Event.Sequence, OutputDigest: outputDigest, Status: SucceededProjectionStatus(),
	}
	if err := result.ValidateFor(request); err != nil {
		return ApplyResult{}, err
	}
	return result, nil
}

func (r ApplyResult) ValidateFor(request ApplyRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if r.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported connector apply result version %q", r.Version)
	}
	if r.TenantID != request.Event.TenantID || r.ConnectorID != request.Event.ConnectorID ||
		r.EventID != request.Event.EventID || r.EventFingerprint != request.EventFingerprint ||
		r.IdempotencyKey != request.Event.IdempotencyKey || r.Sequence != request.Event.Sequence {
		return fmt.Errorf("connector apply result does not match the request")
	}
	if err := r.OutputDigest.Validate(); err != nil {
		return fmt.Errorf("output_digest: %w", err)
	}
	if err := r.Status.Validate(); err != nil {
		return err
	}
	if !r.Status.Ready() {
		return fmt.Errorf("connector apply result is not ready for checkpoint")
	}
	return nil
}

// Projector implementations must honor the event idempotency key and the
// stable attempt number. An ambiguous restart can invoke the same request more
// than once before its durable receipt exists.
type Projector interface {
	Apply(context.Context, ApplyRequest) (ApplyResult, error)
}

type ProjectorFunc func(context.Context, ApplyRequest) (ApplyResult, error)

func (f ProjectorFunc) Apply(ctx context.Context, request ApplyRequest) (ApplyResult, error) {
	return f(ctx, request)
}

// ApplyError controls bounded retry without persisting provider error text.
// Only Code and Retryable enter the durable control plane.
type ApplyError struct {
	Code      string
	Retryable bool
	Err       error
}

func (e *ApplyError) Error() string {
	if e == nil {
		return "connector apply error"
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}

func (e *ApplyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type JournalEntry struct {
	Version                string                             `json:"version"`
	Event                  protocol.ConnectorEventEnvelope    `json:"event"`
	EventFingerprint       protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	SnapshotReconciliation *SnapshotReconciliationIntent      `json:"snapshot_reconciliation,omitempty"`
	AppendedAt             time.Time                          `json:"appended_at"`
}

func (e JournalEntry) ValidateFor(ref ConnectorRef) error {
	if e.Version != ConnectorCoreVersion {
		return fmt.Errorf("unsupported connector journal entry version %q", e.Version)
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := e.Event.ValidateFor(ref.Scope); err != nil {
		return err
	}
	if e.Event.ConnectorID != ref.ConnectorID {
		return fmt.Errorf("connector journal entry crosses the connector scope")
	}
	fingerprint, err := protocol.NewConnectorEventFingerprint(e.Event)
	if err != nil {
		return err
	}
	if e.EventFingerprint != fingerprint {
		return fmt.Errorf("connector journal entry fingerprint does not match the event")
	}
	if e.Event.Kind == protocol.ConnectorSnapshotComplete {
		if e.SnapshotReconciliation == nil {
			return ErrSnapshotReconciliationRequired
		}
		if err := e.SnapshotReconciliation.ValidateForEvent(e.Event); err != nil {
			return err
		}
	} else if e.SnapshotReconciliation != nil {
		return fmt.Errorf("non-snapshot event contains snapshot reconciliation intent")
	}
	return validateUTC("appended_at", e.AppendedAt)
}

type ApplyAttempt struct {
	Version          string                             `json:"version"`
	TenantID         string                             `json:"tenant_id"`
	ConnectorID      string                             `json:"connector_id"`
	EventID          string                             `json:"event_id"`
	EventFingerprint protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Attempt          uint32                             `json:"attempt"`
	StartedAt        time.Time                          `json:"started_at"`
}

type ApplyFailureRecord struct {
	Version          string                             `json:"version"`
	TenantID         string                             `json:"tenant_id"`
	ConnectorID      string                             `json:"connector_id"`
	EventID          string                             `json:"event_id"`
	EventFingerprint protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Attempt          uint32                             `json:"attempt"`
	ErrorCode        string                             `json:"error_code"`
	Retryable        bool                               `json:"retryable"`
	FailedAt         time.Time                          `json:"failed_at"`
}

type DeliveryRecord struct {
	Version           string                            `json:"version"`
	Receipt           protocol.ConnectorDeliveryReceipt `json:"receipt"`
	Result            ApplyResult                       `json:"result"`
	SourceOwnership   SourceOwnership                   `json:"source_ownership"`
	ResourceOwnership ResourceOwnership                 `json:"resource_ownership"`
	Tombstone         *protocol.ConnectorTombstone      `json:"tombstone,omitempty"`
}

type DeadLetter struct {
	Version  string                            `json:"version"`
	Event    protocol.ConnectorEventEnvelope   `json:"event"`
	Receipt  protocol.ConnectorDeliveryReceipt `json:"receipt"`
	Stage    PipelineStage                     `json:"failed_stage"`
	Failures []ApplyFailureRecord              `json:"failures"`
}

type ServingEligibility struct {
	Version                  string                             `json:"version"`
	TenantID                 string                             `json:"tenant_id"`
	ConnectorID              string                             `json:"connector_id"`
	EventID                  string                             `json:"event_id"`
	Fingerprint              protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Sequence                 uint64                             `json:"sequence"`
	Checkpoint               protocol.ConnectorCheckpoint       `json:"checkpoint"`
	OutputDigest             protocol.ContentDigest             `json:"output_digest"`
	Tombstone                *protocol.ConnectorTombstone       `json:"tombstone,omitempty"`
	ReconciliationTombstones []ReconciliationTombstone          `json:"reconciliation_tombstones"`
	EligibleAt               time.Time                          `json:"eligible_at"`
}

// Publisher must be idempotent by EventFingerprint. A crash can occur after
// external publication succeeds but before the durable receipt is written.
type Publisher interface {
	Publish(context.Context, PublicationIntent) error
}

type PublisherFunc func(context.Context, PublicationIntent) error

func (f PublisherFunc) Publish(ctx context.Context, intent PublicationIntent) error {
	return f(ctx, intent)
}

type ServingCursor struct {
	Sequence        uint64                             `json:"sequence"`
	EventID         string                             `json:"event_id"`
	Fingerprint     protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	SourceWatermark string                             `json:"source_watermark"`
	ACLWatermark    string                             `json:"acl_watermark"`
	PublishedAt     time.Time                          `json:"published_at"`
}

type DeadLetterCursor struct {
	Sequence    uint64                             `json:"sequence"`
	EventID     string                             `json:"event_id"`
	Fingerprint protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Attempts    uint32                             `json:"attempts"`
	ErrorCode   string                             `json:"error_code"`
	HandledAt   time.Time                          `json:"handled_at"`
}

type Cursor struct {
	Version          string                        `json:"version"`
	TenantID         string                        `json:"tenant_id"`
	ConnectorID      string                        `json:"connector_id"`
	AppendedSequence uint64                        `json:"appended_sequence"`
	Checkpoint       *protocol.ConnectorCheckpoint `json:"checkpoint,omitempty"`
	Serving          *ServingCursor                `json:"serving,omitempty"`
	Blocked          *DeadLetterCursor             `json:"blocked,omitempty"`
}

type ProcessResult struct {
	Event          protocol.ConnectorEventEnvelope
	Fingerprint    protocol.ConnectorEventFingerprint
	Receipt        *protocol.ConnectorDeliveryReceipt
	Checkpoint     *protocol.ConnectorCheckpoint
	Eligibility    *ServingEligibility
	Reconciliation *SnapshotReconciliationReceipt
	Publication    *PublicationReceipt
	Idempotent     bool
	DeadLetter     bool
}

type ReplayEvent struct {
	Event          protocol.ConnectorEventEnvelope    `json:"event"`
	Fingerprint    protocol.ConnectorEventFingerprint `json:"event_fingerprint"`
	Stage          PipelineStage                      `json:"stage"`
	Attempts       uint32                             `json:"attempts"`
	ErrorCode      string                             `json:"error_code,omitempty"`
	ProjectionHash protocol.ContentDigest             `json:"projection_digest,omitempty"`
}

type ReplayResourceState string

const (
	ReplayResourceActive     ReplayResourceState = "active"
	ReplayResourceTombstoned ReplayResourceState = "tombstoned"
)

type ReplayResource struct {
	ResourceID              protocol.ResourceID          `json:"resource_id"`
	State                   ReplayResourceState          `json:"state"`
	LastSequence            uint64                       `json:"last_sequence"`
	SourceWatermark         string                       `json:"source_watermark"`
	ACLWatermark            string                       `json:"acl_watermark"`
	ContentDigest           protocol.ContentDigest       `json:"content_digest,omitempty"`
	ACLDigest               protocol.ContentDigest       `json:"acl_digest,omitempty"`
	Tombstone               *protocol.ConnectorTombstone `json:"tombstone,omitempty"`
	ReconciliationTombstone *ReconciliationTombstone     `json:"reconciliation_tombstone,omitempty"`
}

type ReplayCursor struct {
	AppendedSequence   uint64 `json:"appended_sequence"`
	CheckpointSequence uint64 `json:"checkpoint_sequence"`
	ServingSequence    uint64 `json:"serving_sequence"`
	BlockedSequence    uint64 `json:"blocked_sequence,omitempty"`
	SourceWatermark    string `json:"source_watermark,omitempty"`
	ACLWatermark       string `json:"acl_watermark,omitempty"`
}

type ReplayReport struct {
	Version     string                 `json:"version"`
	TenantID    string                 `json:"tenant_id"`
	ConnectorID string                 `json:"connector_id"`
	Events      []ReplayEvent          `json:"events"`
	Resources   []ReplayResource       `json:"resources"`
	Cursor      ReplayCursor           `json:"cursor"`
	Digest      protocol.ContentDigest `json:"digest"`
}

func validateOpaqueID(name, value string) error {
	if value == "" || len(value) > 128 {
		return fmt.Errorf("%s is empty or too long", name)
	}
	for index, character := range []byte(value) {
		allowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' ||
			character == ':' || character == '@'
		if !allowed || index == 0 && !isASCIIAlphaNumeric(character) {
			return fmt.Errorf("%s must be a canonical opaque identifier", name)
		}
	}
	return nil
}

func validateErrorCode(value string) error {
	if err := validateOpaqueID("error_code", value); err != nil {
		return err
	}
	if strings.ContainsAny(value, ".:@") {
		return fmt.Errorf("error_code must use alphanumeric, dash, or underscore characters")
	}
	return nil
}

func validateUTC(name string, value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("%s is required", name)
	}
	_, offset := value.Zone()
	if offset != 0 {
		return fmt.Errorf("%s must be UTC", name)
	}
	return nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}
