package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

var (
	ErrRevisionSkew        = errors.New("authorization revision skew")
	ErrReconciliation      = errors.New("authorization reconciliation failed")
	ErrRegrantRevision     = errors.New("authorization regrant requires a newer revision")
	ErrRevisionUnavailable = errors.New("authorization revision unavailable")
	ErrRevisionPending     = errors.New("authorization revision update is already pending")
)

// AuthorizationRevision is the complete published authorization snapshot.
// Epoch is monotonic within one OpenFGA store; the other fields are the exact
// values that must be copied into new authorization contexts.
type AuthorizationRevision struct {
	StoreID              string `json:"store_id"`
	AuthorizationModelID string `json:"authorization_model_id"`
	IdentityWatermark    string `json:"identity_watermark"`
	ACLWatermark         string `json:"acl_watermark"`
	Epoch                uint64 `json:"epoch"`
}

func (r AuthorizationRevision) Validate() error {
	if err := validateStoreID(r.StoreID); err != nil {
		return err
	}
	if err := validateModelID(r.AuthorizationModelID); err != nil {
		return err
	}
	if err := validateToken("identity_watermark", r.IdentityWatermark); err != nil {
		return err
	}
	if err := validateToken("acl_watermark", r.ACLWatermark); err != nil {
		return err
	}
	if r.Epoch == 0 {
		return fmt.Errorf("%w: authorization epoch must be positive", ErrInvalidRequest)
	}
	return nil
}

func (r AuthorizationRevision) validateAdvance(base AuthorizationRevision) error {
	if err := base.Validate(); err != nil {
		return fmt.Errorf("base revision: %w", err)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("target revision: %w", err)
	}
	if r.StoreID != base.StoreID {
		return fmt.Errorf("%w: authorization revision cannot change stores", ErrInvalidRequest)
	}
	if r.Epoch <= base.Epoch {
		return fmt.Errorf("%w: target epoch %d is not newer than %d", ErrRegrantRevision, r.Epoch, base.Epoch)
	}
	return nil
}

// TupleReconciliationPlan is a deterministic, content-free delta between two
// Catalog Claim tuple projections.
type TupleReconciliationPlan struct {
	Current            CatalogTupleProjection `json:"current"`
	Desired            CatalogTupleProjection `json:"desired"`
	BaseRevision       AuthorizationRevision  `json:"base_revision"`
	TargetRevision     AuthorizationRevision  `json:"target_revision"`
	Writes             []CatalogTupleBinding  `json:"writes"`
	Deletes            []CatalogTupleBinding  `json:"deletes"`
	RetiredResourceIDs []protocol.ResourceID  `json:"retired_resource_ids,omitempty"`
	GrantedResourceIDs []protocol.ResourceID  `json:"granted_resource_ids,omitempty"`
}

func (p TupleReconciliationPlan) Validate() error {
	if err := p.Current.Validate(); err != nil {
		return fmt.Errorf("current tuple projection: %w", err)
	}
	if err := p.Desired.Validate(); err != nil {
		return fmt.Errorf("desired tuple projection: %w", err)
	}
	if err := p.BaseRevision.Validate(); err != nil {
		return fmt.Errorf("base revision: %w", err)
	}
	if err := p.TargetRevision.Validate(); err != nil {
		return fmt.Errorf("target revision: %w", err)
	}
	if err := validateCanonicalTupleBindings("writes", p.Writes); err != nil {
		return err
	}
	if err := validateCanonicalTupleBindings("deletes", p.Deletes); err != nil {
		return err
	}
	deletes := make(map[Tuple]struct{}, len(p.Deletes))
	for _, binding := range p.Deletes {
		deletes[binding.Tuple] = struct{}{}
	}
	for _, binding := range p.Writes {
		if _, overlap := deletes[binding.Tuple]; overlap {
			return fmt.Errorf("%w: tuple cannot be both written and deleted", ErrInvalidRequest)
		}
	}
	wantWrites, wantDeletes, err := catalogTupleProjectionDelta(p.Current, p.Desired)
	if err != nil {
		return err
	}
	if !catalogTupleBindingSlicesEqual(wantWrites, p.Writes) ||
		!catalogTupleBindingSlicesEqual(wantDeletes, p.Deletes) {
		return fmt.Errorf("%w: tuple changes do not match the bound Catalog projections", ErrInvalidRequest)
	}
	wantRetired := resourceIDsFromBindings(p.Deletes)
	if !resourceIDSlicesEqual(wantRetired, p.RetiredResourceIDs) {
		return fmt.Errorf("%w: retired resource IDs do not match tuple deletes", ErrInvalidRequest)
	}
	wantGranted := resourceIDsFromBindings(p.Writes)
	if !resourceIDSlicesEqual(wantGranted, p.GrantedResourceIDs) {
		return fmt.Errorf("%w: granted resource IDs do not match tuple writes", ErrInvalidRequest)
	}

	hasChanges := len(p.Writes) > 0 || len(p.Deletes) > 0
	if p.TargetRevision == p.BaseRevision {
		if hasChanges {
			return fmt.Errorf("%w: tuple changes require a newer authorization revision", ErrRegrantRevision)
		}
		return nil
	}
	if err := p.TargetRevision.validateAdvance(p.BaseRevision); err != nil {
		return err
	}
	if hasChanges && p.TargetRevision.ACLWatermark == p.BaseRevision.ACLWatermark {
		return fmt.Errorf("%w: tuple changes require a newer ACL watermark", ErrRegrantRevision)
	}
	return nil
}

func (p TupleReconciliationPlan) IsNoop() bool {
	return len(p.Writes) == 0 && len(p.Deletes) == 0 && p.TargetRevision == p.BaseRevision
}

// PlanCatalogTupleReconciliation computes additions, removals, and changes.
// Repeated calls with equal inputs return byte-for-byte equivalent plans.
func PlanCatalogTupleReconciliation(
	current CatalogTupleProjection,
	desired CatalogTupleProjection,
	base AuthorizationRevision,
	target AuthorizationRevision,
) (TupleReconciliationPlan, error) {
	if err := current.Validate(); err != nil {
		return TupleReconciliationPlan{}, fmt.Errorf("current tuple projection: %w", err)
	}
	if err := desired.Validate(); err != nil {
		return TupleReconciliationPlan{}, fmt.Errorf("desired tuple projection: %w", err)
	}

	writes, deletes, err := catalogTupleProjectionDelta(current, desired)
	if err != nil {
		return TupleReconciliationPlan{}, err
	}

	plan := TupleReconciliationPlan{
		Current:            current,
		Desired:            desired,
		BaseRevision:       base,
		TargetRevision:     target,
		Writes:             writes,
		Deletes:            deletes,
		RetiredResourceIDs: resourceIDsFromBindings(deletes),
		GrantedResourceIDs: resourceIDsFromBindings(writes),
	}
	if err := plan.Validate(); err != nil {
		return TupleReconciliationPlan{}, err
	}
	return plan, nil
}

func catalogTupleProjectionDelta(
	current CatalogTupleProjection,
	desired CatalogTupleProjection,
) ([]CatalogTupleBinding, []CatalogTupleBinding, error) {
	currentByTuple := make(map[Tuple]CatalogTupleBinding, len(current.Bindings))
	for _, binding := range current.Bindings {
		currentByTuple[binding.Tuple] = binding
	}
	desiredByTuple := make(map[Tuple]CatalogTupleBinding, len(desired.Bindings))
	for _, binding := range desired.Bindings {
		desiredByTuple[binding.Tuple] = binding
	}

	writes := make([]CatalogTupleBinding, 0)
	deletes := make([]CatalogTupleBinding, 0)
	for tuple, binding := range currentByTuple {
		candidate, retained := desiredByTuple[tuple]
		if retained {
			if candidate.ResourceID != binding.ResourceID {
				return nil, nil, fmt.Errorf(
					"%w: retained tuple changed its opaque Catalog resource identity",
					ErrInvalidRequest,
				)
			}
			continue
		}
		deletes = append(deletes, binding)
	}
	for tuple, binding := range desiredByTuple {
		if _, retained := currentByTuple[tuple]; !retained {
			writes = append(writes, binding)
		}
	}
	sort.Slice(writes, func(i, j int) bool { return catalogTupleBindingLess(writes[i], writes[j]) })
	sort.Slice(deletes, func(i, j int) bool { return catalogTupleBindingLess(deletes[i], deletes[j]) })
	return writes, deletes, nil
}

func catalogTupleBindingSlicesEqual(left, right []CatalogTupleBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateCanonicalTupleBindings(name string, bindings []CatalogTupleBinding) error {
	seen := make(map[Tuple]struct{}, len(bindings))
	for index, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("%s binding %d: %w", name, index, err)
		}
		if index > 0 && catalogTupleBindingLess(binding, bindings[index-1]) {
			return fmt.Errorf("%w: %s are not in canonical order", ErrInvalidRequest, name)
		}
		if _, duplicate := seen[binding.Tuple]; duplicate {
			return fmt.Errorf("%w: %s contain a duplicate tuple", ErrInvalidRequest, name)
		}
		seen[binding.Tuple] = struct{}{}
	}
	return nil
}

func resourceIDsFromBindings(bindings []CatalogTupleBinding) []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{}, len(bindings))
	for _, binding := range bindings {
		seen[binding.ResourceID] = struct{}{}
	}
	resourceIDs := make([]protocol.ResourceID, 0, len(seen))
	for resourceID := range seen {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Slice(resourceIDs, func(i, j int) bool { return resourceIDs[i] < resourceIDs[j] })
	return resourceIDs
}

func resourceIDSlicesEqual(left, right []protocol.ResourceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type TupleWriteRequest struct {
	StoreID              string  `json:"store_id"`
	AuthorizationModelID string  `json:"authorization_model_id"`
	Writes               []Tuple `json:"writes,omitempty"`
	Deletes              []Tuple `json:"deletes,omitempty"`
}

func (r TupleWriteRequest) Validate() error {
	if err := validateStoreID(r.StoreID); err != nil {
		return err
	}
	if err := validateModelID(r.AuthorizationModelID); err != nil {
		return err
	}
	seen := make(map[Tuple]string, len(r.Writes)+len(r.Deletes))
	groups := []struct {
		name   string
		tuples []Tuple
	}{
		{name: "deletes", tuples: r.Deletes},
		{name: "writes", tuples: r.Writes},
	}
	for _, group := range groups {
		name, tuples := group.name, group.tuples
		for index, tuple := range tuples {
			if err := tuple.Validate(); err != nil {
				return fmt.Errorf("%s tuple %d: %w", name, index, err)
			}
			if index > 0 && tupleLess(tuple, tuples[index-1]) {
				return fmt.Errorf("%w: %s are not in canonical order", ErrInvalidRequest, name)
			}
			if existing, duplicate := seen[tuple]; duplicate {
				return fmt.Errorf("%w: tuple appears in both %s and %s operations or is duplicated", ErrInvalidRequest, existing, name)
			}
			seen[tuple] = name
		}
	}
	return nil
}

type TupleWriter interface {
	ApplyTupleChanges(context.Context, TupleWriteRequest) error
}

type TupleWriterFunc func(context.Context, TupleWriteRequest) error

func (f TupleWriterFunc) ApplyTupleChanges(ctx context.Context, request TupleWriteRequest) error {
	if f == nil {
		return fmt.Errorf("%w: tuple writer is not initialized", ErrInvalidRequest)
	}
	return f(ctx, request)
}

type RevisionPublisher interface {
	Current(context.Context) (AuthorizationRevision, error)
	Reserve(context.Context, AuthorizationRevision, AuthorizationRevision) (RevisionReservation, error)
	Publish(context.Context, RevisionReservation) error
	Abort(RevisionReservation)
}

type RevisionReservation struct {
	ID       string                `json:"id"`
	Expected AuthorizationRevision `json:"expected"`
	Target   AuthorizationRevision `json:"target"`
}

func (r RevisionReservation) Validate() error {
	if err := validateToken("revision reservation ID", r.ID); err != nil {
		return err
	}
	return r.Target.validateAdvance(r.Expected)
}

type ReconciliationOutcome string

const (
	ReconciliationSucceeded ReconciliationOutcome = "succeeded"
	ReconciliationNoop      ReconciliationOutcome = "noop"
	ReconciliationFailed    ReconciliationOutcome = "failed"
)

// ReconciliationReport contains operational counts and revision epochs only.
// It deliberately excludes tuples, principals, authorization objects, and
// Catalog resource identifiers.
type ReconciliationReport struct {
	Outcome                  ReconciliationOutcome `json:"outcome"`
	BaseEpoch                uint64                `json:"base_epoch"`
	TargetEpoch              uint64                `json:"target_epoch"`
	WriteCount               int                   `json:"write_count"`
	DeleteCount              int                   `json:"delete_count"`
	InvalidatedResourceCount int                   `json:"invalidated_resource_count"`
	GrantedResourceCount     int                   `json:"granted_resource_count"`
	RevisionPublished        bool                  `json:"revision_published"`
}

type TupleReconciler struct {
	mu        sync.Mutex
	writer    TupleWriter
	revisions RevisionPublisher
	lifecycle RevocationLifecycle
	telemetry telemetry.Sink
}

type TupleReconcilerOptions struct {
	Telemetry telemetry.Sink
}

func NewTupleReconciler(
	writer TupleWriter,
	revisions RevisionPublisher,
	lifecycle RevocationLifecycle,
) (*TupleReconciler, error) {
	return NewTupleReconcilerWithOptions(writer, revisions, lifecycle, TupleReconcilerOptions{})
}

func NewTupleReconcilerWithOptions(
	writer TupleWriter,
	revisions RevisionPublisher,
	lifecycle RevocationLifecycle,
	options TupleReconcilerOptions,
) (*TupleReconciler, error) {
	if writer == nil || revisions == nil || lifecycle == nil {
		return nil, fmt.Errorf("%w: tuple reconciler dependencies are required", ErrInvalidRequest)
	}
	if options.Telemetry == nil {
		options.Telemetry = telemetry.NopSink{}
	}
	return &TupleReconciler{
		writer: writer, revisions: revisions, lifecycle: lifecycle, telemetry: options.Telemetry,
	}, nil
}

func (r *TupleReconciler) Reconcile(
	ctx context.Context,
	plan TupleReconciliationPlan,
) (report ReconciliationReport, err error) {
	report = reconciliationReport(plan)
	if r == nil || r.writer == nil || r.revisions == nil || r.lifecycle == nil || ctx == nil {
		return report, fmt.Errorf("%w: tuple reconciler is not initialized", ErrReconciliation)
	}
	startedAt := time.Now()
	defer func() {
		_ = r.telemetry.Emit(ctx, reconciliationTelemetryRecord(report, err, time.Since(startedAt)))
	}()
	if err := plan.Validate(); err != nil {
		return report, fmt.Errorf("%w: %w", ErrReconciliation, err)
	}
	if err := ctx.Err(); err != nil {
		return report, contextFailure(err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	current, err := r.revisions.Current(ctx)
	if err != nil {
		return report, fmt.Errorf("%w: read current revision: %w", ErrReconciliation, err)
	}
	if current != plan.BaseRevision {
		return report, fmt.Errorf("%w: expected epoch %d, found %d", ErrRevisionSkew, plan.BaseRevision.Epoch, current.Epoch)
	}
	if plan.IsNoop() {
		report.Outcome = ReconciliationNoop
		return report, nil
	}
	reservation, err := r.revisions.Reserve(ctx, plan.BaseRevision, plan.TargetRevision)
	if err != nil {
		return report, fmt.Errorf("%w: reserve revision: %w", ErrReconciliation, err)
	}
	published := false
	defer func() {
		if !published {
			r.revisions.Abort(reservation)
		}
	}()

	transition := RevocationTransition{
		BaseRevision:       plan.BaseRevision,
		TargetRevision:     plan.TargetRevision,
		RetiredResourceIDs: append([]protocol.ResourceID(nil), plan.RetiredResourceIDs...),
		GrantedResourceIDs: append([]protocol.ResourceID(nil), plan.GrantedResourceIDs...),
	}
	if len(transition.RetiredResourceIDs) > 0 || len(transition.GrantedResourceIDs) > 0 {
		if err := r.lifecycle.Prepare(ctx, transition); err != nil {
			return report, fmt.Errorf("%w: prepare revocation lifecycle: %w", ErrReconciliation, err)
		}
	}

	if len(plan.Writes) > 0 || len(plan.Deletes) > 0 {
		request := TupleWriteRequest{
			StoreID:              plan.TargetRevision.StoreID,
			AuthorizationModelID: plan.TargetRevision.AuthorizationModelID,
			Writes:               tupleBindings(plan.Writes),
			Deletes:              tupleBindings(plan.Deletes),
		}
		if err := r.writer.ApplyTupleChanges(ctx, request); err != nil {
			return report, fmt.Errorf("%w: apply tuple changes: %w", ErrReconciliation, err)
		}
	}

	// Grants become eligible only for the target epoch. Readers still holding
	// the base revision remain denied until the compare-and-swap below succeeds.
	if len(transition.RetiredResourceIDs) > 0 || len(transition.GrantedResourceIDs) > 0 {
		if err := r.lifecycle.Commit(ctx, transition); err != nil {
			return report, fmt.Errorf("%w: commit revocation lifecycle: %w", ErrReconciliation, err)
		}
	}
	if err := r.revisions.Publish(ctx, reservation); err != nil {
		return report, fmt.Errorf("%w: publish revision: %w", ErrReconciliation, err)
	}
	published = true
	report.Outcome = ReconciliationSucceeded
	report.RevisionPublished = true
	return report, nil
}

func reconciliationTelemetryRecord(
	report ReconciliationReport,
	reconcileErr error,
	elapsed time.Duration,
) telemetry.Record {
	outcome := telemetry.OutcomeFailed
	if reconcileErr == nil {
		outcome = telemetry.OutcomeOK
	}
	budgetResult := telemetry.BudgetPass
	if elapsed > time.Second {
		budgetResult = telemetry.BudgetFail
	}
	return telemetry.Record{
		ContractVersion: telemetry.ContractVersion1,
		MetricScope:     telemetry.MetricScopeOperational,
		Event:           telemetry.EventPermissionedReconciliation,
		Stage:           telemetry.StageReconciliation,
		Outcome:         outcome,
		Budget: telemetry.Budget{
			Name: telemetry.BudgetLocalHardLatency, Result: budgetResult,
		},
		Counts: telemetry.Counts{
			Samples: 1, ReconciliationAdditions: uint64(report.WriteCount),
			ReconciliationRemovals: uint64(report.DeleteCount),
		},
		Durations: telemetry.Durations{Elapsed: uint64(elapsed / time.Millisecond)},
	}
}

func reconciliationReport(plan TupleReconciliationPlan) ReconciliationReport {
	return ReconciliationReport{
		Outcome:                  ReconciliationFailed,
		BaseEpoch:                plan.BaseRevision.Epoch,
		TargetEpoch:              plan.TargetRevision.Epoch,
		WriteCount:               len(plan.Writes),
		DeleteCount:              len(plan.Deletes),
		InvalidatedResourceCount: len(canonicalResourceIDUnion(plan.RetiredResourceIDs, plan.GrantedResourceIDs)),
		GrantedResourceCount:     len(plan.GrantedResourceIDs),
	}
}

func tupleBindings(bindings []CatalogTupleBinding) []Tuple {
	tuples := make([]Tuple, len(bindings))
	for index, binding := range bindings {
		tuples[index] = binding.Tuple
	}
	return tuples
}
