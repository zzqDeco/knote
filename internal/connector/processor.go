package connector

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type ProcessorOptions struct {
	RetryPolicy             RetryPolicy
	Clock                   func() time.Time
	Faults                  FaultInjector
	Publisher               Publisher
	ReconciliationProjector ReconciliationProjector
}

type Processor struct {
	store       *Store
	retryPolicy RetryPolicy
	clock       func() time.Time
	faults      FaultInjector
	publisher   Publisher
	reconciler  ReconciliationProjector
}

func NewProcessor(store *Store, options ProcessorOptions) (*Processor, error) {
	if store == nil {
		return nil, fmt.Errorf("connector store is required")
	}
	policy := options.RetryPolicy
	if policy.MaxAttempts == 0 {
		policy.MaxAttempts = DefaultMaxAttempts
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Processor{
		store: store, retryPolicy: policy, clock: clock, faults: options.Faults,
		publisher: options.Publisher, reconciler: options.ReconciliationProjector,
	}, nil
}

func (p *Processor) Process(
	ctx context.Context,
	ref ConnectorRef,
	event protocol.ConnectorEventEnvelope,
	projector Projector,
) (ProcessResult, error) {
	if err := validateEventOperation(ctx, ref, event); err != nil {
		return ProcessResult{}, err
	}
	if event.Kind == protocol.ConnectorSnapshotComplete {
		return ProcessResult{}, ErrSnapshotReconciliationRequired
	}
	if isNilCallback(projector) {
		return ProcessResult{}, fmt.Errorf("connector projector is required")
	}
	var result ProcessResult
	err := p.store.withConnectorLock(ctx, ref, func() error {
		durable, existing, err := p.appendEvent(ctx, ref, event)
		result = processResultFor(durable, existing)
		if err != nil {
			return err
		}
		if durable.deadLetter != nil {
			return ErrDeadLettered
		}
		if durable.publicationReceipt == nil {
			if err := p.applyEvent(ctx, ref, event.Sequence, durable.entry.EventFingerprint, projector); err != nil {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return err
			}
			if err := p.completeDurableStages(ref, event.Sequence, durable.entry.EventFingerprint); err != nil {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return err
			}
			if isNilCallback(p.publisher) {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return ErrPublisherRequired
			}
			if err := p.publishEvent(ctx, ref, event.Sequence, p.publisher, false); err != nil {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return err
			}
		}
		result = p.currentResult(ref, event.Sequence, existing, result)
		return nil
	})
	return result, err
}

// ProcessSnapshot is the only path that accepts snapshot_complete. The exact
// snapshots, projection base, derived plan, and ownership scope are bound into
// the journal entry before the reconciliation projector is invoked.
func (p *Processor) ProcessSnapshot(
	ctx context.Context,
	ref ConnectorRef,
	event protocol.ConnectorEventEnvelope,
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
) (ProcessResult, error) {
	if err := validateEventOperation(ctx, ref, event); err != nil {
		return ProcessResult{}, err
	}
	if event.Kind != protocol.ConnectorSnapshotComplete {
		return ProcessResult{}, fmt.Errorf("ProcessSnapshot requires snapshot_complete event")
	}
	if isNilReconciliationProjector(p.reconciler) {
		return ProcessResult{}, ErrReconciliationProjectorRequired
	}
	if err := validateReconciliationScope(ref, authoritative, projected); err != nil {
		return ProcessResult{}, err
	}
	var result ProcessResult
	err := p.store.withConnectorLock(ctx, ref, func() error {
		durable, existing, err := p.appendSnapshotEvent(ref, event, authoritative, projected)
		result = processResultFor(durable, existing)
		if err != nil {
			return err
		}
		if durable.deadLetter != nil {
			return ErrDeadLettered
		}
		if durable.publicationReceipt == nil {
			if err := p.reconcileSnapshotEvent(ctx, ref, event.Sequence, durable.entry.EventFingerprint); err != nil {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return err
			}
			if err := p.completeDurableStages(ref, event.Sequence, durable.entry.EventFingerprint); err != nil {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return err
			}
			if isNilCallback(p.publisher) {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return ErrPublisherRequired
			}
			if err := p.publishEvent(ctx, ref, event.Sequence, p.publisher, false); err != nil {
				result = p.currentResult(ref, event.Sequence, existing, result)
				return err
			}
		}
		result = p.currentResult(ref, event.Sequence, existing, result)
		return nil
	})
	return result, err
}

// Recover resumes a pending standalone reconciliation and then the sole
// unfinished event, including publication. External integrations can be
// reinvoked with their previously persisted idempotency fingerprints.
func (p *Processor) Recover(ctx context.Context, ref ConnectorRef, projector Projector) ([]ProcessResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("connector recovery context is required")
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if isNilCallback(projector) {
		return nil, fmt.Errorf("connector projector is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := []ProcessResult{}
	err := p.store.withConnectorLock(ctx, ref, func() error {
		if err := p.recoverStandaloneReconciliation(ctx, ref); err != nil {
			return err
		}
		var durable durableEvent
		if err := p.store.withLock(func() error {
			state, err := p.store.loadStateLocked(ref, true)
			if err != nil {
				return err
			}
			if len(state.events) == 0 {
				return nil
			}
			durable = state.events[len(state.events)-1]
			return nil
		}); err != nil {
			return err
		}
		if durable.entry.Event.Sequence == 0 || durable.publicationReceipt != nil {
			return nil
		}
		result := processResultFor(durable, true)
		results = append(results, result)
		if durable.deadLetter != nil {
			return ErrDeadLettered
		}
		if durable.entry.Event.Kind == protocol.ConnectorSnapshotComplete {
			if isNilReconciliationProjector(p.reconciler) {
				return ErrReconciliationProjectorRequired
			}
			if err := p.reconcileSnapshotEvent(ctx, ref, durable.entry.Event.Sequence, durable.entry.EventFingerprint); err != nil {
				results[0] = p.currentResult(ref, durable.entry.Event.Sequence, true, result)
				return err
			}
		} else if err := p.applyEvent(ctx, ref, durable.entry.Event.Sequence, durable.entry.EventFingerprint, projector); err != nil {
			results[0] = p.currentResult(ref, durable.entry.Event.Sequence, true, result)
			return err
		}
		if err := p.completeDurableStages(ref, durable.entry.Event.Sequence, durable.entry.EventFingerprint); err != nil {
			results[0] = p.currentResult(ref, durable.entry.Event.Sequence, true, result)
			return err
		}
		if isNilCallback(p.publisher) {
			results[0] = p.currentResult(ref, durable.entry.Event.Sequence, true, result)
			return ErrPublisherRequired
		}
		if err := p.publishEvent(ctx, ref, durable.entry.Event.Sequence, p.publisher, false); err != nil {
			results[0] = p.currentResult(ref, durable.entry.Event.Sequence, true, result)
			return err
		}
		results[0] = p.currentResult(ref, durable.entry.Event.Sequence, true, result)
		return nil
	})
	return results, err
}

func (p *Processor) Publish(ctx context.Context, ref ConnectorRef, sequence uint64, publisher Publisher) error {
	if ctx == nil {
		return fmt.Errorf("connector publication context is required")
	}
	if isNilCallback(publisher) {
		return ErrPublisherRequired
	}
	if sequence == 0 {
		return ErrPublicationOrder
	}
	return p.store.withConnectorLock(ctx, ref, func() error {
		return p.publishEvent(ctx, ref, sequence, publisher, true)
	})
}

func validateEventOperation(ctx context.Context, ref ConnectorRef, event protocol.ConnectorEventEnvelope) error {
	if ctx == nil {
		return fmt.Errorf("connector processing context is required")
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := event.ValidateFor(ref.Scope); err != nil {
		return err
	}
	if event.ConnectorID != ref.ConnectorID {
		return fmt.Errorf("connector event crosses the registered connector scope")
	}
	return ctx.Err()
}

func (p *Processor) appendEvent(
	ctx context.Context,
	ref ConnectorRef,
	event protocol.ConnectorEventEnvelope,
) (durableEvent, bool, error) {
	var durable durableEvent
	var existing bool
	fingerprint, err := protocol.NewConnectorEventFingerprint(event)
	if err != nil {
		return durableEvent{}, false, err
	}
	err = p.store.withLock(func() error {
		if err := p.ensureNoPendingReconciliationLocked(ref); err != nil {
			return err
		}
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		index, found, err := validateIncomingEvent(state, event, fingerprint)
		if err != nil {
			return err
		}
		if found {
			durable, existing = state.events[index], true
			return nil
		}
		if wouldResurrect(state, event) {
			return ErrTombstoneResurrection
		}
		return nil
	})
	if err != nil || existing {
		return durable, existing, err
	}
	appendedAt, err := p.now()
	if err != nil {
		return durableEvent{}, false, err
	}
	entry := JournalEntry{
		Version: ConnectorCoreVersion, Event: event, EventFingerprint: fingerprint, AppendedAt: appendedAt,
	}
	if err := entry.ValidateFor(ref); err != nil {
		return durableEvent{}, false, err
	}
	if err := p.inject(FaultBeforeAppend, event); err != nil {
		return durableEvent{}, false, err
	}
	err = p.store.withLock(func() error {
		if err := p.ensureNoPendingReconciliationLocked(ref); err != nil {
			return err
		}
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		index, found, err := validateIncomingEvent(state, event, fingerprint)
		if err != nil {
			return err
		}
		if found {
			durable, existing = state.events[index], true
			return nil
		}
		if wouldResurrect(state, event) {
			return ErrTombstoneResurrection
		}
		if _, err := p.store.ensureEventResourceOwnershipLocked(
			ref, state.registration, event, fingerprint, appendedAt,
		); err != nil {
			return err
		}
		if err := p.store.writeJSONOnce(p.store.journalPath(ref, event.Sequence), entry); err != nil {
			return err
		}
		durable = durableEvent{entry: entry, attempts: []durableAttempt{}}
		return nil
	})
	if err != nil {
		return durable, existing, err
	}
	if existing {
		return durable, true, nil
	}
	if err := p.inject(FaultAfterAppend, event); err != nil {
		return durable, false, err
	}
	return durable, false, ctx.Err()
}

func (p *Processor) appendSnapshotEvent(
	ref ConnectorRef,
	event protocol.ConnectorEventEnvelope,
	authoritative AuthoritativeSnapshot,
	projected ProjectionSnapshot,
) (durableEvent, bool, error) {
	authoritativeDigest, err := authoritativeSnapshotDigest(authoritative)
	if err != nil {
		return durableEvent{}, false, err
	}
	projectionDigest, err := projectionSnapshotDigest(projected)
	if err != nil {
		return durableEvent{}, false, err
	}
	var durable durableEvent
	var existing bool
	var preparation reconciliationPreparation
	fingerprint, err := protocol.NewConnectorEventFingerprint(event)
	if err != nil {
		return durableEvent{}, false, err
	}
	err = p.store.withLock(func() error {
		if err := p.ensureNoPendingReconciliationLocked(ref); err != nil {
			return err
		}
		if projected.ProjectionBaseSequence != event.Sequence-1 {
			return ErrProjectionBaseMismatch
		}
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		index, found, err := validateIncomingEvent(state, event, fingerprint)
		if err != nil {
			return err
		}
		if found {
			durable, existing = state.events[index], true
			if durable.entry.SnapshotReconciliation == nil {
				return ErrSnapshotReconciliationRequired
			}
			intent := durable.entry.SnapshotReconciliation
			if intent.AuthoritativeSnapshotDigest != authoritativeDigest ||
				intent.ProjectionBaseDigest != projectionDigest ||
				intent.ProjectionBaseSequence != projected.ProjectionBaseSequence {
				return ErrJournalConflict
			}
			return nil
		}
		preparation, err = p.prepareReconciliationLocked(ref, authoritative, projected, nil)
		if err != nil {
			return err
		}
		if preparation.request.ProjectionBaseSequence != event.Sequence-1 {
			return ErrProjectionBaseMismatch
		}
		return nil
	})
	if err != nil || existing {
		return durable, existing, err
	}
	createdAt, err := p.now()
	if err != nil {
		return durableEvent{}, false, err
	}
	buildIntent := func(request ReconciliationApplyRequest) (SnapshotReconciliationIntent, error) {
		intent := SnapshotReconciliationIntent{
			Version: ConnectorCoreVersion, TenantID: event.TenantID, ConnectorID: event.ConnectorID,
			SourceID: preparation.registration.SourceID, EventID: event.EventID, EventFingerprint: fingerprint,
			Sequence: event.Sequence, AuthoritativeSnapshotDigest: authoritativeDigest,
			AuthoritativeCapturedAt: preparation.request.AuthoritativeCapturedAt,
			AuthoritativeResources:  append([]AuthoritativeResource{}, request.AuthoritativeResources...),
			SourceWatermark:         event.SourceWatermark, ACLWatermark: event.ACLWatermark,
			ProjectionBaseDigest: projectionDigest, ProjectionBaseSequence: projected.ProjectionBaseSequence,
			PlanDigest:       request.Plan.Digest,
			OwnedResourceIDs: append([]protocol.ResourceID{}, request.OwnedResourceIDs...),
			Plan:             cloneReconciliationPlan(request.Plan), CreatedAt: createdAt,
		}
		boundRequest := reconciliationRequestForSnapshotIntent(intent)
		if err := bindReconciliationIdempotencyKey(&boundRequest); err != nil {
			return SnapshotReconciliationIntent{}, err
		}
		intent.IdempotencyKey = boundRequest.IdempotencyKey
		return intent, intent.ValidateForEvent(event)
	}
	intent, err := buildIntent(preparation.request)
	if err != nil {
		return durableEvent{}, false, err
	}
	entry := JournalEntry{
		Version: ConnectorCoreVersion, Event: event, EventFingerprint: fingerprint,
		SnapshotReconciliation: &intent, AppendedAt: createdAt,
	}
	if err := entry.ValidateFor(ref); err != nil {
		return durableEvent{}, false, err
	}
	if err := p.inject(FaultBeforeAppend, event); err != nil {
		return durableEvent{}, false, err
	}
	err = p.store.withLock(func() error {
		if err := p.ensureNoPendingReconciliationLocked(ref); err != nil {
			return err
		}
		if projected.ProjectionBaseSequence != event.Sequence-1 {
			return ErrProjectionBaseMismatch
		}
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		index, found, err := validateIncomingEvent(state, event, fingerprint)
		if err != nil {
			return err
		}
		if found {
			durable, existing = state.events[index], true
			if durable.entry.SnapshotReconciliation == nil ||
				durable.entry.SnapshotReconciliation.AuthoritativeSnapshotDigest != authoritativeDigest ||
				durable.entry.SnapshotReconciliation.ProjectionBaseDigest != projectionDigest ||
				durable.entry.SnapshotReconciliation.ProjectionBaseSequence != projected.ProjectionBaseSequence {
				return ErrJournalConflict
			}
			return nil
		}
		current, err := p.prepareReconciliationLocked(ref, authoritative, projected, nil)
		if err != nil {
			return err
		}
		if !reconciliationRequestsEqual(current.request, preparation.request) ||
			current.request.ProjectionBaseSequence != event.Sequence-1 {
			return ErrJournalConflict
		}
		if err := p.store.claimReconciliationResourceOwnershipsLocked(
			ref, current.registration, current.unownedAuthoritative,
			&event, fingerprint, "", createdAt,
		); err != nil {
			return err
		}
		entry := JournalEntry{
			Version: ConnectorCoreVersion, Event: event, EventFingerprint: fingerprint,
			SnapshotReconciliation: &intent, AppendedAt: createdAt,
		}
		if err := p.store.writeJSONOnce(p.store.journalPath(ref, event.Sequence), entry); err != nil {
			return err
		}
		durable = durableEvent{entry: entry, attempts: []durableAttempt{}}
		return nil
	})
	if err != nil {
		return durable, existing, err
	}
	if existing {
		return durable, true, nil
	}
	if err := p.inject(FaultAfterAppend, event); err != nil {
		return durable, false, err
	}
	return durable, false, nil
}

func validateIncomingEvent(
	state durableState,
	event protocol.ConnectorEventEnvelope,
	fingerprint protocol.ConnectorEventFingerprint,
) (index int, existing bool, err error) {
	checkpointSequence := uint64(0)
	publishedSequence := uint64(0)
	if state.cursor.Checkpoint != nil {
		checkpointSequence = state.cursor.Checkpoint.LastSequence
	}
	if state.cursor.Serving != nil {
		publishedSequence = state.cursor.Serving.Sequence
	}
	if event.Sequence < checkpointSequence {
		return 0, false, ErrStaleEvent
	}
	if event.Sequence <= uint64(len(state.events)) {
		durable := state.events[event.Sequence-1]
		if durable.entry.EventFingerprint != fingerprint {
			return 0, false, ErrJournalConflict
		}
		return int(event.Sequence - 1), true, nil
	}
	if state.cursor.Blocked != nil {
		return 0, false, ErrPendingEvent
	}
	if checkpointSequence != publishedSequence || uint64(len(state.events)) != checkpointSequence {
		return 0, false, ErrPendingEvent
	}
	expected := checkpointSequence + 1
	if event.Sequence < expected {
		return 0, false, ErrStaleEvent
	}
	if event.Sequence > expected {
		return 0, false, ErrSequenceGap
	}
	for _, durable := range state.events {
		if durable.entry.Event.EventID == event.EventID || durable.entry.Event.IdempotencyKey == event.IdempotencyKey {
			return 0, false, ErrJournalConflict
		}
	}
	return 0, false, nil
}

func wouldResurrect(state durableState, incoming protocol.ConnectorEventEnvelope) bool {
	if incoming.Kind != protocol.ConnectorContentUpsert && incoming.Kind != protocol.ConnectorACLReplace {
		return false
	}
	return containsResourceID(committedTerminalResourceIDs(state), incoming.ResourceID)
}

func pendingEventWouldResurrect(state durableState, event durableEvent) bool {
	terminalResourceIDs := committedTerminalResourceIDs(state)
	if len(terminalResourceIDs) == 0 {
		return false
	}
	switch event.entry.Event.Kind {
	case protocol.ConnectorContentUpsert, protocol.ConnectorACLReplace:
		return containsResourceID(terminalResourceIDs, event.entry.Event.ResourceID)
	case protocol.ConnectorSnapshotComplete:
		if event.entry.SnapshotReconciliation == nil {
			return false
		}
		intent := event.entry.SnapshotReconciliation
		removed := reconciliationRemovalIDs(intent.Plan)
		removed = append(removed, intent.Plan.TombstonedResources...)
		for _, resourceID := range intent.OwnedResourceIDs {
			if !containsResourceID(removed, resourceID) && containsResourceID(terminalResourceIDs, resourceID) {
				return true
			}
		}
	}
	return false
}

func (p *Processor) ensurePendingEventNotTerminal(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
) error {
	return p.store.withLock(func() error {
		state, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if pendingEventWouldResurrect(state, *event) {
			return ErrTombstoneResurrection
		}
		return nil
	})
}

func (p *Processor) applyEvent(
	ctx context.Context,
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
	projector Projector,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var request ApplyRequest
		alreadyApplied := false
		needsAttempt := false
		needsDeadLetter := false
		var eventEnvelope protocol.ConnectorEventEnvelope
		var nextAttempt uint32
		err := p.store.withLock(func() error {
			state, event, err := p.loadEventLocked(ref, sequence, fingerprint)
			if err != nil {
				return err
			}
			if pendingEventWouldResurrect(state, *event) {
				return ErrTombstoneResurrection
			}
			if event.deadLetter != nil {
				return ErrDeadLettered
			}
			if event.delivery != nil {
				alreadyApplied = true
				return nil
			}
			if len(event.attempts) > 0 {
				last := event.attempts[len(event.attempts)-1]
				if last.failure != nil && (!last.failure.Retryable || last.failure.Attempt >= p.retryPolicy.MaxAttempts) {
					needsDeadLetter = true
					eventEnvelope = event.entry.Event
					return nil
				}
			}
			var attempt durableAttempt
			if len(event.attempts) == 0 || event.attempts[len(event.attempts)-1].failure != nil {
				needsAttempt = true
				nextAttempt = uint32(len(event.attempts) + 1)
				eventEnvelope = event.entry.Event
				return nil
			}
			attempt = event.attempts[len(event.attempts)-1]
			ownership, err := p.store.loadResourceOwnershipLocked(ref, event.entry.Event.ResourceID)
			if err != nil {
				return err
			}
			if err := validateResourceOwnershipForRegistration(ownership, state.registration); err != nil {
				return err
			}
			request = applyRequestFor(event.entry, attempt.intent.Attempt)
			request.SourceOwnership = sourceOwnershipFor(state.registration)
			request.ResourceOwnership = ownership
			if event.entry.Event.Kind == protocol.ConnectorResourceTombstone {
				tombstone, err := deterministicTombstone(event.entry)
				if err != nil {
					return err
				}
				request.Tombstone = &tombstone
			}
			return request.Validate()
		})
		if err != nil {
			return err
		}
		if alreadyApplied {
			return nil
		}
		if needsDeadLetter {
			return p.persistDeadLetter(ref, sequence, fingerprint, eventEnvelope)
		}
		if needsAttempt {
			startedAt, err := p.now()
			if err != nil {
				return err
			}
			intent := ApplyAttempt{
				Version: ConnectorCoreVersion, TenantID: eventEnvelope.TenantID,
				ConnectorID: eventEnvelope.ConnectorID, EventID: eventEnvelope.EventID,
				EventFingerprint: fingerprint, Attempt: nextAttempt, StartedAt: startedAt,
			}
			if err := p.store.withLock(func() error {
				_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
				if err != nil {
					return err
				}
				if event.delivery != nil || event.deadLetter != nil {
					return nil
				}
				if len(event.attempts) != int(nextAttempt-1) {
					return nil
				}
				if nextAttempt > 1 && event.attempts[nextAttempt-2].failure == nil {
					return fmt.Errorf("%w: apply attempt lost its preceding failure", ErrStoreIntegrity)
				}
				if err := p.store.writeJSONOnce(
					p.store.attemptIntentPath(ref, sequence, nextAttempt), intent,
				); err != nil {
					return err
				}
				event.attempts = append(event.attempts, durableAttempt{intent: intent})
				return nil
			}); err != nil {
				return err
			}
			continue
		}
		if err := p.ensurePendingEventNotTerminal(ref, sequence, fingerprint); err != nil {
			return err
		}
		if err := p.inject(FaultBeforeApply, request.Event); err != nil {
			return err
		}
		callbackRequest := request
		callbackRequest.Tombstone = cloneTombstone(request.Tombstone)
		result, applyErr := projector.Apply(ctx, callbackRequest)
		if applyErr != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			code, retryable := classifyApplyError(applyErr)
			if err := p.persistApplyFailure(ref, sequence, fingerprint, request.Attempt, code, retryable); err != nil {
				return err
			}
			continue
		}
		if err := result.ValidateFor(request); err != nil {
			if persistErr := p.persistApplyFailure(
				ref, sequence, fingerprint, request.Attempt, "invalid-apply-result", false,
			); persistErr != nil {
				return errors.Join(err, persistErr)
			}
			continue
		}
		if err := p.inject(FaultAfterApply, request.Event); err != nil {
			return err
		}
		return p.persistReceipt(ref, sequence, fingerprint, request, result)
	}
}

func (p *Processor) persistReceipt(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
	request ApplyRequest,
	result ApplyResult,
) error {
	if err := p.inject(FaultBeforeReceipt, request.Event); err != nil {
		return err
	}
	handledAt, err := p.now()
	if err != nil {
		return err
	}
	receipt := protocol.ConnectorDeliveryReceipt{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: request.Event.TenantID, ConnectorID: request.Event.ConnectorID,
		EventID: request.Event.EventID, EventFingerprint: fingerprint,
		IdempotencyKey: request.Event.IdempotencyKey, Sequence: request.Event.Sequence,
		State: protocol.ConnectorDeliveryApplied, Attempts: request.Attempt, HandledAt: handledAt,
	}
	if err := receipt.ValidateFor(request.Event); err != nil {
		return err
	}
	record := DeliveryRecord{
		Version: ConnectorCoreVersion, Receipt: receipt, Result: result,
		SourceOwnership: request.SourceOwnership, ResourceOwnership: request.ResourceOwnership,
		Tombstone: cloneTombstone(request.Tombstone),
	}
	alreadyPersisted := false
	if err := p.store.withLock(func() error {
		state, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.delivery != nil {
			alreadyPersisted = true
			return nil
		}
		if event.deadLetter != nil {
			return ErrDeadLettered
		}
		if len(event.attempts) != int(request.Attempt) || request.Attempt == 0 ||
			event.attempts[request.Attempt-1].failure != nil {
			return fmt.Errorf("%w: apply receipt lost its durable attempt", ErrStoreIntegrity)
		}
		currentRequest := applyRequestFor(event.entry, request.Attempt)
		currentRequest.SourceOwnership = sourceOwnershipFor(state.registration)
		currentRequest.ResourceOwnership, err = p.store.loadResourceOwnershipLocked(ref, event.entry.Event.ResourceID)
		if err != nil {
			return err
		}
		if event.entry.Event.Kind == protocol.ConnectorResourceTombstone {
			tombstone, err := deterministicTombstone(event.entry)
			if err != nil {
				return err
			}
			currentRequest.Tombstone = &tombstone
		}
		if !reflect.DeepEqual(currentRequest, request) {
			return ErrJournalConflict
		}
		if err := result.ValidateFor(currentRequest); err != nil {
			return err
		}
		return p.store.writeJSONOnce(p.store.receiptPath(ref, sequence), record)
	}); err != nil {
		return err
	}
	if alreadyPersisted {
		return nil
	}
	return p.inject(FaultAfterReceipt, request.Event)
}

func (p *Processor) persistDeadLetter(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
	eventEnvelope protocol.ConnectorEventEnvelope,
) error {
	var failures []ApplyFailureRecord
	alreadyPersisted := false
	if err := p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.deadLetter != nil {
			alreadyPersisted = true
			return nil
		}
		if event.delivery != nil || event.reconciliation != nil {
			return fmt.Errorf("%w: applied event cannot be dead-lettered", ErrStoreIntegrity)
		}
		if len(event.attempts) == 0 || event.attempts[len(event.attempts)-1].failure == nil {
			return fmt.Errorf("cannot dead-letter an event without a durable failure")
		}
		failures = make([]ApplyFailureRecord, len(event.attempts))
		for index, attempt := range event.attempts {
			if attempt.failure == nil {
				return fmt.Errorf("cannot dead-letter an event with an unfinished attempt")
			}
			failures[index] = *attempt.failure
		}
		return nil
	}); err != nil {
		return err
	}
	if alreadyPersisted {
		return ErrDeadLettered
	}
	if err := p.inject(FaultBeforeDeadLetter, eventEnvelope); err != nil {
		return err
	}
	handledAt, err := p.now()
	if err != nil {
		return err
	}
	lastFailure := failures[len(failures)-1]
	receipt := protocol.ConnectorDeliveryReceipt{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: eventEnvelope.TenantID, ConnectorID: eventEnvelope.ConnectorID,
		EventID: eventEnvelope.EventID, EventFingerprint: fingerprint,
		IdempotencyKey: eventEnvelope.IdempotencyKey, Sequence: eventEnvelope.Sequence,
		State: protocol.ConnectorDeliveryDeadLettered, Attempts: uint32(len(failures)),
		ErrorCode: lastFailure.ErrorCode, HandledAt: handledAt,
	}
	if err := receipt.ValidateFor(eventEnvelope); err != nil {
		return err
	}
	deadLetter := DeadLetter{
		Version: ConnectorCoreVersion, Event: eventEnvelope, Receipt: receipt,
		Stage: failureStageForEvent(eventEnvelope), Failures: append([]ApplyFailureRecord{}, failures...),
	}
	wrote := false
	if err := p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.deadLetter != nil {
			return nil
		}
		if event.delivery != nil || event.reconciliation != nil || len(event.attempts) != len(failures) {
			return fmt.Errorf("%w: dead letter lost its durable failures", ErrStoreIntegrity)
		}
		for index, attempt := range event.attempts {
			if attempt.failure == nil || *attempt.failure != failures[index] {
				return fmt.Errorf("%w: dead letter failures changed before persistence", ErrStoreIntegrity)
			}
		}
		if err := p.store.writeJSONOnce(p.store.deadLetterPath(ref, sequence), deadLetter); err != nil {
			return err
		}
		wrote = true
		return nil
	}); err != nil {
		return err
	}
	if wrote {
		if err := p.inject(FaultAfterDeadLetter, eventEnvelope); err != nil {
			return err
		}
	}
	if err := p.store.withLock(func() error {
		_, err := p.store.loadStateLocked(ref, true)
		return err
	}); err != nil {
		return err
	}
	return ErrDeadLettered
}

func (p *Processor) persistApplyFailure(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
	attempt uint32,
	code string,
	retryable bool,
) error {
	failedAt, err := p.now()
	if err != nil {
		return err
	}
	return p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.delivery != nil || event.reconciliation != nil || event.deadLetter != nil {
			return nil
		}
		if attempt == 0 || len(event.attempts) != int(attempt) || event.attempts[attempt-1].failure != nil {
			return fmt.Errorf("%w: apply failure lost its durable attempt", ErrStoreIntegrity)
		}
		failure := ApplyFailureRecord{
			Version: ConnectorCoreVersion, TenantID: event.entry.Event.TenantID,
			ConnectorID: event.entry.Event.ConnectorID, EventID: event.entry.Event.EventID,
			EventFingerprint: event.entry.EventFingerprint, Attempt: attempt,
			ErrorCode: code, Retryable: retryable, FailedAt: failedAt,
		}
		if err := validateErrorCode(failure.ErrorCode); err != nil {
			return err
		}
		if err := p.store.writeJSONOnce(
			p.store.attemptFailurePath(ref, event.entry.Event.Sequence, attempt), failure,
		); err != nil {
			return err
		}
		event.attempts[attempt-1].failure = &failure
		return nil
	})
}

func (p *Processor) reconcileSnapshotEvent(
	ctx context.Context,
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var request ReconciliationApplyRequest
		var intent SnapshotReconciliationIntent
		var eventEnvelope protocol.ConnectorEventEnvelope
		var attempt uint32
		var nextAttempt uint32
		alreadyApplied := false
		needsAttempt := false
		needsDeadLetter := false
		if err := p.store.withLock(func() error {
			state, event, err := p.loadEventLocked(ref, sequence, fingerprint)
			if err != nil {
				return err
			}
			if event.entry.Event.Kind != protocol.ConnectorSnapshotComplete || event.entry.SnapshotReconciliation == nil {
				return ErrSnapshotReconciliationRequired
			}
			eventEnvelope = event.entry.Event
			if pendingEventWouldResurrect(state, *event) {
				return ErrTombstoneResurrection
			}
			if event.deadLetter != nil {
				return ErrDeadLettered
			}
			if event.reconciliation != nil {
				alreadyApplied = true
				return nil
			}
			if len(event.attempts) > 0 {
				last := event.attempts[len(event.attempts)-1]
				if last.failure != nil && (!last.failure.Retryable || last.failure.Attempt >= p.retryPolicy.MaxAttempts) {
					needsDeadLetter = true
					return nil
				}
			}
			if len(event.attempts) == 0 || event.attempts[len(event.attempts)-1].failure != nil {
				needsAttempt = true
				nextAttempt = uint32(len(event.attempts) + 1)
				return nil
			}
			attempt = event.attempts[len(event.attempts)-1].intent.Attempt
			intent = *event.entry.SnapshotReconciliation
			owned, err := p.store.requireResourceOwnershipsLocked(ref, state.registration, intent.OwnedResourceIDs)
			if err != nil {
				return err
			}
			request = reconciliationRequestForSnapshotIntent(intent)
			request.SourceOwnership = sourceOwnershipFor(state.registration)
			request.OwnedResourceIDs = owned
			return request.Validate()
		}); err != nil {
			return err
		}
		if alreadyApplied {
			return nil
		}
		if needsDeadLetter {
			return p.persistDeadLetter(ref, sequence, fingerprint, eventEnvelope)
		}
		if needsAttempt {
			startedAt, err := p.now()
			if err != nil {
				return err
			}
			attemptIntent := ApplyAttempt{
				Version: ConnectorCoreVersion, TenantID: eventEnvelope.TenantID,
				ConnectorID: eventEnvelope.ConnectorID, EventID: eventEnvelope.EventID,
				EventFingerprint: fingerprint, Attempt: nextAttempt, StartedAt: startedAt,
			}
			if err := p.store.withLock(func() error {
				_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
				if err != nil {
					return err
				}
				if event.reconciliation != nil || event.deadLetter != nil {
					return nil
				}
				if event.entry.Event.Kind != protocol.ConnectorSnapshotComplete {
					return ErrSnapshotReconciliationRequired
				}
				if len(event.attempts) != int(nextAttempt-1) {
					return nil
				}
				if nextAttempt > 1 && event.attempts[nextAttempt-2].failure == nil {
					return fmt.Errorf("%w: reconciliation attempt lost its preceding failure", ErrStoreIntegrity)
				}
				if err := p.store.writeJSONOnce(
					p.store.attemptIntentPath(ref, sequence, nextAttempt), attemptIntent,
				); err != nil {
					return err
				}
				event.attempts = append(event.attempts, durableAttempt{intent: attemptIntent})
				return nil
			}); err != nil {
				return err
			}
			continue
		}
		if err := p.ensurePendingEventNotTerminal(ref, sequence, fingerprint); err != nil {
			return err
		}
		if err := p.inject(FaultBeforeReconciliation, eventEnvelope); err != nil {
			return err
		}
		if err := p.reconciler.ApplyReconciliation(ctx, cloneReconciliationRequest(request)); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			code, retryable := classifyApplyError(err)
			if persistErr := p.persistApplyFailure(ref, sequence, fingerprint, attempt, code, retryable); persistErr != nil {
				return persistErr
			}
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.inject(FaultAfterReconciliation, eventEnvelope); err != nil {
			return err
		}
		if err := p.inject(FaultBeforeReconciliationReceipt, eventEnvelope); err != nil {
			return err
		}
		appliedAt, err := p.now()
		if err != nil {
			return err
		}
		requestDigest, err := canonicalContentDigest(request)
		if err != nil {
			return err
		}
		derivedTombstones, err := newReconciliationTombstones(request, requestDigest)
		if err != nil {
			return err
		}
		receipt := SnapshotReconciliationReceipt{
			Version: ConnectorCoreVersion, TenantID: intent.TenantID, ConnectorID: intent.ConnectorID,
			SourceID: intent.SourceID, EventID: intent.EventID, EventFingerprint: intent.EventFingerprint,
			Sequence: intent.Sequence, AuthoritativeSnapshotDigest: intent.AuthoritativeSnapshotDigest,
			SourceWatermark: intent.SourceWatermark, ACLWatermark: intent.ACLWatermark,
			ProjectionBaseDigest: intent.ProjectionBaseDigest, ProjectionBaseSequence: intent.ProjectionBaseSequence,
			PlanDigest:    intent.PlanDigest,
			RequestDigest: requestDigest, DerivedTombstones: derivedTombstones, AppliedAt: appliedAt,
		}
		if err := receipt.ValidateFor(intent, request); err != nil {
			return err
		}
		wrote := false
		if err := p.store.withLock(func() error {
			state, event, err := p.loadEventLocked(ref, sequence, fingerprint)
			if err != nil {
				return err
			}
			if event.reconciliation != nil {
				return nil
			}
			if event.deadLetter != nil {
				return ErrDeadLettered
			}
			if attempt == 0 || len(event.attempts) != int(attempt) || event.attempts[attempt-1].failure != nil {
				return fmt.Errorf("%w: reconciliation receipt lost its durable attempt", ErrStoreIntegrity)
			}
			if event.entry.SnapshotReconciliation == nil || !reflect.DeepEqual(*event.entry.SnapshotReconciliation, intent) {
				return ErrJournalConflict
			}
			currentRequest := reconciliationRequestForSnapshotIntent(intent)
			currentRequest.SourceOwnership = sourceOwnershipFor(state.registration)
			currentRequest.OwnedResourceIDs, err = p.store.requireResourceOwnershipsLocked(
				ref, state.registration, intent.OwnedResourceIDs,
			)
			if err != nil {
				return err
			}
			if !reconciliationRequestsEqual(currentRequest, request) {
				return ErrJournalConflict
			}
			if err := p.store.writeJSONOnce(p.store.reconciliationReceiptPath(ref, sequence), receipt); err != nil {
				return err
			}
			wrote = true
			return nil
		}); err != nil {
			return err
		}
		if wrote {
			return p.inject(FaultAfterReconciliationReceipt, eventEnvelope)
		}
		return nil
	}
}

func (p *Processor) completeDurableStages(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
) error {
	if err := p.persistCheckpoint(ref, sequence, fingerprint); err != nil {
		return err
	}
	if err := p.persistEligibility(ref, sequence, fingerprint); err != nil {
		return err
	}
	return p.store.withLock(func() error {
		_, err := p.store.loadStateLocked(ref, true)
		return err
	})
}

func (p *Processor) persistCheckpoint(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
) error {
	var envelope protocol.ConnectorEventEnvelope
	alreadyPersisted := false
	if err := p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.checkpoint != nil {
			alreadyPersisted = true
			return nil
		}
		if event.entry.Event.Kind == protocol.ConnectorSnapshotComplete {
			if event.reconciliation == nil {
				return ErrSnapshotReconciliationRequired
			}
		} else if event.delivery == nil || event.delivery.Receipt.State != protocol.ConnectorDeliveryApplied {
			return fmt.Errorf("cannot checkpoint an event without an applied receipt")
		}
		envelope = event.entry.Event
		return nil
	}); err != nil {
		return err
	}
	if alreadyPersisted {
		return nil
	}
	if err := p.inject(FaultBeforeCheckpoint, envelope); err != nil {
		return err
	}
	committedAt, err := p.now()
	if err != nil {
		return err
	}
	checkpoint := protocol.ConnectorCheckpoint{
		Version: protocol.EnterpriseContractVersion, TenantID: envelope.TenantID,
		ConnectorID: envelope.ConnectorID, LastSequence: envelope.Sequence,
		CommittedEventID: envelope.EventID, CommittedEventFingerprint: fingerprint,
		IdempotencyKey: envelope.IdempotencyKey, SourceWatermark: envelope.SourceWatermark,
		ACLWatermark: envelope.ACLWatermark, CommittedAt: committedAt,
	}
	if err := checkpoint.ValidateEvent(envelope); err != nil {
		return err
	}
	wrote := false
	if err := p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.checkpoint != nil {
			return nil
		}
		if event.entry.Event != envelope {
			return ErrJournalConflict
		}
		if event.entry.Event.Kind == protocol.ConnectorSnapshotComplete {
			if event.reconciliation == nil {
				return ErrSnapshotReconciliationRequired
			}
		} else if event.delivery == nil || event.delivery.Receipt.State != protocol.ConnectorDeliveryApplied {
			return fmt.Errorf("cannot checkpoint an event without an applied receipt")
		}
		if err := p.store.writeJSONOnce(p.store.checkpointPath(ref, sequence), checkpoint); err != nil {
			return err
		}
		wrote = true
		return nil
	}); err != nil {
		return err
	}
	if wrote {
		return p.inject(FaultAfterCheckpoint, envelope)
	}
	return nil
}

func (p *Processor) persistEligibility(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
) error {
	var envelope protocol.ConnectorEventEnvelope
	var checkpoint protocol.ConnectorCheckpoint
	var outputDigest protocol.ContentDigest
	var tombstone *protocol.ConnectorTombstone
	var reconciliationTombstones []ReconciliationTombstone
	alreadyPersisted := false
	if err := p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.eligibility != nil {
			alreadyPersisted = true
			return nil
		}
		if event.checkpoint == nil {
			return fmt.Errorf("cannot mark serving eligibility before checkpoint")
		}
		outputDigest, tombstone, err = durableEventOutput(*event)
		if err != nil {
			return err
		}
		envelope = event.entry.Event
		checkpoint = *event.checkpoint
		reconciliationTombstones = durableReconciliationTombstones(*event)
		return nil
	}); err != nil {
		return err
	}
	if alreadyPersisted {
		return nil
	}
	if err := p.inject(FaultBeforeServingEligibility, envelope); err != nil {
		return err
	}
	eligibleAt, err := p.now()
	if err != nil {
		return err
	}
	eligibility := ServingEligibility{
		Version: ConnectorCoreVersion, TenantID: envelope.TenantID,
		ConnectorID: envelope.ConnectorID, EventID: envelope.EventID,
		Fingerprint: fingerprint, Sequence: envelope.Sequence,
		Checkpoint: checkpoint, OutputDigest: outputDigest,
		Tombstone:                cloneTombstone(tombstone),
		ReconciliationTombstones: cloneReconciliationTombstones(reconciliationTombstones),
		EligibleAt:               eligibleAt,
	}
	if err := eligibility.Validate(); err != nil {
		return err
	}
	wrote := false
	if err := p.store.withLock(func() error {
		_, event, err := p.loadEventLocked(ref, sequence, fingerprint)
		if err != nil {
			return err
		}
		if event.eligibility != nil {
			return nil
		}
		if event.entry.Event != envelope || event.checkpoint == nil || *event.checkpoint != checkpoint {
			return ErrJournalConflict
		}
		if err := validateEligibility(eligibility, *event); err != nil {
			return err
		}
		if err := p.store.writeJSONOnce(p.store.eligibilityPath(ref, sequence), eligibility); err != nil {
			return err
		}
		wrote = true
		return nil
	}); err != nil {
		return err
	}
	if wrote {
		return p.inject(FaultAfterServingEligibility, envelope)
	}
	return nil
}

func (p *Processor) publishEvent(
	ctx context.Context,
	ref ConnectorRef,
	sequence uint64,
	publisher Publisher,
	rejectPublished bool,
) error {
	var intent PublicationIntent
	var eventEnvelope protocol.ConnectorEventEnvelope
	var eligibility ServingEligibility
	var sourceID string
	skip := false
	needsIntent := false
	if err := p.store.withLock(func() error {
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		published := uint64(0)
		if state.cursor.Serving != nil {
			published = state.cursor.Serving.Sequence
		}
		if sequence <= published {
			if rejectPublished {
				return ErrStalePublication
			}
			skip = true
			return nil
		}
		if sequence != published+1 {
			return ErrPublicationOrder
		}
		if sequence > uint64(len(state.events)) {
			return ErrPublicationOrder
		}
		event := &state.events[sequence-1]
		eventEnvelope = event.entry.Event
		if pendingEventWouldResurrect(state, *event) {
			return ErrTombstoneResurrection
		}
		if event.eligibility == nil {
			return ErrNotServingEligible
		}
		if event.publicationReceipt != nil {
			if rejectPublished {
				return ErrStalePublication
			}
			skip = true
			return nil
		}
		if event.publicationIntent != nil {
			intent = clonePublicationIntent(*event.publicationIntent)
			return intent.Validate()
		}
		eligibility = *event.eligibility
		eligibility.Tombstone = cloneTombstone(event.eligibility.Tombstone)
		eligibility.ReconciliationTombstones = cloneReconciliationTombstones(
			event.eligibility.ReconciliationTombstones,
		)
		sourceID = state.registration.SourceID
		needsIntent = true
		return nil
	}); err != nil {
		return err
	}
	if skip {
		return nil
	}
	if needsIntent {
		createdAt, err := p.now()
		if err != nil {
			return err
		}
		digest, err := canonicalContentDigest(eligibility)
		if err != nil {
			return err
		}
		intent = PublicationIntent{
			Version: ConnectorCoreVersion, TenantID: eventEnvelope.TenantID,
			ConnectorID: eventEnvelope.ConnectorID, SourceID: sourceID,
			EventID: eventEnvelope.EventID, EventFingerprint: eligibility.Fingerprint,
			Sequence: sequence, Eligibility: eligibility, EligibilityDigest: digest, CreatedAt: createdAt,
		}
		if err := intent.Validate(); err != nil {
			return err
		}
		if err := p.inject(FaultBeforePublicationIntent, eventEnvelope); err != nil {
			return err
		}
		wroteIntent := false
		if err := p.store.withLock(func() error {
			state, err := p.store.loadStateLocked(ref, true)
			if err != nil {
				return err
			}
			published := uint64(0)
			if state.cursor.Serving != nil {
				published = state.cursor.Serving.Sequence
			}
			if sequence != published+1 || sequence > uint64(len(state.events)) {
				return ErrPublicationOrder
			}
			event := &state.events[sequence-1]
			if pendingEventWouldResurrect(state, *event) {
				return ErrTombstoneResurrection
			}
			if event.publicationReceipt != nil {
				return nil
			}
			if event.entry.Event != eventEnvelope || event.eligibility == nil ||
				!reflect.DeepEqual(*event.eligibility, eligibility) || state.registration.SourceID != sourceID {
				return ErrPublicationConflict
			}
			if event.publicationIntent != nil {
				if !reflect.DeepEqual(*event.publicationIntent, intent) {
					return ErrPublicationConflict
				}
				return nil
			}
			if err := p.store.writeJSONOnce(p.store.publicationIntentPath(ref, sequence), intent); err != nil {
				return err
			}
			wroteIntent = true
			return nil
		}); err != nil {
			return err
		}
		if wroteIntent {
			if err := p.inject(FaultAfterPublicationIntent, eventEnvelope); err != nil {
				return err
			}
		}
	}
	if err := p.ensurePendingEventNotTerminal(ref, sequence, intent.EventFingerprint); err != nil {
		return err
	}
	if err := p.inject(FaultBeforePublish, eventEnvelope); err != nil {
		return err
	}
	if err := publisher.Publish(ctx, clonePublicationIntent(intent)); err != nil {
		return fmt.Errorf("publish connector event: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.inject(FaultAfterPublish, eventEnvelope); err != nil {
		return err
	}
	if err := p.inject(FaultBeforePublicationReceipt, eventEnvelope); err != nil {
		return err
	}
	publishedAt, err := p.now()
	if err != nil {
		return err
	}
	receipt := PublicationReceipt{
		Version: ConnectorCoreVersion, TenantID: intent.TenantID, ConnectorID: intent.ConnectorID,
		SourceID: intent.SourceID, EventID: intent.EventID, EventFingerprint: intent.EventFingerprint,
		Sequence: intent.Sequence, EligibilityDigest: intent.EligibilityDigest,
		SourceWatermark: intent.Eligibility.Checkpoint.SourceWatermark,
		ACLWatermark:    intent.Eligibility.Checkpoint.ACLWatermark, PublishedAt: publishedAt,
	}
	if err := receipt.ValidateFor(intent); err != nil {
		return err
	}
	wroteReceipt := false
	if err := p.store.withLock(func() error {
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		if sequence > uint64(len(state.events)) {
			return ErrPublicationConflict
		}
		event := &state.events[sequence-1]
		if event.publicationReceipt != nil {
			return nil
		}
		if event.publicationIntent == nil || !reflect.DeepEqual(*event.publicationIntent, intent) {
			return ErrPublicationConflict
		}
		if err := p.store.writeJSONOnce(p.store.publicationReceiptPath(ref, sequence), receipt); err != nil {
			return err
		}
		wroteReceipt = true
		return nil
	}); err != nil {
		return err
	}
	if wroteReceipt {
		if err := p.inject(FaultAfterPublicationReceipt, eventEnvelope); err != nil {
			return err
		}
	}
	return p.store.withLock(func() error {
		_, err := p.store.loadStateLocked(ref, true)
		return err
	})
}

func clonePublicationIntent(intent PublicationIntent) PublicationIntent {
	clone := intent
	clone.Eligibility.Tombstone = cloneTombstone(intent.Eligibility.Tombstone)
	clone.Eligibility.ReconciliationTombstones = cloneReconciliationTombstones(
		intent.Eligibility.ReconciliationTombstones,
	)
	return clone
}

func (p *Processor) loadEventLocked(
	ref ConnectorRef,
	sequence uint64,
	fingerprint protocol.ConnectorEventFingerprint,
) (durableState, *durableEvent, error) {
	state, err := p.store.loadStateLocked(ref, true)
	if err != nil {
		return durableState{}, nil, err
	}
	if sequence == 0 || sequence > uint64(len(state.events)) {
		return durableState{}, nil, ErrJournalConflict
	}
	event := &state.events[sequence-1]
	if event.entry.EventFingerprint != fingerprint {
		return durableState{}, nil, ErrJournalConflict
	}
	return state, event, nil
}

func (p *Processor) ensureNoPendingReconciliationLocked(ref ConnectorRef) error {
	var pending ReconciliationReservation
	found, err := p.store.readOptionalJSON(p.store.reconciliationPendingPath(ref), &pending)
	if err != nil || !found {
		return err
	}
	if err := pending.Validate(); err != nil {
		return fmt.Errorf("%w: pending reconciliation: %v", ErrStoreIntegrity, err)
	}
	var receipt ReconciliationReservationReceipt
	found, err = p.store.readOptionalJSON(
		p.store.reconciliationReservationReceiptPath(ref, pending.RequestDigest), &receipt,
	)
	if err != nil {
		return err
	}
	if found {
		if err := receipt.ValidateFor(pending); err != nil {
			return fmt.Errorf("%w: reconciliation receipt: %v", ErrStoreIntegrity, err)
		}
		return p.store.removeFileDurably(p.store.reconciliationPendingPath(ref))
	}
	return ErrPendingReconciliation
}

func (p *Processor) recoverStandaloneReconciliation(ctx context.Context, ref ConnectorRef) error {
	var pending ReconciliationReservation
	found := false
	if err := p.store.withLock(func() error {
		var err error
		found, err = p.store.readOptionalJSON(p.store.reconciliationPendingPath(ref), &pending)
		if err != nil || !found {
			return err
		}
		if err := pending.Validate(); err != nil {
			return fmt.Errorf("%w: pending reconciliation: %v", ErrStoreIntegrity, err)
		}
		if err := p.requireQuiescentConnectorLocked(ref); err != nil {
			return err
		}
		var receipt ReconciliationReservationReceipt
		if receiptFound, err := p.store.readOptionalJSON(
			p.store.reconciliationReservationReceiptPath(ref, pending.RequestDigest), &receipt,
		); err != nil {
			return err
		} else if receiptFound {
			if err := receipt.ValidateFor(pending); err != nil {
				return fmt.Errorf("%w: reconciliation receipt: %v", ErrStoreIntegrity, err)
			}
			found = false
			return p.store.removeFileDurably(p.store.reconciliationPendingPath(ref))
		}
		return nil
	}); err != nil || !found {
		return err
	}
	if isNilReconciliationProjector(p.reconciler) {
		return ErrReconciliationProjectorRequired
	}
	if err := p.reconciler.ApplyReconciliation(ctx, cloneReconciliationRequest(pending.Request)); err != nil {
		return fmt.Errorf("recover connector reconciliation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	appliedAt, err := p.now()
	if err != nil {
		return err
	}
	derivedTombstones, err := newReconciliationTombstones(
		pending.Request, pending.RequestDigest,
	)
	if err != nil {
		return err
	}
	receipt := ReconciliationReservationReceipt{
		Version: ConnectorCoreVersion, TenantID: pending.Request.SourceOwnership.TenantID,
		ConnectorID: pending.Request.SourceOwnership.ConnectorID,
		SourceID:    pending.Request.SourceOwnership.SourceID, PlanDigest: pending.Request.Plan.Digest,
		RequestDigest: pending.RequestDigest, Request: cloneReconciliationRequest(pending.Request),
		DerivedTombstones: derivedTombstones, AppliedAt: appliedAt,
	}
	if err := receipt.ValidateFor(pending); err != nil {
		return err
	}
	return p.store.withLock(func() error {
		var current ReconciliationReservation
		found, err := p.store.readOptionalJSON(p.store.reconciliationPendingPath(ref), &current)
		if err != nil {
			return err
		}
		if !found || current.RequestDigest != pending.RequestDigest ||
			!reconciliationRequestsEqual(current.Request, pending.Request) {
			return ErrPendingReconciliation
		}
		if err := p.store.writeJSONOnce(
			p.store.reconciliationReservationReceiptPath(ref, pending.RequestDigest), receipt,
		); err != nil {
			return err
		}
		return p.store.removeFileDurably(p.store.reconciliationPendingPath(ref))
	})
}

func classifyApplyError(err error) (string, bool) {
	var applyError *ApplyError
	if errors.As(err, &applyError) {
		if validationErr := validateErrorCode(applyError.Code); validationErr == nil {
			return applyError.Code, applyError.Retryable
		}
		return "invalid-error-code", false
	}
	return "projector-error", true
}

func deterministicTombstone(entry JournalEntry) (protocol.ConnectorTombstone, error) {
	event := entry.Event
	tombstone := protocol.ConnectorTombstone{
		Version: protocol.EnterpriseContractVersion, TenantID: event.TenantID,
		ConnectorID: event.ConnectorID, EventID: event.EventID,
		EventFingerprint: entry.EventFingerprint, IdempotencyKey: event.IdempotencyKey,
		Sequence: event.Sequence, ResourceID: event.ResourceID,
		SourceWatermark: event.SourceWatermark, ACLWatermark: event.ACLWatermark,
		ReasonCode: "source-delete", DeletedAt: event.OccurredAt,
	}
	if err := tombstone.ValidateFor(event); err != nil {
		return protocol.ConnectorTombstone{}, err
	}
	return tombstone, nil
}

func processResultFor(event durableEvent, idempotent bool) ProcessResult {
	result := ProcessResult{
		Event: event.entry.Event, Fingerprint: event.entry.EventFingerprint, Idempotent: idempotent,
	}
	if event.delivery != nil {
		receipt := event.delivery.Receipt
		result.Receipt = &receipt
	}
	if event.reconciliation != nil {
		receipt := *event.reconciliation
		result.Reconciliation = &receipt
	}
	if event.deadLetter != nil {
		receipt := event.deadLetter.Receipt
		result.Receipt = &receipt
		result.DeadLetter = true
	}
	if event.checkpoint != nil {
		checkpoint := *event.checkpoint
		result.Checkpoint = &checkpoint
	}
	if event.eligibility != nil {
		eligibility := *event.eligibility
		result.Eligibility = &eligibility
	}
	if event.publicationReceipt != nil {
		receipt := *event.publicationReceipt
		result.Publication = &receipt
	}
	return result
}

func (p *Processor) currentResult(
	ref ConnectorRef,
	sequence uint64,
	idempotent bool,
	fallback ProcessResult,
) ProcessResult {
	result := fallback
	_ = p.store.withLock(func() error {
		state, err := p.store.loadStateLocked(ref, true)
		if err != nil || sequence == 0 || sequence > uint64(len(state.events)) {
			return err
		}
		result = processResultFor(state.events[sequence-1], idempotent)
		return nil
	})
	return result
}

func (p *Processor) inject(point FaultPoint, event protocol.ConnectorEventEnvelope) error {
	if p.faults == nil {
		return nil
	}
	return p.faults.Inject(point, event)
}

func (p *Processor) now() (time.Time, error) {
	value := p.clock()
	if value.IsZero() {
		return time.Time{}, fmt.Errorf("connector clock returned zero time")
	}
	return value.UTC(), nil
}

func isNilCallback(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
