package connector

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

func (s *Store) Replay(ref ConnectorRef) (ReplayReport, error) {
	if err := ref.Validate(); err != nil {
		return ReplayReport{}, err
	}
	var report ReplayReport
	err := s.withLock(func() error {
		state, err := s.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		report, err = buildReplayReport(ref, state)
		return err
	})
	return report, err
}

func (s *Store) ReplayJSON(ref ConnectorRef) ([]byte, error) {
	report, err := s.Replay(ref)
	if err != nil {
		return nil, err
	}
	return deterministicJSON(report)
}

func (s *Store) Tombstones(ref ConnectorRef) ([]protocol.ConnectorTombstone, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	var tombstones []protocol.ConnectorTombstone
	err := s.withLock(func() error {
		state, err := s.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		tombstones = committedTombstones(state.events)
		return nil
	})
	return tombstones, err
}

func buildReplayReport(ref ConnectorRef, state durableState) (ReplayReport, error) {
	report := ReplayReport{
		Version: ConnectorCoreVersion, TenantID: ref.Scope.TenantID, ConnectorID: ref.ConnectorID,
		Events: []ReplayEvent{}, Resources: []ReplayResource{},
		Cursor: ReplayCursor{AppendedSequence: state.cursor.AppendedSequence},
	}
	if state.cursor.Checkpoint != nil {
		report.Cursor.CheckpointSequence = state.cursor.Checkpoint.LastSequence
		report.Cursor.SourceWatermark = state.cursor.Checkpoint.SourceWatermark
		report.Cursor.ACLWatermark = state.cursor.Checkpoint.ACLWatermark
	}
	if state.cursor.Serving != nil {
		report.Cursor.ServingSequence = state.cursor.Serving.Sequence
	}
	if state.cursor.Blocked != nil {
		report.Cursor.BlockedSequence = state.cursor.Blocked.Sequence
	}

	resources := make(map[protocol.ResourceID]ReplayResource)
	standaloneIndex := 0
	for _, durable := range state.events {
		for standaloneIndex < len(state.reconciliations) &&
			state.reconciliations[standaloneIndex].Request.ProjectionBaseSequence < durable.entry.Event.Sequence {
			receipt := state.reconciliations[standaloneIndex]
			if err := applyReconciliationState(
				resources, receipt.Request, receipt.DerivedTombstones, receipt.Request.ProjectionBaseSequence,
			); err != nil {
				return ReplayReport{}, err
			}
			standaloneIndex++
		}
		replayEvent := ReplayEvent{
			Event: durable.entry.Event, Fingerprint: durable.entry.EventFingerprint, Stage: StageAppend,
			Attempts: uint32(len(durable.attempts)),
		}
		switch {
		case durable.deadLetter != nil:
			replayEvent.Stage = StageDeadLetter
			replayEvent.Attempts = durable.deadLetter.Receipt.Attempts
			replayEvent.ErrorCode = durable.deadLetter.Receipt.ErrorCode
		case durable.publicationReceipt != nil:
			replayEvent.Stage = StagePublished
			if durable.delivery != nil {
				replayEvent.Attempts = durable.delivery.Receipt.Attempts
			}
			outputDigest, _, err := durableEventOutput(durable)
			if err != nil {
				return ReplayReport{}, err
			}
			replayEvent.ProjectionHash = outputDigest
		case durable.publicationIntent != nil:
			replayEvent.Stage = StagePublicationIntent
			if durable.delivery != nil {
				replayEvent.Attempts = durable.delivery.Receipt.Attempts
			}
			outputDigest, _, err := durableEventOutput(durable)
			if err != nil {
				return ReplayReport{}, err
			}
			replayEvent.ProjectionHash = outputDigest
		case durable.eligibility != nil:
			replayEvent.Stage = StageServingEligibility
			if durable.delivery != nil {
				replayEvent.Attempts = durable.delivery.Receipt.Attempts
			}
			replayEvent.ProjectionHash = durable.eligibility.OutputDigest
		case durable.checkpoint != nil:
			replayEvent.Stage = StageCheckpoint
			if durable.delivery != nil {
				replayEvent.Attempts = durable.delivery.Receipt.Attempts
				replayEvent.ProjectionHash = durable.delivery.Result.OutputDigest
			} else if durable.entry.SnapshotReconciliation != nil {
				replayEvent.ProjectionHash = durable.entry.SnapshotReconciliation.PlanDigest
			}
		case durable.reconciliation != nil:
			replayEvent.Stage = StageReconciliation
			replayEvent.ProjectionHash = durable.entry.SnapshotReconciliation.PlanDigest
		case durable.delivery != nil:
			replayEvent.Stage = StageReceipt
			replayEvent.Attempts = durable.delivery.Receipt.Attempts
			replayEvent.ProjectionHash = durable.delivery.Result.OutputDigest
		case len(durable.attempts) > 0:
			replayEvent.Stage = failureStageForEvent(durable.entry.Event)
		}
		report.Events = append(report.Events, replayEvent)

		if durable.checkpoint == nil {
			continue
		}
		event := durable.entry.Event
		switch event.Kind {
		case protocol.ConnectorContentUpsert:
			resource := resources[event.ResourceID]
			if resource.State == ReplayResourceTombstoned {
				return ReplayReport{}, fmt.Errorf("%w: %w: resource %s", ErrStoreIntegrity, ErrTombstoneResurrection, event.ResourceID)
			}
			resource.ResourceID = event.ResourceID
			resource.State = ReplayResourceActive
			resource.LastSequence = event.Sequence
			resource.SourceWatermark = event.SourceWatermark
			resource.ACLWatermark = event.ACLWatermark
			resource.ContentDigest = event.PayloadDigest
			resources[event.ResourceID] = resource
		case protocol.ConnectorACLReplace:
			resource := resources[event.ResourceID]
			if resource.State == ReplayResourceTombstoned {
				return ReplayReport{}, fmt.Errorf("%w: %w: resource %s", ErrStoreIntegrity, ErrTombstoneResurrection, event.ResourceID)
			}
			resource.ResourceID = event.ResourceID
			resource.State = ReplayResourceActive
			resource.LastSequence = event.Sequence
			resource.SourceWatermark = event.SourceWatermark
			resource.ACLWatermark = event.ACLWatermark
			resource.ACLDigest = event.PayloadDigest
			resources[event.ResourceID] = resource
		case protocol.ConnectorResourceTombstone:
			if durable.delivery == nil || durable.delivery.Tombstone == nil {
				return ReplayReport{}, fmt.Errorf("%w: committed tombstone has no durable tombstone", ErrStoreIntegrity)
			}
			resource := resources[event.ResourceID]
			resource.ResourceID = event.ResourceID
			resource.State = ReplayResourceTombstoned
			resource.LastSequence = event.Sequence
			resource.SourceWatermark = event.SourceWatermark
			resource.ACLWatermark = event.ACLWatermark
			resource.Tombstone = cloneTombstone(durable.delivery.Tombstone)
			resource.ReconciliationTombstone = nil
			resources[event.ResourceID] = resource
		case protocol.ConnectorSnapshotComplete:
		default:
			return ReplayReport{}, fmt.Errorf("%w: unsupported journal event kind %q", ErrStoreIntegrity, event.Kind)
		}
		if durable.reconciliation != nil {
			request := reconciliationRequestForSnapshotIntent(*durable.entry.SnapshotReconciliation)
			if err := applyReconciliationState(
				resources, request, durable.reconciliation.DerivedTombstones, event.Sequence,
			); err != nil {
				return ReplayReport{}, err
			}
		}
	}
	for standaloneIndex < len(state.reconciliations) {
		receipt := state.reconciliations[standaloneIndex]
		if err := applyReconciliationState(
			resources, receipt.Request, receipt.DerivedTombstones, receipt.Request.ProjectionBaseSequence,
		); err != nil {
			return ReplayReport{}, err
		}
		standaloneIndex++
	}

	resourceIDs := make([]protocol.ResourceID, 0, len(resources))
	for resourceID := range resources {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Slice(resourceIDs, func(i, j int) bool { return resourceIDs[i] < resourceIDs[j] })
	for _, resourceID := range resourceIDs {
		report.Resources = append(report.Resources, resources[resourceID])
	}
	digest, err := replayDigest(report)
	if err != nil {
		return ReplayReport{}, err
	}
	report.Digest = digest
	return report, nil
}

func applyReconciliationState(
	resources map[protocol.ResourceID]ReplayResource,
	request ReconciliationApplyRequest,
	tombstones []ReconciliationTombstone,
	sequence uint64,
) error {
	if err := request.Validate(); err != nil {
		return fmt.Errorf("%w: reconciliation request: %v", ErrStoreIntegrity, err)
	}
	expectedSequence := request.ProjectionBaseSequence
	if request.Snapshot != nil {
		expectedSequence = request.Snapshot.Sequence
	}
	if sequence != expectedSequence {
		return fmt.Errorf(
			"%w: reconciliation state sequence %d does not match request sequence %d",
			ErrStoreIntegrity, sequence, expectedSequence,
		)
	}
	authoritativeIDs := make(map[protocol.ResourceID]struct{}, len(request.AuthoritativeResources))
	for _, authoritative := range request.AuthoritativeResources {
		resource := resources[authoritative.ResourceID]
		if resource.State == ReplayResourceTombstoned {
			return fmt.Errorf(
				"%w: %w: resource %s",
				ErrStoreIntegrity, ErrTombstoneResurrection, authoritative.ResourceID,
			)
		}
		authoritativeIDs[authoritative.ResourceID] = struct{}{}
		resources[authoritative.ResourceID] = ReplayResource{
			ResourceID: authoritative.ResourceID, State: ReplayResourceActive, LastSequence: sequence,
			SourceWatermark: authoritative.SourceWatermark, ACLWatermark: authoritative.ACLWatermark,
			ContentDigest: authoritative.ContentDigest, ACLDigest: authoritative.ACLDigest,
		}
	}
	for index := range tombstones {
		tombstone := tombstones[index]
		if _, found := authoritativeIDs[tombstone.ResourceID]; found {
			return fmt.Errorf(
				"%w: reconciliation resource %s is both authoritative and tombstoned",
				ErrStoreIntegrity, tombstone.ResourceID,
			)
		}
		resource := resources[tombstone.ResourceID]
		resource.ResourceID = tombstone.ResourceID
		resource.State = ReplayResourceTombstoned
		resource.LastSequence = sequence
		resource.SourceWatermark = tombstone.SourceWatermark
		resource.ACLWatermark = tombstone.ACLWatermark
		resource.Tombstone = nil
		copy := tombstone
		resource.ReconciliationTombstone = &copy
		resources[tombstone.ResourceID] = resource
	}
	return nil
}

func replayDigest(report ReplayReport) (protocol.ContentDigest, error) {
	report.Digest = ""
	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return protocol.NewContentDigest(string(data)), nil
}

func committedTombstones(events []durableEvent) []protocol.ConnectorTombstone {
	tombstones := []protocol.ConnectorTombstone{}
	for _, event := range events {
		if event.checkpoint != nil && event.delivery != nil && event.delivery.Tombstone != nil {
			tombstones = append(tombstones, *event.delivery.Tombstone)
		}
	}
	sort.Slice(tombstones, func(i, j int) bool {
		if tombstones[i].ResourceID != tombstones[j].ResourceID {
			return tombstones[i].ResourceID < tombstones[j].ResourceID
		}
		return tombstones[i].Sequence < tombstones[j].Sequence
	})
	return tombstones
}

func committedReconciliationTombstones(state durableState) []ReconciliationTombstone {
	tombstones := []ReconciliationTombstone{}
	for _, event := range state.events {
		if event.reconciliation != nil {
			tombstones = append(tombstones, event.reconciliation.DerivedTombstones...)
		}
	}
	for _, receipt := range state.reconciliations {
		tombstones = append(tombstones, receipt.DerivedTombstones...)
	}
	sort.Slice(tombstones, func(i, j int) bool {
		if tombstones[i].ResourceID != tombstones[j].ResourceID {
			return tombstones[i].ResourceID < tombstones[j].ResourceID
		}
		if tombstones[i].ProjectionBaseSequence != tombstones[j].ProjectionBaseSequence {
			return tombstones[i].ProjectionBaseSequence < tombstones[j].ProjectionBaseSequence
		}
		return tombstones[i].RequestDigest < tombstones[j].RequestDigest
	})
	return tombstones
}

func committedTerminalResourceIDs(state durableState) []protocol.ResourceID {
	resourceIDs := []protocol.ResourceID{}
	for _, tombstone := range committedTombstones(state.events) {
		resourceIDs = append(resourceIDs, tombstone.ResourceID)
	}
	for _, tombstone := range committedReconciliationTombstones(state) {
		resourceIDs = append(resourceIDs, tombstone.ResourceID)
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
