package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestSnapshotReconciliationDeletionIsDurableAndTerminal(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "snapshot-stale", "content")
	if _, err := setup.Process(
		context.Background(), ref, stale, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatalf("seed stale resource: %v", err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "snapshot-stale")},
		[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "snapshot-stale")},
	)
	event := testSnapshotCompletionEvent(t, ref, 2, authoritative)
	var request ReconciliationApplyRequest
	var publication PublicationIntent
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now,
		ReconciliationProjector: ReconciliationProjectorFunc(func(
			_ context.Context,
			value ReconciliationApplyRequest,
		) error {
			request = value
			return nil
		}),
		Publisher: PublisherFunc(func(_ context.Context, intent PublicationIntent) error {
			publication = intent
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if err != nil {
		t.Fatalf("ProcessSnapshot: %v", err)
	}
	if result.Reconciliation == nil || result.Eligibility == nil || result.Publication == nil {
		t.Fatalf("incomplete snapshot result: %+v", result)
	}
	requestDigest, err := canonicalContentDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	authoritativeDigest, err := authoritativeSnapshotDigest(authoritative)
	if err != nil {
		t.Fatal(err)
	}
	projectedDigest, err := projectionSnapshotDigest(projected)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reconciliation.DerivedTombstones) != 1 {
		t.Fatalf("derived tombstones = %+v", result.Reconciliation.DerivedTombstones)
	}
	tombstone := result.Reconciliation.DerivedTombstones[0]
	if tombstone.TenantID != ref.Scope.TenantID || tombstone.ConnectorID != ref.ConnectorID ||
		tombstone.SourceID != "source-1" || tombstone.ResourceID != stale.ResourceID ||
		tombstone.RequestDigest != requestDigest || tombstone.AuthoritativeSnapshotDigest != authoritativeDigest ||
		tombstone.ProjectedSnapshotDigest != projectedDigest || tombstone.PlanDigest != request.Plan.Digest ||
		tombstone.SourceWatermark != authoritative.SourceWatermark ||
		tombstone.ACLWatermark != authoritative.ACLWatermark || tombstone.ProjectionBaseSequence != 1 ||
		tombstone.SnapshotEventFingerprint != result.Fingerprint || tombstone.SnapshotSequence != event.Sequence ||
		!tombstone.DeletedAt.Equal(authoritative.CapturedAt) {
		t.Fatalf("tombstone does not bind exact reconciliation: %+v", tombstone)
	}
	if !reflect.DeepEqual(result.Eligibility.ReconciliationTombstones, []ReconciliationTombstone{tombstone}) ||
		!reflect.DeepEqual(publication.Eligibility.ReconciliationTombstones, []ReconciliationTombstone{tombstone}) {
		t.Fatalf("publication omitted terminal tombstone: result=%+v publication=%+v", result.Eligibility, publication)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restartedStore.Replay(ref)
	if err != nil {
		t.Fatalf("Replay after restart: %v", err)
	}
	if len(replay.Resources) != 1 || replay.Resources[0].State != ReplayResourceTombstoned ||
		replay.Resources[0].ReconciliationTombstone == nil ||
		!reflect.DeepEqual(*replay.Resources[0].ReconciliationTombstone, tombstone) {
		t.Fatalf("restart replay lost terminal tombstone: %+v", replay.Resources)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var applyCalls atomic.Int32
	resurrection := testConnectorEvent(t, ref, 3, protocol.ConnectorContentUpsert, "snapshot-stale", "resurrection")
	if _, err := restarted.Process(
		context.Background(), ref, resurrection, successfulTestProjector(t, &applyCalls),
	); !errors.Is(err, ErrTombstoneResurrection) {
		t.Fatalf("restart resurrection error = %v, want ErrTombstoneResurrection", err)
	}
	if applyCalls.Load() != 0 {
		t.Fatalf("terminal resource reached projector: %d", applyCalls.Load())
	}
}

func TestSnapshotReplayIsDeterministicAcrossProcessorClocks(t *testing.T) {
	type replayResult struct {
		data      []byte
		digest    protocol.ContentDigest
		appliedAt time.Time
	}
	run := func(root string, clockStart time.Time) replayResult {
		t.Helper()
		clock := &testClock{next: clockStart}
		store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
		stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "clock-stale", "content")
		if _, err := processor.Process(
			context.Background(), ref, stale, successfulTestProjector(t, &atomic.Int32{}),
		); err != nil {
			t.Fatalf("seed stale resource: %v", err)
		}
		authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
		projected := reconciliationProjectionSnapshot(
			ref, 1,
			[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "clock-stale")},
			[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "clock-stale")},
		)
		event := testSnapshotCompletionEvent(t, ref, 2, authoritative)
		result, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
		if err != nil {
			t.Fatalf("ProcessSnapshot: %v", err)
		}
		data, err := store.ReplayJSON(ref)
		if err != nil {
			t.Fatalf("ReplayJSON: %v", err)
		}
		report, err := store.Replay(ref)
		if err != nil {
			t.Fatalf("Replay: %v", err)
		}
		if result.Reconciliation == nil || len(result.Reconciliation.DerivedTombstones) != 1 ||
			!result.Reconciliation.DerivedTombstones[0].DeletedAt.Equal(authoritative.CapturedAt) {
			t.Fatalf("reconciliation tombstone did not use source capture time: %+v", result.Reconciliation)
		}
		return replayResult{data: data, digest: report.Digest, appliedAt: result.Reconciliation.AppliedAt}
	}

	first := run(filepath.Join(t.TempDir(), "first"), time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC))
	second := run(filepath.Join(t.TempDir(), "second"), time.Date(2026, time.July, 18, 8, 0, 0, 0, time.UTC))
	if first.appliedAt.Equal(second.appliedAt) {
		t.Fatalf("test clocks did not produce different operational times: %s", first.appliedAt)
	}
	if !reflect.DeepEqual(first.data, second.data) || first.digest != second.digest {
		t.Fatalf(
			"identical source inputs produced different replay output:\nfirst=%s\nsecond=%s\nfirst digest=%s second digest=%s",
			first.data, second.data, first.digest, second.digest,
		)
	}
}

func TestStandaloneReconciliationBindsExactSnapshotDigests(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "standalone-stale", "content")
	if _, err := processor.Process(
		context.Background(), ref, stale, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "projected-v1")},
		[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "projected-v1")},
	)
	projectorFailure := errors.New("reconciliation unavailable")
	var firstRequest ReconciliationApplyRequest
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
			firstRequest = request
			return projectorFailure
		}),
	); !errors.Is(err, projectorFailure) {
		t.Fatalf("first reconciliation error = %v", err)
	}
	variantAuthoritative := authoritative
	variantAuthoritative.CapturedAt = variantAuthoritative.CapturedAt.Add(time.Minute)
	variantProjected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "projected-v2")},
		[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "projected-v2")},
	)
	firstPlan, err := processor.PlanReconciliation(ref, authoritative, projected)
	if err != nil {
		t.Fatal(err)
	}
	variantPlan, err := processor.PlanReconciliation(ref, variantAuthoritative, variantProjected)
	if err != nil {
		t.Fatal(err)
	}
	if firstPlan.Digest != variantPlan.Digest {
		t.Fatalf("test snapshots unexpectedly changed plan: first=%s variant=%s", firstPlan.Digest, variantPlan.Digest)
	}
	var conflictingCalls atomic.Int32
	if _, err := processor.Reconcile(
		context.Background(), ref, variantAuthoritative, variantProjected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			conflictingCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrPendingReconciliation) {
		t.Fatalf("same-plan different-snapshot error = %v, want ErrPendingReconciliation", err)
	}
	if conflictingCalls.Load() != 0 {
		t.Fatalf("different exact snapshots reached projector: %d", conflictingCalls.Load())
	}
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected, successfulTestReconciler(),
	); err != nil {
		t.Fatalf("exact reconciliation resume: %v", err)
	}
	requestDigest, err := canonicalContentDigest(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ReconciliationReservationReceipt
	if err := store.readJSON(store.reconciliationReservationReceiptPath(ref, requestDigest), &receipt); err != nil {
		t.Fatal(err)
	}
	if !reconciliationRequestsEqual(receipt.Request, firstRequest) || receipt.RequestDigest != requestDigest ||
		receipt.Request.AuthoritativeSnapshotDigest == "" || receipt.Request.ProjectedSnapshotDigest == "" ||
		receipt.Request.ProjectionBaseSequence != 1 || len(receipt.DerivedTombstones) != 1 {
		t.Fatalf("receipt omitted exact snapshot request: %+v", receipt)
	}
	if _, err := os.Stat(store.reconciliationPendingPath(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed reservation remains pending: %v", err)
	}
}

func TestStandaloneReconciliationReplayBindsAndAppliesAuthoritativeState(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	resourceID := reconciliationResourceID(t, ref.Scope.TenantID, "standalone-authoritative")
	authoritativeResource := reconciliationAuthoritativeResource(resourceID, "standalone-authoritative")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{authoritativeResource})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	var request ReconciliationApplyRequest
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(_ context.Context, value ReconciliationApplyRequest) error {
			request = cloneReconciliationRequest(value)
			return nil
		}),
	); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("bound request validation: %v", err)
	}
	if request.IdempotencyKey == "" ||
		!reflect.DeepEqual(request.AuthoritativeResources, []AuthoritativeResource{authoritativeResource}) {
		t.Fatalf("request omitted authoritative replay binding: %+v", request)
	}

	tamperedKey := cloneReconciliationRequest(request)
	tamperedKey.IdempotencyKey = protocol.NewContentDigest("different-reconciliation-request")
	if err := tamperedKey.Validate(); err == nil {
		t.Fatal("request accepted an idempotency key that did not bind its exact payload")
	}
	tamperedResource := cloneReconciliationRequest(request)
	tamperedResource.AuthoritativeResources[0].ContentDigest = protocol.NewContentDigest("tampered-content")
	if err := bindReconciliationIdempotencyKey(&tamperedResource); err != nil {
		t.Fatal(err)
	}
	if err := tamperedResource.Validate(); err == nil {
		t.Fatal("request accepted resources that did not match its authoritative snapshot digest")
	}

	replay, err := store.Replay(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Resources) != 1 {
		t.Fatalf("standalone replay resources = %+v", replay.Resources)
	}
	resource := replay.Resources[0]
	if resource.ResourceID != resourceID || resource.State != ReplayResourceActive || resource.LastSequence != 0 ||
		resource.SourceWatermark != authoritativeResource.SourceWatermark ||
		resource.ACLWatermark != authoritativeResource.ACLWatermark ||
		resource.ContentDigest != authoritativeResource.ContentDigest || resource.ACLDigest != authoritativeResource.ACLDigest {
		t.Fatalf("standalone replay omitted authoritative state: %+v", resource)
	}
}

func TestStandaloneReconciliationRejectsUnfinishedEventBeforeReservation(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "pending-reconcile", "v1")
	if _, err := setup.Process(
		context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	fault := &oneShotFault{point: FaultAfterAppend}
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: fault, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	second := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "pending-reconcile", "v2")
	if _, err := processor.Process(
		context.Background(), ref, second, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("interrupt seq2 after append: %v", err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(second.ResourceID, "pending-reconcile")},
		[]ProjectedACL{reconciliationProjectedACL(second.ResourceID, "pending-reconcile")},
	)
	var reconciliationCalls atomic.Int32
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrPendingEvent) {
		t.Fatalf("non-quiescent reconciliation error = %v, want ErrPendingEvent", err)
	}
	if reconciliationCalls.Load() != 0 {
		t.Fatalf("non-quiescent reconciliation reached projector: %d", reconciliationCalls.Load())
	}
	if _, err := os.Stat(store.reconciliationPendingPath(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-quiescent reconciliation persisted reservation: %v", err)
	}
	var eventCalls atomic.Int32
	if _, err := processor.Recover(
		context.Background(), ref, successfulTestProjector(t, &eventCalls),
	); err != nil {
		t.Fatalf("Recover legitimate pending event: %v", err)
	}
	if eventCalls.Load() != 1 {
		t.Fatalf("legitimate pending event apply calls = %d, want 1", eventCalls.Load())
	}
	replay, err := store.Replay(ref)
	if err != nil {
		t.Fatalf("Replay after legitimate recovery: %v", err)
	}
	if len(replay.Resources) != 1 || replay.Resources[0].State != ReplayResourceActive ||
		replay.Resources[0].LastSequence != 2 {
		t.Fatalf("legitimate recovery replay = %+v", replay.Resources)
	}
}

func TestProcessSnapshotRejectsStaleProjectionBaseBeforeCallbacks(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "projection-base-a", "v1")
	if _, err := processor.Process(
		context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	staleProjected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(first.ResourceID, "projection-base-a")},
		[]ProjectedACL{reconciliationProjectedACL(first.ResourceID, "projection-base-a")},
	)
	second := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "projection-base-b", "v1")
	if _, err := processor.Process(
		context.Background(), ref, second, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(first.ResourceID, "projection-base-a"),
	})
	var reconciliationCalls atomic.Int32
	var publicationCalls atomic.Int32
	processor.reconciler = ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
		reconciliationCalls.Add(1)
		return nil
	})
	processor.publisher = PublisherFunc(func(context.Context, PublicationIntent) error {
		publicationCalls.Add(1)
		return nil
	})
	snapshot := testSnapshotCompletionEvent(t, ref, 3, authoritative)
	if _, err := processor.ProcessSnapshot(
		context.Background(), ref, snapshot, authoritative, staleProjected,
	); !errors.Is(err, ErrProjectionBaseMismatch) {
		t.Fatalf("stale projection base error = %v, want ErrProjectionBaseMismatch", err)
	}
	if reconciliationCalls.Load() != 0 || publicationCalls.Load() != 0 {
		t.Fatalf(
			"stale projection reached callbacks: reconciliation=%d publication=%d",
			reconciliationCalls.Load(), publicationCalls.Load(),
		)
	}
	journal, err := store.Journal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(journal) != 2 {
		t.Fatalf("stale projection appended snapshot event: journal=%+v", journal)
	}
}

func TestStandaloneReconciliationRejectsStaleProjectionBase(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "standalone-base-a", "v1")
	if _, err := processor.Process(
		context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	staleProjected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(first.ResourceID, "standalone-base-a")},
		[]ProjectedACL{reconciliationProjectedACL(first.ResourceID, "standalone-base-a")},
	)
	second := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "standalone-base-b", "v1")
	if _, err := processor.Process(
		context.Background(), ref, second, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(first.ResourceID, "standalone-base-a"),
		reconciliationAuthoritativeResource(second.ResourceID, "standalone-base-b"),
	})
	var reconciliationCalls atomic.Int32
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, staleProjected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrProjectionBaseMismatch) {
		t.Fatalf("standalone stale projection base error = %v, want ErrProjectionBaseMismatch", err)
	}
	if reconciliationCalls.Load() != 0 {
		t.Fatalf("standalone stale projection reached projector: %d", reconciliationCalls.Load())
	}
	if _, err := os.Stat(store.reconciliationPendingPath(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("standalone stale projection persisted reservation: %v", err)
	}
}

func TestProjectionSnapshotDigestBindsBaseSequence(t *testing.T) {
	_, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	baseZero := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	baseOne := baseZero
	baseOne.ProjectionBaseSequence = 1
	zeroDigest, err := projectionSnapshotDigest(baseZero)
	if err != nil {
		t.Fatal(err)
	}
	oneDigest, err := projectionSnapshotDigest(baseOne)
	if err != nil {
		t.Fatal(err)
	}
	if zeroDigest == oneDigest {
		t.Fatalf("projection snapshot digest omitted base sequence: %s", zeroDigest)
	}
}

func TestStandaloneReconciliationRevalidatesQuiescenceBeforeReservationWrite(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "reservation-race", "v1")
	if _, err := processor.Process(
		context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	second := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "reservation-race", "v2")
	fingerprint, err := protocol.NewConnectorEventFingerprint(second)
	if err != nil {
		t.Fatal(err)
	}
	appendedAt := time.Date(2026, time.July, 17, 13, 30, 0, 0, time.UTC)
	entry := JournalEntry{
		Version: ConnectorCoreVersion, Event: second, EventFingerprint: fingerprint, AppendedAt: appendedAt,
	}
	if err := entry.ValidateFor(ref); err != nil {
		t.Fatal(err)
	}
	var injected atomic.Bool
	var injectionErr error
	processor.clock = func() time.Time {
		if injected.CompareAndSwap(false, true) {
			injectionErr = store.withLock(func() error {
				return store.writeJSONOnce(store.journalPath(ref, second.Sequence), entry)
			})
		}
		return appendedAt.Add(time.Second)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(first.ResourceID, "reservation-race")},
		[]ProjectedACL{reconciliationProjectedACL(first.ResourceID, "reservation-race")},
	)
	var reconciliationCalls atomic.Int32
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrPendingEvent) {
		t.Fatalf("reservation revalidation error = %v, want ErrPendingEvent", err)
	}
	if injectionErr != nil {
		t.Fatalf("inject unfinished event between quiescence checks: %v", injectionErr)
	}
	if reconciliationCalls.Load() != 0 {
		t.Fatalf("reservation race reached projector: %d", reconciliationCalls.Load())
	}
	if _, err := os.Stat(store.reconciliationPendingPath(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reservation race persisted pending request: %v", err)
	}
}

func TestPublishedEventRemainsIdempotentAfterLaterReconciliationTombstone(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "published-before-delete", "v1")
	var applyCalls atomic.Int32
	if _, err := processor.Process(
		context.Background(), ref, event, successfulTestProjector(t, &applyCalls),
	); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(
		ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(event.ResourceID, "published-before-delete")},
		[]ProjectedACL{reconciliationProjectedACL(event.ResourceID, "published-before-delete")},
	)
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected, successfulTestReconciler(),
	); err != nil {
		t.Fatalf("terminal reconciliation after publication: %v", err)
	}
	duplicate, err := processor.Process(
		context.Background(), ref, event, successfulTestProjector(t, &applyCalls),
	)
	if err != nil {
		t.Fatalf("published duplicate after terminal reconciliation: %v", err)
	}
	if !duplicate.Idempotent || applyCalls.Load() != 1 {
		t.Fatalf("published duplicate result=%+v apply calls=%d", duplicate, applyCalls.Load())
	}
	replay, err := store.Replay(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Resources) != 1 || replay.Resources[0].State != ReplayResourceTombstoned {
		t.Fatalf("published-then-terminal replay = %+v", replay.Resources)
	}
}

func TestLegacyReconciliationTombstoneBlocksPendingEventRecoveryAndRetry(t *testing.T) {
	for _, kind := range []protocol.ConnectorEventKind{
		protocol.ConnectorContentUpsert,
		protocol.ConnectorACLReplace,
	} {
		t.Run(string(kind), func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
			first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "legacy-pending", "v1")
			if _, err := setup.Process(
				context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
			); err != nil {
				t.Fatal(err)
			}
			var publicationCalls atomic.Int32
			processor, err := NewProcessor(store, ProcessorOptions{
				Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterAppend},
				Publisher: PublisherFunc(func(context.Context, PublicationIntent) error {
					publicationCalls.Add(1)
					return nil
				}),
				ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			second := testConnectorEvent(t, ref, 2, kind, "legacy-pending", "v2")
			if _, err := processor.Process(
				context.Background(), ref, second, successfulTestProjector(t, &atomic.Int32{}),
			); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("interrupt seq2 after append: %v", err)
			}
			persistLegacyStandaloneDeletion(t, store, processor, ref, second.ResourceID)

			var applyCalls atomic.Int32
			if _, err := processor.Recover(
				context.Background(), ref, successfulTestProjector(t, &applyCalls),
			); !errors.Is(err, ErrTombstoneResurrection) {
				t.Fatalf("Recover terminal conflict error = %v, want ErrTombstoneResurrection", err)
			}
			if applyCalls.Load() != 0 || publicationCalls.Load() != 0 {
				t.Fatalf("terminal conflict reached callbacks: apply=%d publish=%d", applyCalls.Load(), publicationCalls.Load())
			}
			if _, err := processor.Process(
				context.Background(), ref, second, successfulTestProjector(t, &applyCalls),
			); !errors.Is(err, ErrTombstoneResurrection) {
				t.Fatalf("Process retry terminal conflict error = %v, want ErrTombstoneResurrection", err)
			}
			if applyCalls.Load() != 0 || publicationCalls.Load() != 0 {
				t.Fatalf("terminal Process retry reached callbacks: apply=%d publish=%d", applyCalls.Load(), publicationCalls.Load())
			}
			replay, err := store.Replay(ref)
			if err != nil {
				t.Fatalf("fail-closed replay: %v", err)
			}
			if len(replay.Resources) != 1 || replay.Resources[0].State != ReplayResourceTombstoned {
				t.Fatalf("fail-closed replay resources = %+v", replay.Resources)
			}
		})
	}
}

func TestLegacyReconciliationTombstoneBlocksDirectPublication(t *testing.T) {
	for _, kind := range []protocol.ConnectorEventKind{
		protocol.ConnectorContentUpsert,
		protocol.ConnectorACLReplace,
	} {
		t.Run(string(kind), func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
			first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "legacy-publish", "v1")
			if _, err := setup.Process(
				context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
			); err != nil {
				t.Fatal(err)
			}
			var publicationCalls atomic.Int32
			publisher := PublisherFunc(func(context.Context, PublicationIntent) error {
				publicationCalls.Add(1)
				return nil
			})
			processor, err := NewProcessor(store, ProcessorOptions{
				Clock: clock.Now, Faults: &oneShotFault{point: FaultBeforePublish}, Publisher: publisher,
				ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			second := testConnectorEvent(t, ref, 2, kind, "legacy-publish", "v2")
			if _, err := processor.Process(
				context.Background(), ref, second, successfulTestProjector(t, &atomic.Int32{}),
			); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("interrupt seq2 before publish: %v", err)
			}
			if publicationCalls.Load() != 0 {
				t.Fatalf("publisher called before injected crash: %d", publicationCalls.Load())
			}
			persistLegacyStandaloneDeletion(t, store, processor, ref, second.ResourceID)
			if err := processor.Publish(context.Background(), ref, 2, publisher); !errors.Is(err, ErrTombstoneResurrection) {
				t.Fatalf("direct Publish terminal conflict error = %v, want ErrTombstoneResurrection", err)
			}
			if publicationCalls.Load() != 0 {
				t.Fatalf("terminal direct Publish reached publisher: %d", publicationCalls.Load())
			}
		})
	}
}

func TestLegacyReconciliationTombstoneBlocksPendingSnapshotRecovery(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "legacy-snapshot", "v1")
	if _, err := setup.Process(
		context.Background(), ref, first, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(first.ResourceID, "legacy-snapshot-v2"),
	})
	projected := reconciliationProjectionSnapshot(ref, 1, []ProjectedResource{}, []ProjectedACL{})
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterAppend}, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshotCompletionEvent(t, ref, 2, authoritative)
	if _, err := processor.ProcessSnapshot(
		context.Background(), ref, snapshot, authoritative, projected,
	); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("interrupt snapshot after append: %v", err)
	}
	persistLegacyStandaloneDeletion(t, store, processor, ref, first.ResourceID)
	var reconciliationCalls atomic.Int32
	processor.reconciler = ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
		reconciliationCalls.Add(1)
		return nil
	})
	if _, err := processor.Recover(
		context.Background(), ref, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, ErrTombstoneResurrection) {
		t.Fatalf("snapshot recovery terminal conflict error = %v, want ErrTombstoneResurrection", err)
	}
	if reconciliationCalls.Load() != 0 {
		t.Fatalf("terminal snapshot recovery reached reconciler: %d", reconciliationCalls.Load())
	}
}

func TestReconciliationClaimsAuthoritativeResourcesInOneDurableManifest(t *testing.T) {
	root := t.TempDir()
	store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, newTestClock())
	firstID := reconciliationResourceID(t, ref.Scope.TenantID, "missed-cdc-a")
	secondID := reconciliationResourceID(t, ref.Scope.TenantID, "missed-cdc-b")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(firstID, "a"),
		reconciliationAuthoritativeResource(secondID, "b"),
	})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	var request ReconciliationApplyRequest
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(_ context.Context, value ReconciliationApplyRequest) error {
			request = value
			return nil
		}),
	); err != nil {
		t.Fatalf("claim authoritative resources: %v", err)
	}
	entries, err := os.ReadDir(store.reconciliationOwnershipClaimsDir(ref))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IsDir() {
		t.Fatalf("ownership claims = %+v, want one atomic manifest", entries)
	}
	var claim ReconciliationOwnershipClaim
	if err := store.readJSON(
		filepath.Join(store.reconciliationOwnershipClaimsDir(ref), entries[0].Name()), &claim,
	); err != nil {
		t.Fatal(err)
	}
	wantIDs := []protocol.ResourceID{firstID, secondID}
	if firstID > secondID {
		wantIDs[0], wantIDs[1] = wantIDs[1], wantIDs[0]
	}
	if !reflect.DeepEqual(claim.ResourceIDs, wantIDs) || claim.RequestDigest == "" ||
		claim.ConnectorID != ref.ConnectorID || claim.SourceID != "source-1" {
		t.Fatalf("atomic ownership claim = %+v", claim)
	}
	for _, resourceID := range wantIDs {
		if _, err := os.Stat(store.resourceOwnershipPath(ref, resourceID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("resource %s was claimed with a partial per-resource record: %v", resourceID, err)
		}
		ownership, err := store.ResourceOwnership(ref, resourceID)
		if err != nil || ownership.BoundReconciliationDigest != requestDigestForTest(t, request) {
			t.Fatalf("claimed ownership %s = %+v err=%v", resourceID, ownership, err)
		}
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, resourceID := range wantIDs {
		if _, err := restartedStore.ResourceOwnership(ref, resourceID); err != nil {
			t.Fatalf("restart ownership %s: %v", resourceID, err)
		}
	}
	registration := Registration{
		Version: ConnectorCoreVersion, Scope: ref.Scope, ConnectorID: "connector-2",
		OwnerID: "owner-2", SourceID: "source-2",
		RegisteredAt: time.Date(2026, time.July, 17, 7, 1, 0, 0, time.UTC),
	}
	if err := restartedStore.Register(registration); err != nil {
		t.Fatal(err)
	}
	other := registration.Ref()
	otherProcessor, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: newTestClock().Now, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var crossSourceCalls atomic.Int32
	if _, err := otherProcessor.Reconcile(
		context.Background(), other,
		reconciliationAuthoritativeSnapshot(other, []AuthoritativeResource{
			reconciliationAuthoritativeResource(firstID, "cross-source"),
		}),
		reconciliationProjectionSnapshot(other, 0, []ProjectedResource{}, []ProjectedACL{}),
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			crossSourceCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrResourceOwnership) {
		t.Fatalf("cross-source claim error = %v, want ErrResourceOwnership", err)
	}
	if crossSourceCalls.Load() != 0 {
		t.Fatalf("cross-source claim reached projector: %d", crossSourceCalls.Load())
	}
	unownedProjectedID := reconciliationResourceID(t, ref.Scope.TenantID, "projected-only")
	if _, err := processor.Reconcile(
		context.Background(), ref,
		reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{}),
		reconciliationProjectionSnapshot(
			ref, 0,
			[]ProjectedResource{reconciliationProjectedResource(unownedProjectedID, "projected-only")},
			[]ProjectedACL{reconciliationProjectedACL(unownedProjectedID, "projected-only")},
		),
		successfulTestReconciler(),
	); !errors.Is(err, ErrResourceOwnershipRequired) {
		t.Fatalf("projected-only ownership error = %v, want ErrResourceOwnershipRequired", err)
	}
}

func TestReconciliationOwnershipClaimSurvivesCrashBeforeReservation(t *testing.T) {
	root := t.TempDir()
	store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, newTestClock())
	resourceIDs := []protocol.ResourceID{
		reconciliationResourceID(t, ref.Scope.TenantID, "crash-claim-a"),
		reconciliationResourceID(t, ref.Scope.TenantID, "crash-claim-b"),
	}
	requestDigest := protocol.NewContentDigest("crash-before-reconciliation-reservation")
	boundAt := time.Date(2026, time.July, 17, 11, 30, 0, 0, time.UTC)
	if err := store.withLock(func() error {
		registration, err := store.loadRegistrationLocked(ref)
		if err != nil {
			return err
		}
		return store.claimReconciliationResourceOwnershipsLocked(
			ref, registration, resourceIDs, nil, "", requestDigest, boundAt,
		)
	}); err != nil {
		t.Fatalf("persist ownership claim at crash boundary: %v", err)
	}
	if _, err := os.Stat(store.reconciliationPendingPath(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("test unexpectedly persisted a reservation: %v", err)
	}

	restarted, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(restarted.reconciliationOwnershipClaimsDir(ref))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IsDir() {
		t.Fatalf("crash recovery saw ownership claims %+v, want one complete manifest", entries)
	}
	for _, resourceID := range resourceIDs {
		ownership, err := restarted.ResourceOwnership(ref, resourceID)
		if err != nil {
			t.Fatalf("restart ownership %s: %v", resourceID, err)
		}
		if ownership.BoundReconciliationDigest != requestDigest || !ownership.BoundAt.Equal(boundAt) {
			t.Fatalf("restart ownership %s lost claim binding: %+v", resourceID, ownership)
		}
		if _, err := os.Stat(restarted.resourceOwnershipPath(ref, resourceID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restart found partial per-resource ownership %s: %v", resourceID, err)
		}
	}
}

func TestSnapshotCanAtomicallyClaimResourceMissedByCDC(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	resourceID := reconciliationResourceID(t, ref.Scope.TenantID, "snapshot-missed-cdc")
	authoritativeResource := reconciliationAuthoritativeResource(resourceID, "snapshot-missed-cdc")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		authoritativeResource,
	})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); err != nil {
		t.Fatalf("ProcessSnapshot missed CDC resource: %v", err)
	}
	ownership, err := store.ResourceOwnership(ref, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if ownership.BoundEventID != event.EventID || ownership.BoundSequence != event.Sequence ||
		ownership.BoundFingerprint == "" || ownership.SourceID != "source-1" {
		t.Fatalf("snapshot ownership = %+v", ownership)
	}
	replay, err := store.Replay(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Resources) != 1 || replay.Resources[0].ResourceID != resourceID ||
		replay.Resources[0].State != ReplayResourceActive || replay.Resources[0].LastSequence != event.Sequence ||
		replay.Resources[0].SourceWatermark != authoritativeResource.SourceWatermark ||
		replay.Resources[0].ACLWatermark != authoritativeResource.ACLWatermark ||
		replay.Resources[0].ContentDigest != authoritativeResource.ContentDigest ||
		replay.Resources[0].ACLDigest != authoritativeResource.ACLDigest {
		t.Fatalf("snapshot replay omitted authoritative resource: %+v", replay.Resources)
	}
}

func TestSnapshotReplayReplacesChangedResourceWithAuthoritativeMetadata(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	content := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "snapshot-changed", "old-content")
	if _, err := processor.Process(
		context.Background(), ref, content, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatalf("seed content: %v", err)
	}
	acl := testConnectorEvent(t, ref, 2, protocol.ConnectorACLReplace, "snapshot-changed", "old-acl")
	if _, err := processor.Process(
		context.Background(), ref, acl, successfulTestProjector(t, &atomic.Int32{}),
	); err != nil {
		t.Fatalf("seed ACL: %v", err)
	}
	authoritativeResource := reconciliationAuthoritativeResource(content.ResourceID, "authoritative-v2")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{authoritativeResource})
	projected := reconciliationProjectionSnapshot(
		ref, 2,
		[]ProjectedResource{reconciliationProjectedResource(content.ResourceID, "projected-v1")},
		[]ProjectedACL{reconciliationProjectedACL(content.ResourceID, "projected-v1")},
	)
	event := testSnapshotCompletionEvent(t, ref, 3, authoritative)
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); err != nil {
		t.Fatalf("ProcessSnapshot changed resource: %v", err)
	}
	replay, err := store.Replay(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Resources) != 1 {
		t.Fatalf("replay resources = %+v", replay.Resources)
	}
	resource := replay.Resources[0]
	if resource.ResourceID != content.ResourceID || resource.State != ReplayResourceActive ||
		resource.LastSequence != event.Sequence || resource.SourceWatermark != authoritativeResource.SourceWatermark ||
		resource.ACLWatermark != authoritativeResource.ACLWatermark ||
		resource.ContentDigest != authoritativeResource.ContentDigest || resource.ACLDigest != authoritativeResource.ACLDigest ||
		resource.Tombstone != nil || resource.ReconciliationTombstone != nil {
		t.Fatalf("replay retained stale projected metadata: %+v", resource)
	}
}

func TestProcessorClockAndFaultCallbacksRunOutsideRootStoreLock(t *testing.T) {
	run := func(t *testing.T, deadLetter bool) {
		store, processor, ref := newTestProcessor(
			t, t.TempDir(), nil, RetryPolicy{MaxAttempts: 1}, newTestClock(),
		)
		var clockMu sync.Mutex
		next := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
		var clockBlocked atomic.Bool
		processor.clock = func() time.Time {
			if !connectorRootLockAvailable(store, ref) {
				clockBlocked.Store(true)
			}
			clockMu.Lock()
			defer clockMu.Unlock()
			value := next
			next = next.Add(time.Second)
			return value
		}
		callbackUnderLock := errors.New("processor callback executed under root store lock")
		processor.faults = FaultInjectorFunc(func(FaultPoint, protocol.ConnectorEventEnvelope) error {
			if !connectorRootLockAvailable(store, ref) {
				return callbackUnderLock
			}
			return nil
		})
		if deadLetter {
			event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "dead-letter", "content")
			_, err := processor.Process(
				context.Background(), ref, event,
				ProjectorFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
					return ApplyResult{}, &ApplyError{Code: "permanent", Retryable: false}
				}),
			)
			if !errors.Is(err, ErrDeadLettered) || errors.Is(err, callbackUnderLock) {
				t.Fatalf("dead-letter processing error = %v", err)
			}
		} else {
			event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "normal", "content")
			if _, err := processor.Process(
				context.Background(), ref, event, successfulTestProjector(t, &atomic.Int32{}),
			); err != nil {
				t.Fatalf("normal processing: %v", err)
			}
			authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
				reconciliationAuthoritativeResource(event.ResourceID, "normal"),
			})
			projected := reconciliationProjectionSnapshot(ref, 1, []ProjectedResource{}, []ProjectedACL{})
			snapshotEvent := testSnapshotCompletionEvent(t, ref, 2, authoritative)
			if _, err := processor.ProcessSnapshot(
				context.Background(), ref, snapshotEvent, authoritative, projected,
			); err != nil {
				t.Fatalf("snapshot processing: %v", err)
			}
			projectedAtTwo := projected
			projectedAtTwo.ProjectionBaseSequence = 2
			if _, err := processor.Reconcile(
				context.Background(), ref, authoritative, projectedAtTwo, successfulTestReconciler(),
			); err != nil {
				t.Fatalf("standalone reconciliation: %v", err)
			}
		}
		if clockBlocked.Load() {
			t.Fatal("processor clock executed while the root store lock was held")
		}
	}
	t.Run("normal-snapshot-and-reconciliation", func(t *testing.T) { run(t, false) })
	t.Run("dead-letter", func(t *testing.T) { run(t, true) })
	t.Run("standalone-reconciliation-recovery", func(t *testing.T) {
		store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
		var clockMu sync.Mutex
		next := time.Date(2026, time.July, 17, 13, 0, 0, 0, time.UTC)
		var clockBlocked atomic.Bool
		processor.clock = func() time.Time {
			if !connectorRootLockAvailable(store, ref) {
				clockBlocked.Store(true)
			}
			clockMu.Lock()
			defer clockMu.Unlock()
			value := next
			next = next.Add(time.Second)
			return value
		}

		stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "recovery-stale", "content")
		if _, err := processor.Process(
			context.Background(), ref, stale, successfulTestProjector(t, &atomic.Int32{}),
		); err != nil {
			t.Fatal(err)
		}
		authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
		projected := reconciliationProjectionSnapshot(
			ref, 1,
			[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "recovery-stale")},
			[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "recovery-stale")},
		)
		projectorFailure := errors.New("reconciliation unavailable")
		var expected ReconciliationApplyRequest
		if _, err := processor.Reconcile(
			context.Background(), ref, authoritative, projected,
			ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
				expected = request
				return projectorFailure
			}),
		); !errors.Is(err, projectorFailure) {
			t.Fatalf("reserve reconciliation: %v", err)
		}
		processor.reconciler = successfulTestReconciler()
		if _, err := processor.Recover(
			context.Background(), ref, successfulTestProjector(t, &atomic.Int32{}),
		); err != nil {
			t.Fatalf("Recover reconciliation: %v", err)
		}
		requestDigest := requestDigestForTest(t, expected)
		var receipt ReconciliationReservationReceipt
		if err := store.readJSON(store.reconciliationReservationReceiptPath(ref, requestDigest), &receipt); err != nil {
			t.Fatal(err)
		}
		if !reconciliationRequestsEqual(receipt.Request, expected) || len(receipt.DerivedTombstones) != 1 ||
			receipt.DerivedTombstones[0].RequestDigest != requestDigest {
			t.Fatalf("recovery receipt lost exact request or tombstone: %+v", receipt)
		}
		if clockBlocked.Load() {
			t.Fatal("recovery clock executed while the root store lock was held")
		}
	})
}

func connectorRootLockAvailable(store *Store, ref ConnectorRef) bool {
	done := make(chan error, 1)
	go func() {
		_, err := store.Cursor(ref)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(time.Second):
		return false
	}
}

func persistLegacyStandaloneDeletion(
	t *testing.T,
	store *Store,
	processor *Processor,
	ref ConnectorRef,
	resourceID protocol.ResourceID,
) ReconciliationReservationReceipt {
	t.Helper()
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	var preparation reconciliationPreparation
	if err := store.withLock(func() error {
		state, err := store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		baseSequence := uint64(0)
		if state.cursor.Checkpoint != nil {
			baseSequence = state.cursor.Checkpoint.LastSequence
		}
		projected := reconciliationProjectionSnapshot(
			ref, baseSequence,
			[]ProjectedResource{reconciliationProjectedResource(resourceID, "legacy-terminal")},
			[]ProjectedACL{reconciliationProjectedACL(resourceID, "legacy-terminal")},
		)
		preparation, err = processor.prepareReconciliationLocked(ref, authoritative, projected, nil)
		return err
	}); err != nil {
		t.Fatalf("prepare legacy reconciliation: %v", err)
	}
	requestDigest := requestDigestForTest(t, preparation.request)
	appliedAt := time.Date(2026, time.July, 17, 14, 0, 0, 0, time.UTC)
	tombstones, err := newReconciliationTombstones(preparation.request, requestDigest)
	if err != nil {
		t.Fatalf("derive legacy reconciliation tombstones: %v", err)
	}
	reservation := ReconciliationReservation{
		Version: ConnectorCoreVersion, Request: cloneReconciliationRequest(preparation.request),
		RequestDigest: requestDigest, CreatedAt: appliedAt.Add(-time.Second),
	}
	receipt := ReconciliationReservationReceipt{
		Version: ConnectorCoreVersion, TenantID: preparation.request.SourceOwnership.TenantID,
		ConnectorID: preparation.request.SourceOwnership.ConnectorID,
		SourceID:    preparation.request.SourceOwnership.SourceID,
		PlanDigest:  preparation.request.Plan.Digest, RequestDigest: requestDigest,
		Request: cloneReconciliationRequest(preparation.request), DerivedTombstones: tombstones, AppliedAt: appliedAt,
	}
	if err := receipt.ValidateFor(reservation); err != nil {
		t.Fatalf("validate legacy reconciliation receipt: %v", err)
	}
	if err := store.withLock(func() error {
		return store.writeJSONOnce(store.reconciliationReservationReceiptPath(ref, requestDigest), receipt)
	}); err != nil {
		t.Fatalf("persist legacy reconciliation receipt: %v", err)
	}
	return receipt
}

func requestDigestForTest(t *testing.T, request ReconciliationApplyRequest) protocol.ContentDigest {
	t.Helper()
	digest, err := canonicalContentDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
