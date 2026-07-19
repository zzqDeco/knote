package connector

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	phase3contract "github.com/zzqDeco/knote/tests/phase3/contract"
)

func TestSnapshotCompletionRequiresExactDurableReconciliationBeforeProgress(t *testing.T) {
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, clock)
	stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "stale", "stale-content")
	var applyCalls atomic.Int32
	if _, err := setup.Process(context.Background(), ref, stale, successfulTestProjector(t, &applyCalls)); err != nil {
		t.Fatalf("bind stale resource: %v", err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "stale")},
		[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "stale")},
	)
	event := testSnapshotCompletionEvent(t, ref, 2, authoritative)
	var received ReconciliationApplyRequest
	var reconciliationCalls atomic.Int32
	var publicationCalls atomic.Int32
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now,
		ReconciliationProjector: ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			received = request
			return nil
		}),
		Publisher: PublisherFunc(func(context.Context, PublicationIntent) error {
			publicationCalls.Add(1)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processor.Process(context.Background(), ref, event, successfulTestProjector(t, &applyCalls)); !errors.Is(err, ErrSnapshotReconciliationRequired) {
		t.Fatalf("ordinary Process snapshot error = %v, want ErrSnapshotReconciliationRequired", err)
	}
	journal, err := store.Journal(ref)
	if err != nil || len(journal) != 1 {
		t.Fatalf("snapshot bypass changed journal: len=%d err=%v", len(journal), err)
	}

	result, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if err != nil {
		t.Fatalf("ProcessSnapshot: %v", err)
	}
	if result.Reconciliation == nil || result.Checkpoint == nil || result.Eligibility == nil || result.Publication == nil {
		t.Fatalf("snapshot stages are incomplete: %+v", result)
	}
	if result.Reconciliation.ProjectionBaseSequence != projected.ProjectionBaseSequence {
		t.Fatalf("snapshot receipt base = %d, want %d", result.Reconciliation.ProjectionBaseSequence, projected.ProjectionBaseSequence)
	}
	if reconciliationCalls.Load() != 1 || publicationCalls.Load() != 1 {
		t.Fatalf("snapshot callback calls: reconciliation=%d publication=%d", reconciliationCalls.Load(), publicationCalls.Load())
	}
	wantStale := []protocol.ResourceID{stale.ResourceID}
	if !reflect.DeepEqual(received.Plan.StaleResources, wantStale) || !reflect.DeepEqual(received.Plan.StaleACLs, wantStale) {
		t.Fatalf("snapshot cleanup plan = %+v", received.Plan)
	}
	if received.ProjectionBaseSequence != projected.ProjectionBaseSequence || received.Snapshot == nil ||
		received.Snapshot.Sequence != event.Sequence ||
		received.Snapshot.ProjectionBaseSequence != projected.ProjectionBaseSequence ||
		received.Snapshot.EventFingerprint != result.Fingerprint || received.Snapshot.PlanDigest != received.Plan.Digest {
		t.Fatalf("snapshot reconciliation binding = %+v", received.Snapshot)
	}
	if received.SourceOwnership.SourceID != "source-1" || !reflect.DeepEqual(received.OwnedResourceIDs, wantStale) {
		t.Fatalf("snapshot trusted ownership = %+v ids=%v", received.SourceOwnership, received.OwnedResourceIDs)
	}
	journal, err = store.Journal(ref)
	if err != nil || len(journal) != 2 || journal[1].SnapshotReconciliation == nil {
		t.Fatalf("snapshot journal = %+v err=%v", journal, err)
	}
	intent := journal[1].SnapshotReconciliation
	if intent.AuthoritativeSnapshotDigest != event.PayloadDigest || intent.ProjectionBaseDigest != received.Snapshot.ProjectionBaseDigest ||
		intent.ProjectionBaseSequence != projected.ProjectionBaseSequence ||
		intent.PlanDigest != received.Plan.Digest || intent.SourceWatermark != event.SourceWatermark ||
		intent.ACLWatermark != event.ACLWatermark {
		t.Fatalf("snapshot durable intent = %+v", intent)
	}
	cursor, err := store.Cursor(ref)
	if err != nil || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 2 ||
		cursor.Serving == nil || cursor.Serving.Sequence != 2 {
		t.Fatalf("snapshot cursor = %+v err=%v", cursor, err)
	}
	replay, err := store.Replay(ref)
	if err != nil || len(replay.Events) != 2 || replay.Events[1].Stage != StagePublished ||
		replay.Events[1].ProjectionHash != received.Plan.Digest {
		t.Fatalf("snapshot replay = %+v err=%v", replay, err)
	}
}

func TestSnapshotReconciliationCrashResumeAndConflictFailClosed(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "stale", "content")
	if _, err := setup.Process(context.Background(), ref, stale, successfulTestProjector(t, &atomic.Int32{})); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "stale")},
		[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "stale")},
	)
	event := testSnapshotCompletionEvent(t, ref, 2, authoritative)
	var mu sync.Mutex
	requests := []ReconciliationApplyRequest{}
	reconciler := ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
		mu.Lock()
		requests = append(requests, request)
		mu.Unlock()
		return nil
	})
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterReconciliation},
		Publisher: successfulTestPublisher(), ReconciliationProjector: reconciler,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("snapshot crash error = %v", err)
	}
	cursor, err := store.Cursor(ref)
	if err != nil || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 ||
		cursor.Serving == nil || cursor.Serving.Sequence != 1 || cursor.AppendedSequence != 2 {
		t.Fatalf("snapshot advanced before reconciliation receipt: cursor=%+v err=%v", cursor, err)
	}
	if _, err := os.Stat(store.reconciliationReceiptPath(ref, 2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconciliation receipt exists after pre-receipt crash: %v", err)
	}
	conflicting := projected
	conflicting.Resources = append([]ProjectedResource{}, projected.Resources...)
	conflicting.Resources[0].SourceWatermark = "different-projection-base"
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, conflicting); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("conflicting snapshot resume error = %v, want ErrJournalConflict", err)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(), ReconciliationProjector: reconciler,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if err != nil {
		t.Fatalf("exact snapshot resume: %v", err)
	}
	if result.Reconciliation == nil || result.Publication == nil {
		t.Fatalf("resumed snapshot result = %+v", result)
	}
	duplicate, err := restarted.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if err != nil || !duplicate.Idempotent {
		t.Fatalf("snapshot exact replay = %+v err=%v", duplicate, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || !reflect.DeepEqual(requests[0], requests[1]) {
		t.Fatalf("ambiguous snapshot reconciliation requests differ: %+v", requests)
	}
}

func TestSnapshotProjectorPermanentFailureDeadLettersWithoutCheckpointOrPublish(t *testing.T) {
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, clock)
	owned := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "owned", "content")
	if _, err := setup.Process(context.Background(), ref, owned, successfulTestProjector(t, &atomic.Int32{})); err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(owned.ResourceID, "owned")},
		[]ProjectedACL{reconciliationProjectedACL(owned.ResourceID, "owned")},
	)
	event := testSnapshotCompletionEvent(t, ref, 2, authoritative)
	projectorFailure := errors.New("snapshot projector unavailable")
	var reconciliationCalls atomic.Int32
	var publicationCalls atomic.Int32
	processor, err := NewProcessor(store, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 5}, Clock: clock.Now,
		ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return &ApplyError{Code: "snapshot-permanent", Retryable: false, Err: projectorFailure}
		}),
		Publisher: PublisherFunc(func(context.Context, PublicationIntent) error {
			publicationCalls.Add(1)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("snapshot projector error = %v, want ErrDeadLettered", err)
	}
	if !result.DeadLetter || result.Receipt == nil || result.Receipt.Attempts != 1 ||
		result.Receipt.ErrorCode != "snapshot-permanent" || reconciliationCalls.Load() != 1 {
		t.Fatalf("permanent snapshot result = %+v calls=%d", result, reconciliationCalls.Load())
	}
	cursor, err := store.Cursor(ref)
	if err != nil || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 ||
		cursor.Serving == nil || cursor.Serving.Sequence != 1 || cursor.AppendedSequence != 2 ||
		cursor.Blocked == nil || cursor.Blocked.Sequence != 2 || cursor.Blocked.Attempts != 1 {
		t.Fatalf("failed snapshot cursor = %+v err=%v", cursor, err)
	}
	if publicationCalls.Load() != 0 {
		t.Fatalf("failed snapshot reached publisher: %d", publicationCalls.Load())
	}
	if _, err := os.Stat(store.checkpointPath(ref, 2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed snapshot checkpoint exists: %v", err)
	}
}

func TestSnapshotReconciliationRetrySucceedsWithoutChangingRequestBinding(t *testing.T) {
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, clock)
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
	var reconciliationCalls atomic.Int32
	requests := []ReconciliationApplyRequest{}
	processor, err := NewProcessor(store, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 3}, Clock: clock.Now,
		Publisher: successfulTestPublisher(),
		ReconciliationProjector: ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
			requests = append(requests, cloneReconciliationRequest(request))
			if reconciliationCalls.Add(1) == 1 {
				return &ApplyError{Code: "snapshot-temporary", Retryable: true}
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if err != nil {
		t.Fatalf("ProcessSnapshot retry: %v", err)
	}
	if reconciliationCalls.Load() != 2 || len(requests) != 2 || !reconciliationRequestsEqual(requests[0], requests[1]) {
		t.Fatalf("snapshot retry requests differ: calls=%d requests=%+v", reconciliationCalls.Load(), requests)
	}
	if result.Reconciliation == nil || result.Publication == nil || result.DeadLetter {
		t.Fatalf("snapshot retry result = %+v", result)
	}
	if err := store.withLock(func() error {
		state, err := store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		attempts := state.events[0].attempts
		if len(attempts) != 2 || attempts[0].failure == nil ||
			attempts[0].failure.ErrorCode != "snapshot-temporary" || attempts[1].failure != nil {
			t.Fatalf("snapshot retry attempts = %+v", attempts)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotReconciliationRecoveryResumesDurableAttemptAfterFailure(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
	var beforeCalls atomic.Int32
	crashBeforeSecondCallback := FaultInjectorFunc(func(point FaultPoint, _ protocol.ConnectorEventEnvelope) error {
		if point == FaultBeforeReconciliation && beforeCalls.Add(1) == 2 {
			return errInjectedCrash
		}
		return nil
	})
	var failingCalls atomic.Int32
	processor, err := NewProcessor(store, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 3}, Clock: clock.Now, Faults: crashBeforeSecondCallback,
		Publisher: successfulTestPublisher(),
		ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			failingCalls.Add(1)
			return &ApplyError{Code: "snapshot-temporary", Retryable: true}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("ProcessSnapshot crash error = %v", err)
	}
	if failingCalls.Load() != 1 {
		t.Fatalf("snapshot projector calls before restart = %d, want 1", failingCalls.Load())
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	var recoveredCalls atomic.Int32
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 3}, Clock: clock.Now,
		Publisher: successfulTestPublisher(),
		ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			recoveredCalls.Add(1)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	results, err := restarted.Recover(context.Background(), ref, successfulTestProjector(t, &atomic.Int32{}))
	if err != nil {
		t.Fatalf("Recover snapshot retry: %v", err)
	}
	if len(results) != 1 || results[0].Reconciliation == nil || results[0].Publication == nil || recoveredCalls.Load() != 1 {
		t.Fatalf("recovered snapshot result = %+v calls=%d", results, recoveredCalls.Load())
	}
	if err := restartedStore.withLock(func() error {
		state, err := restartedStore.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		attempts := state.events[0].attempts
		if len(attempts) != 2 || attempts[0].failure == nil || attempts[1].failure != nil {
			t.Fatalf("recovered snapshot attempts = %+v", attempts)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotReconciliationCancellationDoesNotConsumeRetry(t *testing.T) {
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, clock)
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
	ctx, cancel := context.WithCancel(context.Background())
	processor, err := NewProcessor(store, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 2}, Clock: clock.Now,
		Publisher: successfulTestPublisher(),
		ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			cancel()
			return &ApplyError{Code: "must-not-persist", Retryable: true}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processor.ProcessSnapshot(ctx, ref, event, authoritative, projected); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot error = %v, want context.Canceled", err)
	}
	processor.reconciler = successfulTestReconciler()
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); err != nil {
		t.Fatalf("resume canceled snapshot: %v", err)
	}
	if err := store.withLock(func() error {
		state, err := store.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		attempts := state.events[0].attempts
		if len(attempts) != 1 || attempts[0].failure != nil {
			t.Fatalf("canceled snapshot attempts = %+v", attempts)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotReconciliationDeadLettersBoundedRetryAndStaysTerminalAfterRestart(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
	var reconciliationCalls atomic.Int32
	var publicationCalls atomic.Int32
	processor, err := NewProcessor(store, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 3},
		Clock:       clock.Now,
		ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return &ApplyError{
				Code: "snapshot-projector-unavailable", Retryable: true,
				Err: errors.New("provider detail must not persist"),
			}
		}),
		Publisher: PublisherFunc(func(context.Context, PublicationIntent) error {
			publicationCalls.Add(1)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
	if !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("ProcessSnapshot error = %v, want ErrDeadLettered", err)
	}
	if !result.DeadLetter || result.Receipt == nil || result.Receipt.Attempts != 3 ||
		result.Receipt.ErrorCode != "snapshot-projector-unavailable" {
		t.Fatalf("snapshot dead-letter result = %+v", result)
	}
	if reconciliationCalls.Load() != 3 || publicationCalls.Load() != 0 {
		t.Fatalf("snapshot callbacks: reconciliation=%d publication=%d", reconciliationCalls.Load(), publicationCalls.Load())
	}
	cursor, err := store.Cursor(ref)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Checkpoint != nil || cursor.Serving != nil || cursor.AppendedSequence != 1 ||
		cursor.Blocked == nil || cursor.Blocked.Sequence != 1 || cursor.Blocked.Attempts != 3 {
		t.Fatalf("snapshot dead-letter cursor = %+v", cursor)
	}
	deadLetters, err := store.DeadLetters(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(deadLetters) != 1 || deadLetters[0].Stage != StageReconciliation || len(deadLetters[0].Failures) != 3 {
		t.Fatalf("snapshot dead letters = %+v", deadLetters)
	}
	bytes, err := os.ReadFile(store.deadLetterPath(ref, 1))
	if err != nil {
		t.Fatal(err)
	}
	if stringContains(string(bytes), "provider detail") {
		t.Fatalf("provider error text leaked into snapshot DLQ: %s", bytes)
	}

	nextAuthoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	nextProjected := reconciliationProjectionSnapshot(ref, 1, []ProjectedResource{}, []ProjectedACL{})
	next := testSnapshotCompletionEvent(t, ref, 2, nextAuthoritative)
	if _, err := processor.ProcessSnapshot(context.Background(), ref, next, nextAuthoritative, nextProjected); !errors.Is(err, ErrPendingEvent) {
		t.Fatalf("snapshot after DLQ error = %v, want ErrPendingEvent", err)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		RetryPolicy: RetryPolicy{MaxAttempts: 3}, Clock: clock.Now,
		Publisher: successfulTestPublisher(),
		ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return errors.New("must not be called after DLQ")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(context.Background(), ref, successfulTestProjector(t, &atomic.Int32{})); !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("restart Recover error = %v, want ErrDeadLettered", err)
	}
	if reconciliationCalls.Load() != 3 {
		t.Fatalf("restart recovery called snapshot projector: %d", reconciliationCalls.Load())
	}
}

func TestSnapshotReconciliationFaultBoundariesResumeExactly(t *testing.T) {
	tests := []struct {
		point              FaultPoint
		callsBeforeRestart int32
		callsAfterRecovery int32
	}{
		{FaultBeforeReconciliation, 0, 1},
		{FaultAfterReconciliation, 1, 2},
		{FaultBeforeReconciliationReceipt, 1, 2},
		{FaultAfterReconciliationReceipt, 1, 1},
	}
	for _, test := range tests {
		t.Run(string(test.point), func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
			authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
			projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
			event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
			var calls atomic.Int32
			var appliedMu sync.Mutex
			appliedKeys := map[protocol.ContentDigest]struct{}{}
			reconciler := ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
				if err := request.Validate(); err != nil {
					return err
				}
				calls.Add(1)
				appliedMu.Lock()
				appliedKeys[request.IdempotencyKey] = struct{}{}
				appliedMu.Unlock()
				return nil
			})
			processor, err := NewProcessor(store, ProcessorOptions{
				Clock: clock.Now, Faults: &oneShotFault{point: test.point},
				Publisher: successfulTestPublisher(), ReconciliationProjector: reconciler,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("ProcessSnapshot fault error = %v", err)
			}
			if calls.Load() != test.callsBeforeRestart {
				t.Fatalf("calls before restart = %d, want %d", calls.Load(), test.callsBeforeRestart)
			}
			restartedStore, err := NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewProcessor(restartedStore, ProcessorOptions{
				Clock: clock.Now, Publisher: successfulTestPublisher(), ReconciliationProjector: reconciler,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := restarted.ProcessSnapshot(context.Background(), ref, event, authoritative, projected)
			if err != nil {
				t.Fatalf("snapshot recovery: %v", err)
			}
			if result.Reconciliation == nil || result.Publication == nil || calls.Load() != test.callsAfterRecovery {
				t.Fatalf("snapshot recovery result=%+v calls=%d want=%d", result, calls.Load(), test.callsAfterRecovery)
			}
			appliedMu.Lock()
			uniqueApplications := len(appliedKeys)
			appliedMu.Unlock()
			if uniqueApplications != 1 {
				t.Fatalf("ambiguous reconciliation callbacks used %d idempotency keys, want one", uniqueApplications)
			}
		})
	}
}

func TestPublicationIntentCrashResumeAndMonotonicCursor(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	var mu sync.Mutex
	intents := []PublicationIntent{}
	publisher := PublisherFunc(func(_ context.Context, intent PublicationIntent) error {
		if _, err := store.Cursor(ref); err != nil {
			return err
		}
		mu.Lock()
		intents = append(intents, intent)
		mu.Unlock()
		return nil
	})
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterPublish}, Publisher: publisher,
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc", "content")
	var applyCalls atomic.Int32
	projector := successfulTestProjector(t, &applyCalls)
	if _, err := processor.Process(context.Background(), ref, event, projector); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("publication crash error = %v", err)
	}
	cursor, err := store.Cursor(ref)
	if err != nil || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 || cursor.Serving != nil {
		t.Fatalf("publication advanced serving before receipt: cursor=%+v err=%v", cursor, err)
	}
	if _, err := os.Stat(store.publicationIntentPath(ref, 1)); err != nil {
		t.Fatalf("publication intent missing: %v", err)
	}
	if _, err := os.Stat(store.publicationReceiptPath(ref, 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication receipt exists after ambiguous crash: %v", err)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: publisher, ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	results, err := restarted.Recover(context.Background(), ref, projector)
	if err != nil {
		t.Fatalf("publication Recover: %v", err)
	}
	if len(results) != 1 || results[0].Publication == nil {
		t.Fatalf("publication recovery result = %+v", results)
	}
	cursor, err = restartedStore.Cursor(ref)
	if err != nil || cursor.Serving == nil || cursor.Serving.Sequence != 1 || cursor.Serving.PublishedAt.IsZero() {
		t.Fatalf("published cursor = %+v err=%v", cursor, err)
	}
	mu.Lock()
	if len(intents) != 2 || !reflect.DeepEqual(intents[0], intents[1]) {
		t.Fatalf("ambiguous publication intents differ: %+v", intents)
	}
	mu.Unlock()
	var staleCalls atomic.Int32
	stalePublisher := PublisherFunc(func(context.Context, PublicationIntent) error {
		staleCalls.Add(1)
		return nil
	})
	if err := restarted.Publish(context.Background(), ref, 1, stalePublisher); !errors.Is(err, ErrStalePublication) {
		t.Fatalf("historical publication error = %v, want ErrStalePublication", err)
	}
	if err := restarted.Publish(context.Background(), ref, 2, stalePublisher); !errors.Is(err, ErrPublicationOrder) {
		t.Fatalf("future publication error = %v, want ErrPublicationOrder", err)
	}
	if staleCalls.Load() != 0 || applyCalls.Load() != 1 {
		t.Fatalf("stale/future publication invoked callback=%d apply=%d", staleCalls.Load(), applyCalls.Load())
	}
}

func TestPublicationFaultBoundariesResumeByExactIntent(t *testing.T) {
	tests := []struct {
		point              FaultPoint
		callsBeforeRestart int32
		callsAfterRecovery int32
	}{
		{FaultBeforePublicationIntent, 0, 1},
		{FaultAfterPublicationIntent, 0, 1},
		{FaultBeforePublish, 0, 1},
		{FaultAfterPublish, 1, 2},
		{FaultBeforePublicationReceipt, 1, 2},
		{FaultAfterPublicationReceipt, 1, 1},
	}
	for _, test := range tests {
		t.Run(string(test.point), func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
			var calls atomic.Int32
			var mu sync.Mutex
			intents := []PublicationIntent{}
			publisher := PublisherFunc(func(_ context.Context, intent PublicationIntent) error {
				calls.Add(1)
				mu.Lock()
				intents = append(intents, intent)
				mu.Unlock()
				return nil
			})
			processor, err := NewProcessor(store, ProcessorOptions{
				Clock: clock.Now, Faults: &oneShotFault{point: test.point}, Publisher: publisher,
				ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc", "content")
			projector := successfulTestProjector(t, &atomic.Int32{})
			if _, err := processor.Process(context.Background(), ref, event, projector); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("Process publication fault error = %v", err)
			}
			if calls.Load() != test.callsBeforeRestart {
				t.Fatalf("calls before restart = %d, want %d", calls.Load(), test.callsBeforeRestart)
			}
			restartedStore, err := NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewProcessor(restartedStore, ProcessorOptions{
				Clock: clock.Now, Publisher: publisher, ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Recover(context.Background(), ref, projector); err != nil {
				t.Fatalf("publication recovery: %v", err)
			}
			if calls.Load() != test.callsAfterRecovery {
				t.Fatalf("calls after recovery = %d, want %d", calls.Load(), test.callsAfterRecovery)
			}
			mu.Lock()
			if len(intents) == 2 && !reflect.DeepEqual(intents[0], intents[1]) {
				t.Errorf("publication retry changed durable intent: first=%+v second=%+v", intents[0], intents[1])
			}
			mu.Unlock()
			cursor, err := restartedStore.Cursor(ref)
			if err != nil || cursor.Serving == nil || cursor.Serving.Sequence != 1 {
				t.Fatalf("publication recovery cursor=%+v err=%v", cursor, err)
			}
		})
	}
}

func TestNilPublisherCannotClaimServingAndRecoveryPublishes(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc", "content")
	projector := successfulTestProjector(t, &atomic.Int32{})
	result, err := processor.Process(context.Background(), ref, event, projector)
	if !errors.Is(err, ErrPublisherRequired) {
		t.Fatalf("nil publisher error = %v, want ErrPublisherRequired", err)
	}
	if result.Checkpoint == nil || result.Eligibility == nil || result.Publication != nil {
		t.Fatalf("nil publisher stages = %+v", result)
	}
	cursor, err := store.Cursor(ref)
	if err != nil || cursor.Serving != nil {
		t.Fatalf("nil publisher claimed serving: cursor=%+v err=%v", cursor, err)
	}
	var calls atomic.Int32
	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now,
		Publisher: PublisherFunc(func(context.Context, PublicationIntent) error {
			calls.Add(1)
			return nil
		}),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(context.Background(), ref, projector); err != nil {
		t.Fatalf("publish recovery: %v", err)
	}
	cursor, err = restartedStore.Cursor(ref)
	if err != nil || cursor.Serving == nil || cursor.Serving.Sequence != 1 || calls.Load() != 1 {
		t.Fatalf("publish recovery cursor=%+v calls=%d err=%v", cursor, calls.Load(), err)
	}
}

func TestResourceOwnershipRejectsCrossConnectorMutationAndPersists(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	registration := Registration{
		Version: ConnectorCoreVersion, Scope: ref.Scope, ConnectorID: "connector-2",
		OwnerID: "owner-2", SourceID: "source-2",
		RegisteredAt: time.Date(2026, time.July, 17, 7, 0, 1, 0, time.UTC),
	}
	if err := store.Register(registration); err != nil {
		t.Fatal(err)
	}
	other := registration.Ref()
	otherProcessor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ownedEvent := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "shared", "content")
	var trusted ApplyRequest
	if _, err := processor.Process(context.Background(), ref, ownedEvent, ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		trusted = request
		return successfulTestApplyResult(t, request), nil
	})); err != nil {
		t.Fatal(err)
	}
	if trusted.SourceOwnership.SourceID != "source-1" || trusted.ResourceOwnership.SourceID != "source-1" ||
		trusted.ResourceOwnership.ConnectorID != ref.ConnectorID {
		t.Fatalf("trusted apply ownership = %+v %+v", trusted.SourceOwnership, trusted.ResourceOwnership)
	}
	var mutationCalls atomic.Int32
	deniedProjector := ProjectorFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
		mutationCalls.Add(1)
		return ApplyResult{}, nil
	})
	for _, kind := range []protocol.ConnectorEventKind{
		protocol.ConnectorContentUpsert, protocol.ConnectorACLReplace, protocol.ConnectorResourceTombstone,
	} {
		event := testConnectorEvent(t, other, 1, kind, "shared", "other")
		if _, err := otherProcessor.Process(context.Background(), other, event, deniedProjector); !errors.Is(err, ErrResourceOwnership) {
			t.Fatalf("cross-connector %s error = %v, want ErrResourceOwnership", kind, err)
		}
	}
	projected := reconciliationProjectionSnapshot(other, 0,
		[]ProjectedResource{reconciliationProjectedResource(ownedEvent.ResourceID, "shared")},
		[]ProjectedACL{reconciliationProjectedACL(ownedEvent.ResourceID, "shared")},
	)
	var reconciliationCalls atomic.Int32
	if _, err := otherProcessor.Reconcile(
		context.Background(), other, reconciliationAuthoritativeSnapshot(other, []AuthoritativeResource{}), projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrResourceOwnership) {
		t.Fatalf("cross-connector reconciliation error = %v, want ErrResourceOwnership", err)
	}
	if mutationCalls.Load() != 0 || reconciliationCalls.Load() != 0 {
		t.Fatalf("cross-connector callbacks: mutation=%d reconciliation=%d", mutationCalls.Load(), reconciliationCalls.Load())
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	acl := testConnectorEvent(t, other, 1, protocol.ConnectorACLReplace, "shared", "other-acl")
	if _, err := restarted.Process(context.Background(), other, acl, deniedProjector); !errors.Is(err, ErrResourceOwnership) {
		t.Fatalf("restart ownership denial = %v", err)
	}
	ownership, err := restartedStore.ResourceOwnership(ref, ownedEvent.ResourceID)
	if err != nil || ownership.SourceID != "source-1" || ownership.ConnectorID != ref.ConnectorID {
		t.Fatalf("persisted ownership = %+v err=%v", ownership, err)
	}
}

func TestSlowConnectorCallbackDoesNotBlockAnotherTenantAndCanReadStore(t *testing.T) {
	if phase3contract.ConnectorLagSampleCount != 1 {
		t.Fatalf("connector lag test supports exactly one sample, contract requires %d", phase3contract.ConnectorLagSampleCount)
	}
	store, processor, tenantA := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	registration := Registration{
		Version: ConnectorCoreVersion,
		Scope: protocol.TenantScope{
			Version: protocol.EnterpriseContractVersion, TenantID: "tenant-b", Region: "cn-east-1",
		},
		ConnectorID: "connector-1", OwnerID: "owner-b", SourceID: "source-b",
		RegisteredAt: time.Date(2026, time.July, 17, 7, 0, 0, 0, time.UTC),
	}
	if err := store.Register(registration); err != nil {
		t.Fatal(err)
	}
	tenantB := registration.Ref()
	entered := make(chan struct{})
	release := make(chan struct{})
	projectorA := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		if _, err := store.Cursor(tenantA); err != nil {
			return ApplyResult{}, err
		}
		close(entered)
		<-release
		return successfulTestApplyResult(t, request), nil
	})
	doneA := make(chan error, 1)
	go func() {
		_, err := processor.Process(
			context.Background(), tenantA,
			testConnectorEvent(t, tenantA, 1, protocol.ConnectorContentUpsert, "a", "a"), projectorA,
		)
		doneA <- err
	}()
	<-entered
	startedB := time.Now()
	doneB := make(chan error, 1)
	go func() {
		_, err := processor.Process(
			context.Background(), tenantB,
			testConnectorEvent(t, tenantB, 1, protocol.ConnectorContentUpsert, "b", "b"),
			successfulTestProjector(t, &atomic.Int32{}),
		)
		doneB <- err
	}()
	select {
	case err := <-doneB:
		if err != nil {
			close(release)
			t.Fatalf("tenant B Process: %v", err)
		}
		if elapsed := time.Since(startedB); elapsed > phase3contract.ConnectorLagMaxBudget {
			close(release)
			t.Fatalf("tenant B connector apply lag = %s, want at most %s", elapsed, phase3contract.ConnectorLagMaxBudget)
		}
	case <-time.After(phase3contract.ConnectorLagMaxBudget):
		close(release)
		t.Fatal("tenant B was blocked by tenant A external callback")
	}
	close(release)
	if err := <-doneA; err != nil {
		t.Fatalf("tenant A Process: %v", err)
	}
}

func TestFailedReconciliationReservationBlocksMutationUntilExactResume(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	projectorFailure := errors.New("reconciliation failed")
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			return projectorFailure
		}),
	); !errors.Is(err, projectorFailure) {
		t.Fatalf("failed reconciliation error = %v", err)
	}
	var processCalls atomic.Int32
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc", "content")
	if _, err := processor.Process(
		context.Background(), ref, event, successfulTestProjector(t, &processCalls),
	); !errors.Is(err, ErrPendingReconciliation) {
		t.Fatalf("Process during durable reconciliation reservation = %v", err)
	}
	journal, err := store.Journal(ref)
	if err != nil || len(journal) != 0 || processCalls.Load() != 0 {
		t.Fatalf("pending reconciliation mutated stream: journal=%+v calls=%d err=%v", journal, processCalls.Load(), err)
	}
	conflicting := authoritative
	conflicting.SourceWatermark = "source-conflict"
	var conflictingCalls atomic.Int32
	if _, err := processor.Reconcile(
		context.Background(), ref, conflicting, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			conflictingCalls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrPendingReconciliation) {
		t.Fatalf("conflicting reconciliation error = %v, want ErrPendingReconciliation", err)
	}
	if conflictingCalls.Load() != 0 {
		t.Fatalf("conflicting reconciliation reached projector: %d", conflictingCalls.Load())
	}
	var resumeCalls atomic.Int32
	if _, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			resumeCalls.Add(1)
			return nil
		}),
	); err != nil {
		t.Fatalf("exact reconciliation resume: %v", err)
	}
	if resumeCalls.Load() != 1 {
		t.Fatalf("exact reconciliation resume calls = %d", resumeCalls.Load())
	}
	if _, err := processor.Process(context.Background(), ref, event, successfulTestProjector(t, &processCalls)); err != nil {
		t.Fatalf("Process after reconciliation receipt: %v", err)
	}
}

func TestCanonicalFingerprintReplayAcceptsZeroOffsetNonUTCLocation(t *testing.T) {
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, clock)
	var applyCalls atomic.Int32
	var publicationCalls atomic.Int32
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now,
		Publisher: PublisherFunc(func(context.Context, PublicationIntent) error {
			publicationCalls.Add(1)
			return nil
		}),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc", "content")
	event.OccurredAt = time.Date(2026, time.July, 17, 6, 1, 0, 0, time.FixedZone("zero-offset", 0))
	if err := event.ValidateFor(ref.Scope); err != nil {
		t.Fatal(err)
	}
	projector := successfulTestProjector(t, &applyCalls)
	if _, err := processor.Process(context.Background(), ref, event, projector); err != nil {
		t.Fatalf("first Process: %v", err)
	}
	result, err := processor.Process(context.Background(), ref, event, projector)
	if err != nil || !result.Idempotent {
		t.Fatalf("canonical exact replay = %+v err=%v", result, err)
	}
	if applyCalls.Load() != 1 || publicationCalls.Load() != 1 {
		t.Fatalf("canonical replay callbacks: apply=%d publication=%d", applyCalls.Load(), publicationCalls.Load())
	}
}

func testSnapshotCompletionEvent(
	t *testing.T,
	ref ConnectorRef,
	sequence uint64,
	authoritative AuthoritativeSnapshot,
) protocol.ConnectorEventEnvelope {
	t.Helper()
	digest, err := authoritativeSnapshotDigest(authoritative)
	if err != nil {
		t.Fatalf("authoritativeSnapshotDigest: %v", err)
	}
	event := testConnectorEvent(t, ref, sequence, protocol.ConnectorSnapshotComplete, "snapshot", "snapshot")
	event.SourceWatermark = authoritative.SourceWatermark
	event.ACLWatermark = authoritative.ACLWatermark
	event.PayloadDigest = digest
	if err := event.ValidateFor(ref.Scope); err != nil {
		t.Fatalf("snapshot event ValidateFor: %v", err)
	}
	return event
}
