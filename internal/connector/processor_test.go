package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var errInjectedCrash = errors.New("injected connector crash")

func TestProcessorAppendsBeforeApplyAndAdvancesEveryDurableStage(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	var calls atomic.Int32
	projector := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		calls.Add(1)
		if _, err := os.Stat(store.journalPath(ref, request.Event.Sequence)); err != nil {
			t.Fatalf("journal was not durable before apply: %v", err)
		}
		return successfulTestApplyResult(t, request), nil
	})

	result, err := processor.Process(context.Background(), ref, event, projector)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("projector calls = %d, want 1", calls.Load())
	}
	if result.Receipt == nil || result.Checkpoint == nil || result.Eligibility == nil {
		t.Fatalf("incomplete process result: %+v", result)
	}
	if result.Receipt.State != protocol.ConnectorDeliveryApplied || result.Checkpoint.LastSequence != 1 || result.Eligibility.Sequence != 1 {
		t.Fatalf("unexpected completed stages: %+v", result)
	}
	cursor, err := store.Cursor(ref)
	if err != nil {
		t.Fatalf("Cursor: %v", err)
	}
	if cursor.AppendedSequence != 1 || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 ||
		cursor.Serving == nil || cursor.Serving.Sequence != 1 || cursor.Blocked != nil {
		t.Fatalf("cursor = %+v", cursor)
	}

	duplicate, err := processor.Process(context.Background(), ref, event, projector)
	if err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if !duplicate.Idempotent || calls.Load() != 1 {
		t.Fatalf("exact replay = %+v, projector calls = %d", duplicate, calls.Load())
	}
}

func TestProcessorRejectsReorderConflictsAndIdentifierReuse(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	var calls atomic.Int32
	projector := successfulTestProjector(t, &calls)
	first := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-v1")
	second := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "doc-a", "content-v2")

	if _, err := processor.Process(context.Background(), ref, second, projector); !errors.Is(err, ErrSequenceGap) {
		t.Fatalf("reordered first delivery error = %v, want ErrSequenceGap", err)
	}
	if _, err := processor.Process(context.Background(), ref, first, projector); err != nil {
		t.Fatalf("first Process: %v", err)
	}
	conflict := first
	conflict.PayloadDigest = protocol.NewContentDigest("tampered")
	if _, err := processor.Process(context.Background(), ref, conflict, projector); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("conflicting duplicate error = %v, want ErrJournalConflict", err)
	}
	if _, err := processor.Process(context.Background(), ref, second, projector); err != nil {
		t.Fatalf("second Process: %v", err)
	}
	if _, err := processor.Process(context.Background(), ref, first, projector); !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("historical exact replay error = %v, want ErrStaleEvent", err)
	}

	reusedEventID := testConnectorEvent(t, ref, 3, protocol.ConnectorContentUpsert, "doc-a", "content-v3")
	reusedEventID.EventID = first.EventID
	if _, err := processor.Process(context.Background(), ref, reusedEventID, projector); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("reused event ID error = %v, want ErrJournalConflict", err)
	}
	reusedKey := testConnectorEvent(t, ref, 3, protocol.ConnectorContentUpsert, "doc-a", "content-v3")
	reusedKey.IdempotencyKey = first.IdempotencyKey
	if _, err := processor.Process(context.Background(), ref, reusedKey, projector); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("reused idempotency key error = %v, want ErrJournalConflict", err)
	}
	third := testConnectorEvent(t, ref, 3, protocol.ConnectorContentUpsert, "doc-a", "content-v3")
	if _, err := processor.Process(context.Background(), ref, third, projector); err != nil {
		t.Fatalf("third Process: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("projector calls = %d, want 3", calls.Load())
	}
	journal, err := store.Journal(ref)
	if err != nil {
		t.Fatalf("Journal: %v", err)
	}
	if len(journal) != 3 {
		t.Fatalf("journal length = %d, want 3", len(journal))
	}
}

func TestProcessorCrashRecoveryAtEveryStageBoundary(t *testing.T) {
	tests := []struct {
		point              FaultPoint
		callsBeforeRestart int32
		callsAfterRecovery int32
	}{
		{FaultBeforeAppend, 0, 1},
		{FaultAfterAppend, 0, 1},
		{FaultBeforeApply, 0, 1},
		{FaultAfterApply, 1, 2},
		{FaultBeforeReceipt, 1, 2},
		{FaultAfterReceipt, 1, 1},
		{FaultBeforeCheckpoint, 1, 1},
		{FaultAfterCheckpoint, 1, 1},
		{FaultBeforeServingEligibility, 1, 1},
		{FaultAfterServingEligibility, 1, 1},
	}
	for _, test := range tests {
		t.Run(string(test.point), func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			fault := &oneShotFault{point: test.point}
			store, processor, ref := newTestProcessor(t, root, fault, RetryPolicy{}, clock)
			event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
			var calls atomic.Int32
			projector := successfulTestProjector(t, &calls)

			if _, err := processor.Process(context.Background(), ref, event, projector); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("injected Process error = %v, want crash", err)
			}
			if calls.Load() != test.callsBeforeRestart {
				t.Fatalf("calls before restart = %d, want %d", calls.Load(), test.callsBeforeRestart)
			}

			restartedStore, err := NewStore(root)
			if err != nil {
				t.Fatalf("restart NewStore: %v", err)
			}
			restarted, err := NewProcessor(restartedStore, ProcessorOptions{
				Clock: clock.Now, Publisher: successfulTestPublisher(),
				ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatalf("restart NewProcessor: %v", err)
			}
			result, err := restarted.Process(context.Background(), ref, event, projector)
			if err != nil {
				t.Fatalf("recovery Process: %v", err)
			}
			if result.Eligibility == nil || result.Checkpoint == nil || result.Receipt == nil {
				t.Fatalf("recovery result incomplete: %+v", result)
			}
			if calls.Load() != test.callsAfterRecovery {
				t.Fatalf("calls after recovery = %d, want %d", calls.Load(), test.callsAfterRecovery)
			}
			cursor, err := restartedStore.Cursor(ref)
			if err != nil {
				t.Fatalf("recovered Cursor: %v", err)
			}
			if cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 || cursor.Serving == nil || cursor.Serving.Sequence != 1 {
				t.Fatalf("recovered cursor = %+v", cursor)
			}
			journal, err := restartedStore.Journal(ref)
			if err != nil || len(journal) != 1 {
				t.Fatalf("recovered journal length = %d, err = %v", len(journal), err)
			}
			_ = store
		})
	}
}

func TestProcessorDeadLettersBoundedRetryWithoutAdvancingWatermarks(t *testing.T) {
	root := t.TempDir()
	store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{MaxAttempts: 3}, newTestClock())
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	var calls atomic.Int32
	projector := ProjectorFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
		calls.Add(1)
		return ApplyResult{}, &ApplyError{Code: "acl-failed", Retryable: true, Err: errors.New("provider detail must not persist")}
	})

	result, err := processor.Process(context.Background(), ref, event, projector)
	if !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("Process error = %v, want ErrDeadLettered", err)
	}
	if !result.DeadLetter || result.Receipt == nil || result.Receipt.Attempts != 3 || result.Receipt.ErrorCode != "acl-failed" {
		t.Fatalf("dead-letter result = %+v", result)
	}
	if calls.Load() != 3 {
		t.Fatalf("projector calls = %d, want 3", calls.Load())
	}
	cursor, err := store.Cursor(ref)
	if err != nil {
		t.Fatalf("Cursor: %v", err)
	}
	if cursor.Checkpoint != nil || cursor.Serving != nil || cursor.Blocked == nil || cursor.Blocked.Sequence != 1 {
		t.Fatalf("dead-letter cursor = %+v", cursor)
	}
	deadLetters, err := store.DeadLetters(ref)
	if err != nil {
		t.Fatalf("DeadLetters: %v", err)
	}
	if len(deadLetters) != 1 || len(deadLetters[0].Failures) != 3 {
		t.Fatalf("dead letters = %+v", deadLetters)
	}
	bytes, err := os.ReadFile(store.deadLetterPath(ref, 1))
	if err != nil {
		t.Fatalf("read DLQ: %v", err)
	}
	if stringContains(string(bytes), "provider detail") {
		t.Fatalf("provider error text leaked into DLQ: %s", bytes)
	}

	if _, err := processor.Process(context.Background(), ref, event, projector); !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("dead-letter exact replay error = %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("dead-letter replay called projector: %d", calls.Load())
	}
	next := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "doc-a", "content-b")
	if _, err := processor.Process(context.Background(), ref, next, projector); !errors.Is(err, ErrPendingEvent) {
		t.Fatalf("event after DLQ error = %v, want ErrPendingEvent", err)
	}
	journal, err := store.Journal(ref)
	if err != nil || len(journal) != 1 {
		t.Fatalf("journal advanced after DLQ: length=%d err=%v", len(journal), err)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: newTestClock().Now, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(context.Background(), ref, projector); !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("restart Recover error = %v, want ErrDeadLettered", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("restart recovery called projector: %d", calls.Load())
	}
}

func TestProcessorIncompleteProjectionFailsClosed(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{MaxAttempts: 5}, newTestClock())
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	var calls atomic.Int32
	projector := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		calls.Add(1)
		result := successfulTestApplyResult(t, request)
		result.Status.ACL = ProjectionFailed
		return result, nil
	})
	result, err := processor.Process(context.Background(), ref, event, projector)
	if !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("incomplete projection error = %v, want ErrDeadLettered", err)
	}
	if calls.Load() != 1 || result.Receipt == nil || result.Receipt.ErrorCode != "invalid-apply-result" {
		t.Fatalf("incomplete projection result = %+v, calls = %d", result, calls.Load())
	}
	cursor, err := store.Cursor(ref)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Checkpoint != nil || cursor.Serving != nil {
		t.Fatalf("incomplete projection advanced watermarks: %+v", cursor)
	}
}

func TestProcessorTombstoneReplayIsIdempotentAndCannotResurrect(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	var calls atomic.Int32
	var mu sync.Mutex
	requests := []ApplyRequest{}
	projector := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		calls.Add(1)
		mu.Lock()
		requests = append(requests, request)
		mu.Unlock()
		return successfulTestApplyResult(t, request), nil
	})
	upsert := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	deleted := testConnectorEvent(t, ref, 2, protocol.ConnectorResourceTombstone, "doc-a", "delete-a")
	if _, err := processor.Process(context.Background(), ref, upsert, projector); err != nil {
		t.Fatal(err)
	}
	if _, err := processor.Process(context.Background(), ref, deleted, projector); err != nil {
		t.Fatal(err)
	}
	if _, err := processor.Process(context.Background(), ref, deleted, projector); err != nil {
		t.Fatalf("exact tombstone replay: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("exact tombstone replay called projector: %d", calls.Load())
	}

	resurrection := testConnectorEvent(t, ref, 3, protocol.ConnectorContentUpsert, "doc-a", "resurrect")
	if _, err := processor.Process(context.Background(), ref, resurrection, projector); !errors.Is(err, ErrTombstoneResurrection) {
		t.Fatalf("resurrection error = %v, want ErrTombstoneResurrection", err)
	}
	staleACL := testConnectorEvent(t, ref, 3, protocol.ConnectorACLReplace, "doc-a", "acl-resurrect")
	if _, err := processor.Process(context.Background(), ref, staleACL, projector); !errors.Is(err, ErrTombstoneResurrection) {
		t.Fatalf("ACL resurrection error = %v, want ErrTombstoneResurrection", err)
	}
	repeatedDelete := testConnectorEvent(t, ref, 3, protocol.ConnectorResourceTombstone, "doc-a", "delete-again")
	if _, err := processor.Process(context.Background(), ref, repeatedDelete, projector); err != nil {
		t.Fatalf("later tombstone: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests[1].Tombstone == nil || requests[2].Tombstone == nil ||
		requests[1].Tombstone.ResourceID != deleted.ResourceID || requests[2].Tombstone.ResourceID != deleted.ResourceID {
		t.Fatalf("tombstone requests = %+v", requests)
	}
	report, err := store.Replay(ref)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(report.Resources) != 1 || report.Resources[0].State != ReplayResourceTombstoned ||
		report.Resources[0].LastSequence != 3 || report.Resources[0].Tombstone == nil {
		t.Fatalf("tombstone replay resources = %+v", report.Resources)
	}
	if len(report.Events) != 3 {
		t.Fatalf("replay events = %d, want 3", len(report.Events))
	}
}

func TestProcessorRecoversTombstoneAfterAmbiguousApply(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	upsert := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	if _, err := setup.Process(context.Background(), ref, upsert, successfulTestProjector(t, &atomic.Int32{})); err != nil {
		t.Fatalf("bind resource ownership: %v", err)
	}
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterApply},
		Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := testConnectorEvent(t, ref, 2, protocol.ConnectorResourceTombstone, "doc-a", "delete-a")
	var mu sync.Mutex
	requests := []ApplyRequest{}
	projector := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		mu.Lock()
		requests = append(requests, request)
		mu.Unlock()
		return successfulTestApplyResult(t, request), nil
	})
	if _, err := processor.Process(context.Background(), ref, event, projector); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("first Process error = %v", err)
	}
	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Process(context.Background(), ref, event, projector); err != nil {
		t.Fatalf("recovered tombstone: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0].Attempt != requests[1].Attempt || requests[0].Tombstone == nil ||
		requests[1].Tombstone == nil || *requests[0].Tombstone != *requests[1].Tombstone {
		t.Fatalf("ambiguous tombstone requests differ: %+v", requests)
	}
	_ = store
}

func TestProcessorRecoversBeforeAndAfterDurableDeadLetter(t *testing.T) {
	for _, point := range []FaultPoint{FaultBeforeDeadLetter, FaultAfterDeadLetter} {
		t.Run(string(point), func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			_, processor, ref := newTestProcessor(t, root, &oneShotFault{point: point}, RetryPolicy{MaxAttempts: 3}, clock)
			event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
			var calls atomic.Int32
			projector := ProjectorFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
				calls.Add(1)
				return ApplyResult{}, &ApplyError{Code: "poison-acl", Retryable: false}
			})
			if _, err := processor.Process(context.Background(), ref, event, projector); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("injected Process error = %v", err)
			}
			restartedStore, err := NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewProcessor(restartedStore, ProcessorOptions{
				Clock: clock.Now, Publisher: successfulTestPublisher(),
				ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Recover(context.Background(), ref, projector); !errors.Is(err, ErrDeadLettered) {
				t.Fatalf("Recover error = %v, want ErrDeadLettered", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("recovery reapplied permanent failure: calls=%d", calls.Load())
			}
			cursor, err := restartedStore.Cursor(ref)
			if err != nil || cursor.Blocked == nil || cursor.Checkpoint != nil || cursor.Serving != nil {
				t.Fatalf("recovered DLQ cursor = %+v, err=%v", cursor, err)
			}
		})
	}
}

type oneShotFault struct {
	point FaultPoint
	hit   atomic.Bool
}

func (f *oneShotFault) Inject(point FaultPoint, _ protocol.ConnectorEventEnvelope) error {
	if point == f.point && f.hit.CompareAndSwap(false, true) {
		return errInjectedCrash
	}
	return nil
}

type testClock struct {
	mu   sync.Mutex
	next time.Time
}

func newTestClock() *testClock {
	return &testClock{next: time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := c.next
	c.next = c.next.Add(time.Second)
	return value
}

func newTestProcessor(
	t *testing.T,
	root string,
	faults FaultInjector,
	policy RetryPolicy,
	clock *testClock,
) (*Store, *Processor, ConnectorRef) {
	t.Helper()
	if _, err := os.Lstat(root); err == nil {
		if err := secureConnectorDirectory(root); err != nil {
			t.Fatalf("make connector test root private: %v", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect connector test root: %v", err)
	}
	store, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	scope := protocol.TenantScope{Version: protocol.EnterpriseContractVersion, TenantID: "tenant-a", Region: "cn-east-1"}
	registration := Registration{
		Version: ConnectorCoreVersion, Scope: scope, ConnectorID: "connector-1",
		OwnerID: "owner-1", SourceID: "source-1",
		RegisteredAt: time.Date(2026, time.July, 17, 7, 0, 0, 0, time.UTC),
	}
	if err := store.Register(registration); err != nil {
		t.Fatalf("Register: %v", err)
	}
	processor, err := NewProcessor(store, ProcessorOptions{
		RetryPolicy: policy, Clock: clock.Now, Faults: faults,
		Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	return store, processor, registration.Ref()
}

func testConnectorEvent(
	t *testing.T,
	ref ConnectorRef,
	sequence uint64,
	kind protocol.ConnectorEventKind,
	sourceKey string,
	payload string,
) protocol.ConnectorEventEnvelope {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(ref.Scope.TenantID, "kb-1", protocol.ResourceDocument, sourceKey)
	if err != nil {
		t.Fatalf("NewStableResourceID: %v", err)
	}
	event := protocol.ConnectorEventEnvelope{
		Version: protocol.EnterpriseContractVersion, TenantID: ref.Scope.TenantID,
		ConnectorID: ref.ConnectorID, EventID: fmt.Sprintf("event-%03d", sequence),
		IdempotencyKey: fmt.Sprintf("idem-%03d", sequence), Kind: kind, Sequence: sequence,
		ResourceID: resourceID, SourceWatermark: fmt.Sprintf("source-v%03d", sequence),
		ACLWatermark: fmt.Sprintf("acl-v%03d", sequence), PayloadDigest: protocol.NewContentDigest(payload),
		OccurredAt: time.Date(2026, time.July, 17, 6, 0, 0, 0, time.UTC).Add(time.Duration(sequence) * time.Minute),
	}
	if kind == protocol.ConnectorSnapshotComplete {
		event.ResourceID = ""
	}
	if err := event.ValidateFor(ref.Scope); err != nil {
		t.Fatalf("test event ValidateFor: %v", err)
	}
	return event
}

func successfulTestProjector(t *testing.T, calls *atomic.Int32) Projector {
	t.Helper()
	return ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		calls.Add(1)
		return successfulTestApplyResult(t, request), nil
	})
}

func successfulTestPublisher() Publisher {
	return PublisherFunc(func(context.Context, PublicationIntent) error { return nil })
}

func successfulTestReconciler() ReconciliationProjector {
	return ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error { return nil })
}

func successfulTestApplyResult(t *testing.T, request ApplyRequest) ApplyResult {
	t.Helper()
	result, err := NewSuccessfulApplyResult(
		request,
		protocol.NewContentDigest("projection:"+string(request.EventFingerprint)),
	)
	if err != nil {
		t.Fatalf("NewSuccessfulApplyResult: %v", err)
	}
	return result
}

func stringContains(value, expected string) bool {
	for index := 0; index+len(expected) <= len(value); index++ {
		if value[index:index+len(expected)] == expected {
			return true
		}
	}
	return false
}
