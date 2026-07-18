package connector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestPendingEventWouldResurrectNormalizesSnapshotRemovalIDs(t *testing.T) {
	tombstoned := protocol.ResourceID("a-tombstoned")
	state := durableState{
		reconciliations: []ReconciliationReservationReceipt{{
			DerivedTombstones: []ReconciliationTombstone{{ResourceID: tombstoned}},
		}},
	}
	pending := durableEvent{entry: JournalEntry{
		Event: protocol.ConnectorEventEnvelope{Kind: protocol.ConnectorSnapshotComplete},
		SnapshotReconciliation: &SnapshotReconciliationIntent{
			OwnedResourceIDs: []protocol.ResourceID{tombstoned},
			Plan: ReconciliationPlan{
				StaleResources:      []protocol.ResourceID{"z-stale"},
				TombstonedResources: []protocol.ResourceID{tombstoned},
			},
		},
	}}

	if pendingEventWouldResurrect(state, pending) {
		t.Fatal("snapshot tombstone appended after a sorted stale ID was misclassified as resurrection")
	}
}

func TestProcessorRecoverAllowsNilProjectorForReconciliationOnly(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		root := t.TempDir()
		clock := newTestClock()
		_, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
		authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
		projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
		projectorFailure := errors.New("leave standalone reconciliation pending")
		if _, err := processor.Reconcile(
			context.Background(), ref, authoritative, projected,
			ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
				return projectorFailure
			}),
		); !errors.Is(err, projectorFailure) {
			t.Fatalf("create pending standalone reconciliation: %v", err)
		}

		restartedStore, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		var reconciliationCalls atomic.Int32
		recoveryFailure := errors.New("standalone reconciliation callback reached")
		restarted, err := NewProcessor(restartedStore, ProcessorOptions{
			Clock: clock.Now, Publisher: successfulTestPublisher(),
			ReconciliationProjector: ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
				reconciliationCalls.Add(1)
				return recoveryFailure
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		results, err := restarted.Recover(context.Background(), ref, nil)
		if !errors.Is(err, recoveryFailure) {
			t.Fatalf("Recover standalone reconciliation with nil ordinary projector error = %v", err)
		}
		if len(results) != 0 || reconciliationCalls.Load() != 1 {
			t.Fatalf("standalone recovery results=%+v reconciliation calls=%d", results, reconciliationCalls.Load())
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		root := t.TempDir()
		clock := newTestClock()
		store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
		authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
		projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
		event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
		var reconciliationCalls atomic.Int32
		reconciler := ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			reconciliationCalls.Add(1)
			return nil
		})
		processor, err := NewProcessor(store, ProcessorOptions{
			Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterAppend},
			Publisher: successfulTestPublisher(), ReconciliationProjector: reconciler,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); !errors.Is(err, errInjectedCrash) {
			t.Fatalf("create pending snapshot reconciliation: %v", err)
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
		results, err := restarted.Recover(context.Background(), ref, nil)
		if err != nil {
			t.Fatalf("Recover snapshot reconciliation with nil ordinary projector: %v", err)
		}
		if len(results) != 1 || results[0].Reconciliation == nil || results[0].Publication == nil || reconciliationCalls.Load() != 1 {
			t.Fatalf("snapshot recovery results=%+v reconciliation calls=%d", results, reconciliationCalls.Load())
		}
	})
}

func TestProcessorRecoverRejectsNilProjectorForOrdinaryPendingEvents(t *testing.T) {
	tests := []struct {
		name string
		kind protocol.ConnectorEventKind
	}{
		{name: "content", kind: protocol.ConnectorContentUpsert},
		{name: "acl", kind: protocol.ConnectorACLReplace},
		{name: "tombstone", kind: protocol.ConnectorResourceTombstone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			clock := newTestClock()
			store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
			var applyCalls atomic.Int32
			if _, err := setup.Process(
				context.Background(), ref,
				testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "ordinary", "seed"),
				successfulTestProjector(t, &applyCalls),
			); err != nil {
				t.Fatalf("seed ordinary resource: %v", err)
			}
			processor, err := NewProcessor(store, ProcessorOptions{
				Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterAppend},
				Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			pending := testConnectorEvent(t, ref, 2, test.kind, "ordinary", test.name)
			if _, err := processor.Process(context.Background(), ref, pending, successfulTestProjector(t, &applyCalls)); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("create pending %s event: %v", test.name, err)
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
			if _, err := restarted.Recover(context.Background(), ref, nil); err == nil || !stringContains(err.Error(), "connector projector is required") {
				t.Fatalf("Recover pending %s event with nil projector error = %v", test.name, err)
			}
			cursor, err := restartedStore.Cursor(ref)
			if err != nil {
				t.Fatal(err)
			}
			if cursor.AppendedSequence != 2 || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 {
				t.Fatalf("pending %s cursor advanced after nil-projector rejection: %+v", test.name, cursor)
			}
		})
	}
}
