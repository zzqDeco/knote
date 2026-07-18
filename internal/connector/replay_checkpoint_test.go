package connector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestReplaySnapshotReconciliationRequiresCheckpoint(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, setup, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	stale := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "stale", "stale-content")
	if _, err := setup.Process(context.Background(), ref, stale, successfulTestProjector(t, &atomic.Int32{})); err != nil {
		t.Fatalf("bind stale resource: %v", err)
	}

	authoritativeID := reconciliationResourceID(t, ref.Scope.TenantID, "authoritative")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(authoritativeID, "authoritative"),
	})
	projected := reconciliationProjectionSnapshot(ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(stale.ResourceID, "stale")},
		[]ProjectedACL{reconciliationProjectedACL(stale.ResourceID, "stale")},
	)
	event := testSnapshotCompletionEvent(t, ref, 2, authoritative)
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterReconciliationReceipt},
		Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processor.ProcessSnapshot(context.Background(), ref, event, authoritative, projected); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("snapshot crash error = %v", err)
	}

	beforeCheckpoint, err := store.Replay(ref)
	if err != nil {
		t.Fatalf("Replay before checkpoint: %v", err)
	}
	if beforeCheckpoint.Cursor.CheckpointSequence != 1 || len(beforeCheckpoint.Resources) != 1 ||
		beforeCheckpoint.Resources[0].ResourceID != stale.ResourceID ||
		beforeCheckpoint.Resources[0].State != ReplayResourceActive ||
		beforeCheckpoint.Resources[0].ReconciliationTombstone != nil {
		t.Fatalf("Replay exposed uncommitted reconciliation state: %+v", beforeCheckpoint)
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
	results, err := restarted.Recover(context.Background(), ref, successfulTestProjector(t, &atomic.Int32{}))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(results) != 1 || results[0].Checkpoint == nil || results[0].Checkpoint.LastSequence != 2 {
		t.Fatalf("recovery did not checkpoint snapshot: %+v", results)
	}

	afterCheckpoint, err := restartedStore.Replay(ref)
	if err != nil {
		t.Fatalf("Replay after checkpoint: %v", err)
	}
	resources := make(map[protocol.ResourceID]ReplayResource, len(afterCheckpoint.Resources))
	for _, resource := range afterCheckpoint.Resources {
		resources[resource.ResourceID] = resource
	}
	if afterCheckpoint.Cursor.CheckpointSequence != 2 || len(resources) != 2 {
		t.Fatalf("Replay after checkpoint = %+v", afterCheckpoint)
	}
	if resource := resources[authoritativeID]; resource.State != ReplayResourceActive || resource.LastSequence != 2 {
		t.Fatalf("authoritative resource after checkpoint = %+v", resource)
	}
	if resource := resources[stale.ResourceID]; resource.State != ReplayResourceTombstoned ||
		resource.LastSequence != 2 || resource.ReconciliationTombstone == nil {
		t.Fatalf("reconciliation tombstone after checkpoint = %+v", resource)
	}
}
