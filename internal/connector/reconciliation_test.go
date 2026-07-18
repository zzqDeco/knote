package connector

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestProcessorReconcilePassesExactStaleResourceAndACLPlan(t *testing.T) {
	_, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	var eventCalls atomic.Int32
	for sequence, sourceKey := range []string{"active", "stale"} {
		event := testConnectorEvent(t, ref, uint64(sequence+1), protocol.ConnectorContentUpsert, sourceKey, sourceKey)
		if _, err := processor.Process(context.Background(), ref, event, successfulTestProjector(t, &eventCalls)); err != nil {
			t.Fatalf("bind %s ownership: %v", sourceKey, err)
		}
	}
	activeID := reconciliationResourceID(t, ref.Scope.TenantID, "active")
	staleID := reconciliationResourceID(t, ref.Scope.TenantID, "stale")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(activeID, "active"),
	})
	projected := reconciliationProjectionSnapshot(ref, 2,
		[]ProjectedResource{
			reconciliationProjectedResource(activeID, "active"),
			reconciliationProjectedResource(staleID, "stale"),
		},
		[]ProjectedACL{
			reconciliationProjectedACL(activeID, "active"),
			reconciliationProjectedACL(staleID, "stale"),
		},
	)
	expected, err := processor.PlanReconciliation(ref, authoritative, projected)
	if err != nil {
		t.Fatalf("PlanReconciliation: %v", err)
	}
	var received ReconciliationPlan
	plan, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
			received = request.Plan
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !reflect.DeepEqual(plan, expected) || !reflect.DeepEqual(received, expected) {
		t.Fatalf("projector did not receive exact derived plan:\nexpected=%+v\nreceived=%+v\nreturned=%+v", expected, received, plan)
	}
	if !reflect.DeepEqual(plan.StaleResources, []protocol.ResourceID{staleID}) {
		t.Fatalf("stale resources = %v, want %v", plan.StaleResources, staleID)
	}
	if !reflect.DeepEqual(plan.StaleACLs, []protocol.ResourceID{staleID}) {
		t.Fatalf("stale ACLs = %v, want %v", plan.StaleACLs, staleID)
	}
	if plan.Noop() {
		t.Fatal("stale resource/ACL cleanup plan reported a no-op")
	}
}

func TestProcessorReconcileCrossTenantNeverReachesProjector(t *testing.T) {
	_, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	otherRef := ref
	otherRef.Scope.TenantID = "tenant-b"
	authoritative := reconciliationAuthoritativeSnapshot(otherRef, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(otherRef, 0, []ProjectedResource{}, []ProjectedACL{})
	var calls atomic.Int32
	_, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			calls.Add(1)
			return nil
		}),
	)
	if err == nil {
		t.Fatal("cross-tenant reconciliation was accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("cross-tenant reconciliation reached projector: calls=%d", calls.Load())
	}
}

func TestProcessorReconcileKeepsTombstonesAsRemovals(t *testing.T) {
	_, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	upsertEvent := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "deleted", "content")
	tombstoneEvent := testConnectorEvent(t, ref, 2, protocol.ConnectorResourceTombstone, "deleted", "delete")
	var eventCalls atomic.Int32
	if _, err := processor.Process(context.Background(), ref, upsertEvent, successfulTestProjector(t, &eventCalls)); err != nil {
		t.Fatalf("bind tombstone ownership: %v", err)
	}
	if _, err := processor.Process(context.Background(), ref, tombstoneEvent, successfulTestProjector(t, &eventCalls)); err != nil {
		t.Fatalf("persist tombstone: %v", err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 2,
		[]ProjectedResource{reconciliationProjectedResource(tombstoneEvent.ResourceID, "deleted")},
		[]ProjectedACL{reconciliationProjectedACL(tombstoneEvent.ResourceID, "deleted")},
	)
	var calls atomic.Int32
	plan, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			calls.Add(1)
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("Reconcile tombstone removal: %v", err)
	}
	want := []protocol.ResourceID{tombstoneEvent.ResourceID}
	if !reflect.DeepEqual(plan.TombstonedResources, want) || !reflect.DeepEqual(plan.StaleResources, want) ||
		!reflect.DeepEqual(plan.StaleACLs, want) {
		t.Fatalf("tombstone removal plan = %+v", plan)
	}

	resurrecting := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(tombstoneEvent.ResourceID, "deleted"),
	})
	if _, err := processor.Reconcile(
		context.Background(), ref, resurrecting,
		reconciliationProjectionSnapshot(ref, 2, []ProjectedResource{}, []ProjectedACL{}),
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			calls.Add(1)
			return nil
		}),
	); !errors.Is(err, ErrTombstoneResurrection) {
		t.Fatalf("resurrecting reconciliation error = %v, want ErrTombstoneResurrection", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("resurrecting snapshot reached projector: calls=%d", calls.Load())
	}
}

func TestProcessorReconcilePlanBytesAreDeterministic(t *testing.T) {
	_, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	staleID := reconciliationResourceID(t, ref.Scope.TenantID, "stale")
	var eventCalls atomic.Int32
	if _, err := processor.Process(
		context.Background(), ref,
		testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "stale", "stale"),
		successfulTestProjector(t, &eventCalls),
	); err != nil {
		t.Fatalf("bind stale ownership: %v", err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 1,
		[]ProjectedResource{reconciliationProjectedResource(staleID, "stale")},
		[]ProjectedACL{reconciliationProjectedACL(staleID, "stale")},
	)
	outputs := [][]byte{}
	var calls atomic.Int32
	projector := ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
		calls.Add(1)
		return nil
	})
	for attempt := 0; attempt < 2; attempt++ {
		plan, err := processor.Reconcile(context.Background(), ref, authoritative, projected, projector)
		if err != nil {
			t.Fatalf("Reconcile %d: %v", attempt, err)
		}
		data, err := ReconciliationJSON(plan)
		if err != nil {
			t.Fatalf("ReconciliationJSON %d: %v", attempt, err)
		}
		outputs = append(outputs, data)
	}
	if len(outputs) != 2 || !reflect.DeepEqual(outputs[0], outputs[1]) {
		t.Fatalf("reconciliation plan bytes differ:\nfirst=%s\nsecond=%s", outputs[0], outputs[1])
	}
	if calls.Load() != 1 {
		t.Fatalf("durably completed reconciliation callback calls = %d, want 1", calls.Load())
	}
}

func TestProcessorReconcilePropagatesProjectorFailureWithoutSuccess(t *testing.T) {
	_, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	projectorFailure := errors.New("reconciliation projector unavailable")
	plan, err := processor.Reconcile(
		context.Background(), ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			return projectorFailure
		}),
	)
	if !errors.Is(err, projectorFailure) {
		t.Fatalf("Reconcile error = %v, want projector failure", err)
	}
	if !reflect.DeepEqual(plan, ReconciliationPlan{}) {
		t.Fatalf("failed reconciliation returned a success plan: %+v", plan)
	}
}

func TestProcessorReconcileValidatesContextAndProjector(t *testing.T) {
	_, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	validProjector := ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error { return nil })
	if _, err := processor.Reconcile(nil, ref, authoritative, projected, validProjector); err == nil {
		t.Fatal("nil context was accepted")
	}
	if _, err := processor.Reconcile(context.Background(), ref, authoritative, projected, nil); err == nil {
		t.Fatal("nil projector was accepted")
	}
	var typedNil ReconciliationProjectorFunc
	if _, err := processor.Reconcile(context.Background(), ref, authoritative, projected, typedNil); err == nil {
		t.Fatal("typed-nil projector was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	if _, err := processor.Reconcile(
		ctx, ref, authoritative, projected,
		ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
			calls.Add(1)
			return nil
		}),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconciliation error = %v, want context.Canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("canceled reconciliation reached projector: calls=%d", calls.Load())
	}
}

func TestProcessorReconcileSerializesDerivationAndApplyAgainstProcess(t *testing.T) {
	appendBoundary := make(chan struct{}, 1)
	faults := FaultInjectorFunc(func(point FaultPoint, _ protocol.ConnectorEventEnvelope) error {
		if point == FaultBeforeAppend {
			appendBoundary <- struct{}{}
		}
		return nil
	})
	store, setup, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	var setupCalls atomic.Int32
	if _, err := setup.Process(
		context.Background(), ref,
		testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "deleted", "content"),
		successfulTestProjector(t, &setupCalls),
	); err != nil {
		t.Fatalf("bind concurrent tombstone ownership: %v", err)
	}
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: newTestClock().Now, Faults: faults, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
	projected := reconciliationProjectionSnapshot(ref, 1, []ProjectedResource{}, []ProjectedACL{})

	reconciliationEntered := make(chan struct{})
	releaseReconciliation := make(chan struct{})
	reconciliationDone := make(chan error, 1)
	go func() {
		_, err := processor.Reconcile(
			context.Background(), ref, authoritative, projected,
			ReconciliationProjectorFunc(func(context.Context, ReconciliationApplyRequest) error {
				if _, err := store.Cursor(ref); err != nil {
					return err
				}
				close(reconciliationEntered)
				<-releaseReconciliation
				return nil
			}),
		)
		reconciliationDone <- err
	}()
	<-reconciliationEntered

	tombstone := testConnectorEvent(t, ref, 2, protocol.ConnectorResourceTombstone, "deleted", "delete")
	var eventCalls atomic.Int32
	eventProjector := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		eventCalls.Add(1)
		return NewSuccessfulApplyResult(
			request,
			protocol.NewContentDigest("projection:"+string(request.EventFingerprint)),
		)
	})
	processDone := make(chan error, 1)
	go func() {
		_, err := processor.Process(context.Background(), ref, tombstone, eventProjector)
		processDone <- err
	}()

	interleaved := false
	processCompletedEarly := false
	var processErr error
	select {
	case <-appendBoundary:
		interleaved = true
	case processErr = <-processDone:
		processCompletedEarly = true
	case <-time.After(200 * time.Millisecond):
	}
	_, journalErr := os.Stat(store.journalPath(ref, tombstone.Sequence))
	journaledEarly := journalErr == nil
	unexpectedJournalErr := journalErr != nil && !errors.Is(journalErr, os.ErrNotExist)

	close(releaseReconciliation)
	if err := <-reconciliationDone; err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !interleaved && !processCompletedEarly {
		select {
		case <-appendBoundary:
		case <-time.After(2 * time.Second):
			t.Fatal("Process did not reach append after reconciliation released the lock")
		}
	}
	if !processCompletedEarly {
		processErr = <-processDone
	}
	if interleaved {
		t.Error("Process reached append while reconciliation projector still held the event-stream lock")
	}
	if processCompletedEarly {
		t.Error("Process completed while reconciliation projector was blocked")
	}
	if unexpectedJournalErr {
		t.Errorf("inspect Process journal during reconciliation apply: %v", journalErr)
	}
	if journaledEarly {
		t.Error("Process journaled during reconciliation apply")
	}
	if processErr != nil {
		t.Fatalf("Process after reconciliation: %v", processErr)
	}
	if eventCalls.Load() != 1 {
		t.Fatalf("event projector calls = %d, want 1", eventCalls.Load())
	}
	cursor, err := store.Cursor(ref)
	if err != nil {
		t.Fatalf("Cursor: %v", err)
	}
	if cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 2 ||
		cursor.Serving == nil || cursor.Serving.Sequence != 2 {
		t.Fatalf("cursor after serialized Process = %+v", cursor)
	}
}

func reconciliationResourceID(t *testing.T, tenantID, sourceKey string) protocol.ResourceID {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(tenantID, "kb-1", protocol.ResourceDocument, sourceKey)
	if err != nil {
		t.Fatalf("NewStableResourceID: %v", err)
	}
	return resourceID
}

func reconciliationAuthoritativeResource(resourceID protocol.ResourceID, label string) AuthoritativeResource {
	return AuthoritativeResource{
		ResourceID: resourceID, SourceWatermark: "source-" + label,
		ContentDigest: protocol.NewContentDigest("content-" + label), ACLWatermark: "acl-" + label,
		ACLDigest: protocol.NewContentDigest("acl-body-" + label),
	}
}

func reconciliationProjectedResource(resourceID protocol.ResourceID, label string) ProjectedResource {
	return ProjectedResource{
		ResourceID: resourceID, SourceWatermark: "source-" + label,
		ContentDigest: protocol.NewContentDigest("content-" + label),
	}
}

func reconciliationProjectedACL(resourceID protocol.ResourceID, label string) ProjectedACL {
	return ProjectedACL{
		ResourceID: resourceID, ACLWatermark: "acl-" + label,
		ACLDigest: protocol.NewContentDigest("acl-body-" + label),
	}
}

func reconciliationAuthoritativeSnapshot(ref ConnectorRef, resources []AuthoritativeResource) AuthoritativeSnapshot {
	resources = append([]AuthoritativeResource{}, resources...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	return AuthoritativeSnapshot{
		Version: ConnectorCoreVersion, TenantID: ref.Scope.TenantID, ConnectorID: ref.ConnectorID,
		SourceWatermark: "source-snapshot", ACLWatermark: "acl-snapshot",
		CapturedAt: time.Date(2026, time.July, 17, 9, 0, 0, 0, time.UTC), Resources: resources,
	}
}

func reconciliationProjectionSnapshot(
	ref ConnectorRef,
	baseSequence uint64,
	resources []ProjectedResource,
	acls []ProjectedACL,
) ProjectionSnapshot {
	resources = append([]ProjectedResource{}, resources...)
	acls = append([]ProjectedACL{}, acls...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	sort.Slice(acls, func(i, j int) bool { return acls[i].ResourceID < acls[j].ResourceID })
	return ProjectionSnapshot{
		Version: ConnectorCoreVersion, TenantID: ref.Scope.TenantID,
		ConnectorID: ref.ConnectorID, ProjectionBaseSequence: baseSequence,
		Resources: resources, ACLs: acls,
	}
}
