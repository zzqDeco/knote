package connector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestRegisterTreatsEquivalentUTCRepresentationsAsIdempotent(t *testing.T) {
	store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	var registration Registration
	if err := store.withLock(func() error {
		var err error
		registration, err = store.loadRegistrationLocked(ref)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	registration.RegisteredAt = time.Date(
		registration.RegisteredAt.Year(), registration.RegisteredAt.Month(), registration.RegisteredAt.Day(),
		registration.RegisteredAt.Hour(), registration.RegisteredAt.Minute(), registration.RegisteredAt.Second(),
		registration.RegisteredAt.Nanosecond(), time.FixedZone("UTC-equivalent", 0),
	)
	if err := store.Register(registration); err != nil {
		t.Fatalf("idempotent registration with equivalent UTC location: %v", err)
	}
}

func TestStandaloneReconciliationReplayUsesDurableApplicationOrder(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	resourceID := reconciliationResourceID(t, ref.Scope.TenantID, "causal-reconciliation-order")
	authoritativeResource := reconciliationAuthoritativeResource(resourceID, "causal-add")
	addAuthoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{authoritativeResource})
	emptyProjected := reconciliationProjectionSnapshot(ref, 0, []ProjectedResource{}, []ProjectedACL{})
	var addRequest ReconciliationApplyRequest
	if _, err := processor.Reconcile(
		context.Background(), ref, addAuthoritative, emptyProjected,
		ReconciliationProjectorFunc(func(_ context.Context, request ReconciliationApplyRequest) error {
			addRequest = cloneReconciliationRequest(request)
			return nil
		}),
	); err != nil {
		t.Fatalf("add reconciliation: %v", err)
	}
	addDigest, err := canonicalContentDigest(addRequest)
	if err != nil {
		t.Fatal(err)
	}

	projectedActive := reconciliationProjectionSnapshot(
		ref, 0,
		[]ProjectedResource{{
			ResourceID: resourceID, SourceWatermark: authoritativeResource.SourceWatermark,
			ContentDigest: authoritativeResource.ContentDigest,
		}},
		[]ProjectedACL{{
			ResourceID: resourceID, ACLWatermark: authoritativeResource.ACLWatermark,
			ACLDigest: authoritativeResource.ACLDigest,
		}},
	)
	var removeAuthoritative AuthoritativeSnapshot
	var removeRequest ReconciliationApplyRequest
	for index := 0; index < 512; index++ {
		candidate := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{})
		candidate.SourceWatermark = fmt.Sprintf("source-remove-%03d", index)
		candidate.ACLWatermark = fmt.Sprintf("acl-remove-%03d", index)
		candidate.CapturedAt = candidate.CapturedAt.Add(time.Duration(index) * time.Second)
		var preparation reconciliationPreparation
		if err := store.withLock(func() error {
			var err error
			preparation, err = processor.prepareReconciliationLocked(ref, candidate, projectedActive, nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		digest, err := canonicalContentDigest(preparation.request)
		if err != nil {
			t.Fatal(err)
		}
		if digest < addDigest {
			removeAuthoritative = candidate
			removeRequest = preparation.request
			break
		}
	}
	if removeRequest.IdempotencyKey == "" {
		t.Fatal("could not construct reverse-hash reconciliation fixture")
	}
	removeDigest, err := canonicalContentDigest(removeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if removeDigest >= addDigest {
		t.Fatalf("fixture hashes are not reverse causal order: add=%s remove=%s", addDigest, removeDigest)
	}
	if _, err := processor.Reconcile(
		context.Background(), ref, removeAuthoritative, projectedActive, successfulTestReconciler(),
	); err != nil {
		t.Fatalf("remove reconciliation: %v", err)
	}

	replay, err := store.Replay(ref)
	if err != nil {
		t.Fatalf("replay in durable application order: %v", err)
	}
	if len(replay.Resources) != 1 || replay.Resources[0].ResourceID != resourceID ||
		replay.Resources[0].State != ReplayResourceTombstoned {
		t.Fatalf("causal replay resources = %+v, want final tombstone", replay.Resources)
	}
	var receipts []ReconciliationReservationReceipt
	if err := store.withLock(func() error {
		registration, err := store.loadRegistrationLocked(ref)
		if err != nil {
			return err
		}
		receipts, err = store.readReconciliationReceiptsLocked(ref, registration)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 || receipts[0].ApplicationOrder != 1 || receipts[1].ApplicationOrder != 2 ||
		receipts[0].RequestDigest != protocol.ContentDigest(addDigest) ||
		receipts[1].RequestDigest != protocol.ContentDigest(removeDigest) {
		t.Fatalf("durable reconciliation order = %+v", receipts)
	}
}
