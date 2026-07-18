package connector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestJournalAnchorRepairsOwnershipBeforeAcceptingAnotherEvent(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "journal-first", "content-a")
	fingerprint, err := protocol.NewConnectorEventFingerprint(event)
	if err != nil {
		t.Fatal(err)
	}
	appendedAt := time.Date(2026, time.July, 18, 14, 0, 0, 0, time.UTC)
	entry := JournalEntry{
		Version: ConnectorCoreVersion, Event: event,
		EventFingerprint: fingerprint, AppendedAt: appendedAt,
	}
	if err := entry.ValidateFor(ref); err != nil {
		t.Fatal(err)
	}
	if err := store.withLock(func() error {
		registration, err := store.loadRegistrationLocked(ref)
		if err != nil {
			return err
		}
		_, needsWrite, err := store.prepareEventResourceOwnershipLocked(
			ref, registration, event, fingerprint, appendedAt,
		)
		if err != nil {
			return err
		}
		if !needsWrite {
			t.Fatal("new event ownership did not require a write")
		}
		if _, found, err := store.loadResourceOwnershipOptionalLocked(ref, event.ResourceID); err != nil {
			return err
		} else if found {
			t.Fatal("ownership preflight exposed a claim before the journal anchor")
		}
		return store.writeJSONOnce(store.journalPath(ref, event.Sequence), entry)
	}); err != nil {
		t.Fatalf("prepare journal-only crash state: %v", err)
	}

	conflicting := testConnectorEvent(
		t, ref, 1, protocol.ConnectorContentUpsert, "different-resource", "content-b",
	)
	if _, err := processor.Process(
		context.Background(), ref, conflicting, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("conflicting event error = %v, want ErrJournalConflict", err)
	}
	ownership, err := store.ResourceOwnership(ref, event.ResourceID)
	if err != nil {
		t.Fatalf("journaled event ownership was not repaired: %v", err)
	}
	if !resourceOwnershipMatchesEvent(ownership, event, fingerprint) {
		t.Fatalf("repaired ownership = %+v, want journal event binding", ownership)
	}
}

func TestRecoverRepairsPendingReconciliationOwnership(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	resourceID := reconciliationResourceID(t, ref.Scope.TenantID, "pending-reconciliation")
	authoritative := reconciliationAuthoritativeSnapshot(ref, []AuthoritativeResource{
		reconciliationAuthoritativeResource(resourceID, "pending"),
	})
	projected := reconciliationProjectionSnapshot(ref, 0, nil, nil)
	var reservation ReconciliationReservation
	if err := store.withLock(func() error {
		preparation, err := processor.prepareReconciliationLocked(ref, authoritative, projected, nil)
		if err != nil {
			return err
		}
		requestDigest, err := canonicalContentDigest(preparation.request)
		if err != nil {
			return err
		}
		reservation = ReconciliationReservation{
			Version: ConnectorCoreVersion, Request: preparation.request,
			RequestDigest: requestDigest,
			CreatedAt:     time.Date(2026, time.July, 18, 14, 30, 0, 0, time.UTC),
		}
		if err := reservation.Validate(); err != nil {
			return err
		}
		claim, err := store.prepareReconciliationResourceOwnershipClaimLocked(
			ref, preparation.registration, reservation.Request.OwnedResourceIDs,
			nil, "", reservation.RequestDigest, reservation.CreatedAt,
		)
		if err != nil {
			return err
		}
		if claim == nil {
			t.Fatal("new reconciliation ownership did not require a claim")
		}
		return store.writeJSONOnce(store.reconciliationPendingPath(ref), reservation)
	}); err != nil {
		t.Fatalf("prepare pending reservation without ownership: %v", err)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	var reconciliationCalls atomic.Int32
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(),
		ReconciliationProjector: ReconciliationProjectorFunc(
			func(context.Context, ReconciliationApplyRequest) error {
				reconciliationCalls.Add(1)
				return nil
			},
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(context.Background(), ref, nil); err != nil {
		t.Fatalf("Recover pending reconciliation: %v", err)
	}
	if reconciliationCalls.Load() != 1 {
		t.Fatalf("reconciliation calls = %d, want 1", reconciliationCalls.Load())
	}
	ownership, err := restartedStore.ResourceOwnership(ref, resourceID)
	if err != nil {
		t.Fatalf("pending reconciliation ownership was not repaired: %v", err)
	}
	if ownership.BoundReconciliationDigest != reservation.RequestDigest {
		t.Fatalf("repaired reconciliation ownership = %+v", ownership)
	}
}

func TestRecoverSkipsCallbacksForAlreadyAppliedEvents(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) {
		root := t.TempDir()
		clock := newTestClock()
		store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
		processor, err := NewProcessor(store, ProcessorOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		var applyCalls atomic.Int32
		event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "publish-only", "content")
		if _, err := processor.Process(
			context.Background(), ref, event, successfulTestProjector(t, &applyCalls),
		); !errors.Is(err, ErrPublisherRequired) {
			t.Fatalf("create publish-only ordinary event: %v", err)
		}

		restartedStore, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		restarted, err := NewProcessor(restartedStore, ProcessorOptions{
			Clock: clock.Now, Publisher: successfulTestPublisher(),
		})
		if err != nil {
			t.Fatal(err)
		}
		results, err := restarted.Recover(context.Background(), ref, nil)
		if err != nil {
			t.Fatalf("Recover ordinary publication without projector: %v", err)
		}
		if len(results) != 1 || results[0].Publication == nil || applyCalls.Load() != 1 {
			t.Fatalf("ordinary recovery results=%+v apply calls=%d", results, applyCalls.Load())
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		root := t.TempDir()
		clock := newTestClock()
		store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
		authoritative := reconciliationAuthoritativeSnapshot(ref, nil)
		projected := reconciliationProjectionSnapshot(ref, 0, nil, nil)
		event := testSnapshotCompletionEvent(t, ref, 1, authoritative)
		var reconciliationCalls atomic.Int32
		processor, err := NewProcessor(store, ProcessorOptions{
			Clock: clock.Now,
			ReconciliationProjector: ReconciliationProjectorFunc(
				func(context.Context, ReconciliationApplyRequest) error {
					reconciliationCalls.Add(1)
					return nil
				},
			),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := processor.ProcessSnapshot(
			context.Background(), ref, event, authoritative, projected,
		); !errors.Is(err, ErrPublisherRequired) {
			t.Fatalf("create publish-only snapshot event: %v", err)
		}

		restartedStore, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		restarted, err := NewProcessor(restartedStore, ProcessorOptions{
			Clock: clock.Now, Publisher: successfulTestPublisher(),
		})
		if err != nil {
			t.Fatal(err)
		}
		results, err := restarted.Recover(context.Background(), ref, nil)
		if err != nil {
			t.Fatalf("Recover snapshot publication without reconciler: %v", err)
		}
		if len(results) != 1 || results[0].Publication == nil || reconciliationCalls.Load() != 1 {
			t.Fatalf("snapshot recovery results=%+v reconciliation calls=%d", results, reconciliationCalls.Load())
		}
	})
}
