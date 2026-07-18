package connector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestEventOwnershipRejectsAnOrphanedJournalBinding(t *testing.T) {
	store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	orphan := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "orphaned-owner", "orphan")
	orphanFingerprint, err := protocol.NewConnectorEventFingerprint(orphan)
	if err != nil {
		t.Fatal(err)
	}
	committed := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "committed-owner", "committed")
	committed.EventID = "event-001-committed"
	committed.IdempotencyKey = "idem-001-committed"
	if err := committed.ValidateFor(ref.Scope); err != nil {
		t.Fatal(err)
	}
	committedFingerprint, err := protocol.NewConnectorEventFingerprint(committed)
	if err != nil {
		t.Fatal(err)
	}
	boundAt := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	if err := store.withLock(func() error {
		registration, err := store.loadRegistrationLocked(ref)
		if err != nil {
			return err
		}
		if _, err := store.ensureEventResourceOwnershipLocked(
			ref, registration, orphan, orphanFingerprint, boundAt,
		); err != nil {
			return err
		}
		if _, err := store.ensureEventResourceOwnershipLocked(
			ref, registration, committed, committedFingerprint, boundAt.Add(time.Second),
		); err != nil {
			return err
		}
		entry := JournalEntry{
			Version: ConnectorCoreVersion, Event: committed,
			EventFingerprint: committedFingerprint, AppendedAt: boundAt.Add(time.Second),
		}
		if err := entry.ValidateFor(ref); err != nil {
			return err
		}
		return store.writeJSONOnce(store.journalPath(ref, committed.Sequence), entry)
	}); err != nil {
		t.Fatalf("prepare orphaned ownership: %v", err)
	}

	next := testConnectorEvent(t, ref, 2, protocol.ConnectorContentUpsert, "orphaned-owner", "next")
	nextFingerprint, err := protocol.NewConnectorEventFingerprint(next)
	if err != nil {
		t.Fatal(err)
	}
	err = store.withLock(func() error {
		registration, err := store.loadRegistrationLocked(ref)
		if err != nil {
			return err
		}
		_, err = store.ensureEventResourceOwnershipLocked(
			ref, registration, next, nextFingerprint, boundAt.Add(2*time.Second),
		)
		return err
	})
	if !errors.Is(err, ErrStoreIntegrity) {
		t.Fatalf("reuse orphaned event ownership error = %v, want ErrStoreIntegrity", err)
	}
}

func TestReconciliationOwnershipRejectsUnanchoredStaleClaims(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
		resourceID := testConnectorEvent(
			t, ref, 1, protocol.ConnectorContentUpsert, "stale-standalone-claim", "content",
		).ResourceID
		firstDigest := protocol.NewContentDigest("first reconciliation request")
		secondDigest := protocol.NewContentDigest("second reconciliation request")
		boundAt := time.Date(2026, time.July, 18, 12, 30, 0, 0, time.UTC)
		err := store.withLock(func() error {
			registration, err := store.loadRegistrationLocked(ref)
			if err != nil {
				return err
			}
			if err := store.claimReconciliationResourceOwnershipsLocked(
				ref, registration, []protocol.ResourceID{resourceID}, nil, "", firstDigest, boundAt,
			); err != nil {
				return err
			}
			return store.claimReconciliationResourceOwnershipsLocked(
				ref, registration, []protocol.ResourceID{resourceID}, nil, "", secondDigest, boundAt.Add(time.Second),
			)
		})
		if !errors.Is(err, ErrStoreIntegrity) {
			t.Fatalf("stale standalone claim error = %v, want ErrStoreIntegrity", err)
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
		resourceID := testConnectorEvent(
			t, ref, 1, protocol.ConnectorContentUpsert, "stale-snapshot-claim", "content",
		).ResourceID
		first := testConnectorEvent(t, ref, 1, protocol.ConnectorSnapshotComplete, "snapshot-a", "snapshot-a")
		firstFingerprint, err := protocol.NewConnectorEventFingerprint(first)
		if err != nil {
			t.Fatal(err)
		}
		second := first
		second.EventID = "event-001-retry"
		second.IdempotencyKey = "idem-001-retry"
		second.SourceWatermark = "source-retry"
		second.PayloadDigest = protocol.NewContentDigest("snapshot-b")
		if err := second.ValidateFor(ref.Scope); err != nil {
			t.Fatal(err)
		}
		secondFingerprint, err := protocol.NewConnectorEventFingerprint(second)
		if err != nil {
			t.Fatal(err)
		}
		boundAt := time.Date(2026, time.July, 18, 13, 0, 0, 0, time.UTC)
		err = store.withLock(func() error {
			registration, err := store.loadRegistrationLocked(ref)
			if err != nil {
				return err
			}
			if err := store.claimReconciliationResourceOwnershipsLocked(
				ref, registration, []protocol.ResourceID{resourceID}, &first, firstFingerprint, "", boundAt,
			); err != nil {
				return err
			}
			return store.claimReconciliationResourceOwnershipsLocked(
				ref, registration, []protocol.ResourceID{resourceID}, &second, secondFingerprint, "", boundAt.Add(time.Second),
			)
		})
		if !errors.Is(err, ErrStoreIntegrity) {
			t.Fatalf("stale snapshot claim error = %v, want ErrStoreIntegrity", err)
		}
	})
}

func TestRecoverRejectsNullOptionalStageWithoutReapplying(t *testing.T) {
	root := t.TempDir()
	clock := newTestClock()
	store, _, ref := newTestProcessor(t, root, nil, RetryPolicy{}, clock)
	processor, err := NewProcessor(store, ProcessorOptions{
		Clock: clock.Now, Faults: &oneShotFault{point: FaultAfterAppend},
		Publisher: successfulTestPublisher(), ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "null-stage", "content")
	if _, err := processor.Process(
		context.Background(), ref, event, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("append event: %v", err)
	}
	if err := store.atomicWrite(store.receiptPath(ref, event.Sequence), []byte("null\n")); err != nil {
		t.Fatal(err)
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
	var applyCalls atomic.Int32
	if _, err := restarted.Recover(
		context.Background(), ref, successfulTestProjector(t, &applyCalls),
	); !errors.Is(err, ErrStoreIntegrity) {
		t.Fatalf("Recover null stage error = %v, want ErrStoreIntegrity", err)
	}
	if applyCalls.Load() != 0 {
		t.Fatalf("projector calls after null durable stage = %d, want 0", applyCalls.Load())
	}
}
