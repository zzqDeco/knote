package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestRecoverRemovesInterruptedEmptyAttemptDirectoryAndRetries(t *testing.T) {
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
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "interrupted-attempt", "content")
	if _, err := processor.Process(
		context.Background(), ref, event, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("create appended event: %v", err)
	}
	attemptDirectory := store.attemptDir(ref, event.Sequence, 1)
	if err := store.ensureDir(attemptDirectory); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(attemptDirectory, ".connector-interrupted.tmp")
	if err := os.WriteFile(temporary, []byte("partial intent"), 0o600); err != nil {
		t.Fatal(err)
	}

	restartedStore, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	var applyCalls atomic.Int32
	restarted, err := NewProcessor(restartedStore, ProcessorOptions{
		Clock: clock.Now, Publisher: successfulTestPublisher(),
		ReconciliationProjector: successfulTestReconciler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	results, err := restarted.Recover(
		context.Background(), ref, successfulTestProjector(t, &applyCalls),
	)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(results) != 1 || results[0].Publication == nil || applyCalls.Load() != 1 {
		t.Fatalf("recovery results=%+v apply calls=%d", results, applyCalls.Load())
	}
	if _, err := os.Stat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted temporary intent remains: %v", err)
	}
	if _, err := os.Stat(restartedStore.attemptIntentPath(ref, event.Sequence, 1)); err != nil {
		t.Fatalf("replacement attempt intent: %v", err)
	}
}

func TestRecoverRejectsAttemptFailureWithoutIntent(t *testing.T) {
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
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "invalid-attempt", "content")
	if _, err := processor.Process(
		context.Background(), ref, event, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("create appended event: %v", err)
	}
	attemptDirectory := store.attemptDir(ref, event.Sequence, 1)
	if err := store.ensureDir(attemptDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attemptDirectory, "failure.json"), []byte("{}\n"), 0o600); err != nil {
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
	if _, err := restarted.Recover(
		context.Background(), ref, successfulTestProjector(t, &atomic.Int32{}),
	); !errors.Is(err, ErrStoreIntegrity) {
		t.Fatalf("Recover failure without intent error = %v, want ErrStoreIntegrity", err)
	}
	if _, err := os.Stat(filepath.Join(attemptDirectory, "failure.json")); err != nil {
		t.Fatalf("invalid durable failure was silently removed: %v", err)
	}
}
