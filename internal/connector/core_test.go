package connector

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestConnectorTenantAndOwnerIsolation(t *testing.T) {
	store, processor, tenantA := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	tenantBRegistration := Registration{
		Version: ConnectorCoreVersion,
		Scope: protocol.TenantScope{
			Version: protocol.EnterpriseContractVersion, TenantID: "tenant-b", Region: "cn-east-1",
		},
		ConnectorID: "connector-1", OwnerID: "owner-2", SourceID: "source-1",
		RegisteredAt: time.Date(2026, time.July, 17, 7, 0, 0, 0, time.UTC),
	}
	if err := store.Register(tenantBRegistration); err != nil {
		t.Fatalf("register tenant B: %v", err)
	}
	tenantB := tenantBRegistration.Ref()
	if store.connectorDir(tenantA) == store.connectorDir(tenantB) {
		t.Fatal("tenant partitions share a physical connector directory")
	}

	wrongOwner := tenantA
	wrongOwner.OwnerID = "owner-2"
	if _, err := store.Cursor(wrongOwner); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("wrong-owner cursor error = %v, want ErrOwnershipMismatch", err)
	}
	crossTenantEvent := testConnectorEvent(t, tenantB, 1, protocol.ConnectorContentUpsert, "doc-a", "tenant-b-content")
	var calls atomic.Int32
	projector := successfulTestProjector(t, &calls)
	if _, err := processor.Process(context.Background(), tenantA, crossTenantEvent, projector); err == nil {
		t.Fatal("cross-tenant event was accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("cross-tenant event reached projector: calls=%d", calls.Load())
	}
	if _, err := processor.Process(context.Background(), tenantB, crossTenantEvent, projector); err != nil {
		t.Fatalf("tenant B Process: %v", err)
	}
	tenantACursor, err := store.Cursor(tenantA)
	if err != nil {
		t.Fatal(err)
	}
	tenantBCursor, err := store.Cursor(tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if tenantACursor.AppendedSequence != 0 || tenantBCursor.AppendedSequence != 1 {
		t.Fatalf("tenant cursors crossed: tenant A=%+v tenant B=%+v", tenantACursor, tenantBCursor)
	}
}

func TestConnectorReplayAndPersistedJSONAreByteDeterministic(t *testing.T) {
	build := func(t *testing.T, root string) (*Store, ConnectorRef, []byte, map[string][]byte) {
		t.Helper()
		store, processor, ref := newTestProcessor(t, root, nil, RetryPolicy{}, newTestClock())
		var calls atomic.Int32
		projector := successfulTestProjector(t, &calls)
		events := []protocol.ConnectorEventEnvelope{
			testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a"),
			testConnectorEvent(t, ref, 2, protocol.ConnectorACLReplace, "doc-a", "acl-a"),
			testConnectorEvent(t, ref, 3, protocol.ConnectorResourceTombstone, "doc-a", "delete-a"),
		}
		for _, event := range events {
			if _, err := processor.Process(context.Background(), ref, event, projector); err != nil {
				t.Fatalf("Process sequence %d: %v", event.Sequence, err)
			}
		}
		replay, err := store.ReplayJSON(ref)
		if err != nil {
			t.Fatalf("ReplayJSON: %v", err)
		}
		secondReplay, err := store.ReplayJSON(ref)
		if err != nil || !reflect.DeepEqual(replay, secondReplay) {
			t.Fatalf("repeated replay changed: err=%v", err)
		}
		return store, ref, replay, readPersistedJSON(t, root)
	}

	_, _, firstReplay, firstFiles := build(t, filepath.Join(t.TempDir(), "store"))
	_, _, secondReplay, secondFiles := build(t, filepath.Join(t.TempDir(), "store"))
	if !reflect.DeepEqual(firstReplay, secondReplay) {
		t.Fatalf("replay bytes differ:\nfirst=%s\nsecond=%s", firstReplay, secondReplay)
	}
	if !reflect.DeepEqual(firstFiles, secondFiles) {
		firstNames := sortedMapKeys(firstFiles)
		secondNames := sortedMapKeys(secondFiles)
		t.Fatalf("persisted JSON differs: first=%v second=%v", firstNames, secondNames)
	}
}

func TestProcessorConcurrentDuplicateRace(t *testing.T) {
	store, processor, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	var projectorCalls atomic.Int32
	projector := ProjectorFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		projectorCalls.Add(1)
		time.Sleep(5 * time.Millisecond)
		return NewSuccessfulApplyResult(
			request,
			protocol.NewContentDigest("projection:"+string(request.EventFingerprint)),
		)
	})

	const workers = 24
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := processor.Process(context.Background(), ref, event, projector)
			errorsByWorker <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent duplicate Process: %v", err)
		}
	}
	if projectorCalls.Load() != 1 {
		t.Fatalf("projector calls = %d, want 1", projectorCalls.Load())
	}
	cursor, err := store.Cursor(ref)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.AppendedSequence != 1 || cursor.Checkpoint == nil || cursor.Checkpoint.LastSequence != 1 ||
		cursor.Serving == nil || cursor.Serving.Sequence != 1 {
		t.Fatalf("concurrent duplicate cursor = %+v", cursor)
	}
	journal, err := store.Journal(ref)
	if err != nil || len(journal) != 1 {
		t.Fatalf("concurrent duplicate journal length=%d err=%v", len(journal), err)
	}
}

func TestStoreCleansInterruptedAtomicWriteTempFile(t *testing.T) {
	store, _, ref := newTestProcessor(t, t.TempDir(), nil, RetryPolicy{}, newTestClock())
	temporaryPath := filepath.Join(store.journalDir(ref), ".connector-interrupted.tmp")
	if err := os.WriteFile(temporaryPath, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Journal(ref); err != nil {
		t.Fatalf("Journal after interrupted write: %v", err)
	}
	if _, err := os.Stat(temporaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted temp file still exists: %v", err)
	}
}

func readPersistedJSON(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relative] = data
		return nil
	})
	if err != nil {
		t.Fatalf("read persisted JSON: %v", err)
	}
	return files
}

func sortedMapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
