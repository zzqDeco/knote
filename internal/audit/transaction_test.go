package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestAppendTransactionRecoversOnlyMarkedInterruptedWrites(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		mutate     func(*testing.T, *Store, protocol.TenantScope, auditTransaction, []byte)
		wantCount  int
		wantRecord string
	}{
		{
			name:      "intent-before-ledger-mutation",
			mutate:    func(*testing.T, *Store, protocol.TenantScope, auditTransaction, []byte) {},
			wantCount: 1, wantRecord: "record-01",
		},
		{
			name: "ledger-persisted-head-stale",
			mutate: func(t *testing.T, store *Store, scope protocol.TenantScope, _ auditTransaction, frame []byte) {
				appendAuditTestBytes(t, filepath.Join(store.tenantPath(scope.TenantID), ledgerFileName), frame)
			},
			wantCount: 2, wantRecord: "record-02",
		},
		{
			name: "head-updated-marker-remains",
			mutate: func(t *testing.T, store *Store, scope protocol.TenantScope, transaction auditTransaction, frame []byte) {
				tenantPath := store.tenantPath(scope.TenantID)
				appendAuditTestBytes(t, filepath.Join(tenantPath, ledgerFileName), frame)
				head, err := encodeHead(transaction.Next)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.atomicFile(filepath.Join(tenantPath, headFileName), head, true); err != nil {
					t.Fatal(err)
				}
			},
			wantCount: 2, wantRecord: "record-02",
		},
		{
			name: "partial-frame-rolls-back",
			mutate: func(t *testing.T, store *Store, scope protocol.TenantScope, _ auditTransaction, frame []byte) {
				appendAuditTestBytes(t, filepath.Join(store.tenantPath(scope.TenantID), ledgerFileName), frame[:len(frame)/2])
			},
			wantCount: 1, wantRecord: "record-01",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "audit")
			store := openAuditTestStore(t, root, allowAuditResidency)
			scope := auditTestScope("tenant-transaction-" + testCase.name)
			if _, err := store.Append(context.Background(), scope, auditTestEntry("record-01", 0)); err != nil {
				t.Fatal(err)
			}
			transaction, frame := prepareAuditTestAppend(t, store, scope)
			if err := store.beginTransaction(transaction); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(t, store, scope, transaction, frame)

			reopened := openAuditTestStore(t, root, allowAuditResidency)
			references, err := reopened.ListReferences(context.Background(), scope, allowAuditList)
			if err != nil {
				t.Fatal(err)
			}
			if len(references) != testCase.wantCount || references[len(references)-1].RecordID != testCase.wantRecord {
				t.Fatalf("recovered references = %+v", references)
			}
			if err := reopened.Verify(context.Background(), scope); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(root, transactionFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed transaction marker remains: %v", err)
			}
		})
	}
}

func TestCreateTransactionForwardsLedgerOnlyState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	existingScope := auditTestScope("tenant-existing")
	if _, err := store.Append(context.Background(), existingScope, auditTestEntry("record-existing", 0)); err != nil {
		t.Fatal(err)
	}

	scope := auditTestScope("tenant-create-recovery")
	genesis, err := GenesisDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := newReference(scope, auditTestEntry("record-create", 1), genesis)
	if err != nil {
		t.Fatal(err)
	}
	header, err := encodeLedgerHeader(ledgerHeader{
		FormatVersion: formatVersion, Scope: scope, GenesisDigest: genesis,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encodeFrame(1, reference)
	if err != nil {
		t.Fatal(err)
	}
	ledger := append(header, frame...)
	next := durableHead{
		FormatVersion: formatVersion, Scope: scope, RecordCount: 1,
		LedgerSize: uint64(len(ledger)), LastDigest: reference.RecordDigest,
	}
	if err := store.beginTransaction(auditTransaction{
		FormatVersion: formatVersion, Kind: transactionCreate, Scope: scope, Next: next,
	}); err != nil {
		t.Fatal(err)
	}
	tenantPath := store.tenantPath(scope.TenantID)
	if err := store.ensureDirectory(tenantPath); err != nil {
		t.Fatal(err)
	}
	if err := store.atomicFile(filepath.Join(tenantPath, ledgerFileName), ledger, false); err != nil {
		t.Fatal(err)
	}

	reopened := openAuditTestStore(t, root, allowAuditResidency)
	references, err := reopened.ListReferences(context.Background(), scope, allowAuditList)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 1 || references[0].RecordID != reference.RecordID {
		t.Fatalf("recovered create references = %+v", references)
	}
}

func TestUnmarkedLedgerHeadMismatchStillFailsClosed(t *testing.T) {
	store, scope := newTwoRecordAuditStore(t, "tenant-unmarked-head-mismatch")
	ledgerPath, _ := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	spans := auditFrameSpans(t, ledger)
	if err := os.Truncate(ledgerPath, int64(spans[1].start)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(store.root, allowAuditResidency); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unmarked mismatch reopen error = %v, want ErrIntegrity", err)
	}
}

func TestCreateTransactionRejectsSymlinkedTenantBeforeCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	existingScope := auditTestScope("tenant-existing-create-symlink")
	if _, err := store.Append(context.Background(), existingScope, auditTestEntry("record-existing", 0)); err != nil {
		t.Fatal(err)
	}

	scope := auditTestScope("tenant-create-symlink")
	transaction := prepareAuditTestCreateTransaction(t, scope)
	if err := store.beginTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideTemp := filepath.Join(outside, ".audit-outside.tmp")
	if err := os.WriteFile(outsideTemp, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, store.tenantPath(scope.TenantID)); err != nil {
		t.Skipf("tenant directory symlink unavailable: %v", err)
	}

	if _, err := OpenStore(root, allowAuditResidency); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("symlinked create recovery error = %v, want ErrIntegrity", err)
	}
	if got, err := os.ReadFile(outsideTemp); err != nil || string(got) != "outside" {
		t.Fatalf("create recovery changed outside file: bytes=%q err=%v", got, err)
	}
}

func TestAppendTransactionRejectsSymlinkedTenantBeforeCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	scope := auditTestScope("tenant-append-symlink")
	if _, err := store.Append(context.Background(), scope, auditTestEntry("record-01", 0)); err != nil {
		t.Fatal(err)
	}
	transaction, _ := prepareAuditTestAppend(t, store, scope)
	if err := store.beginTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	tenantPath := store.tenantPath(scope.TenantID)
	if err := os.Rename(tenantPath, tenantPath+".preserved"); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideTemp := filepath.Join(outside, ".audit-outside.tmp")
	if err := os.WriteFile(outsideTemp, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, tenantPath); err != nil {
		t.Skipf("tenant directory symlink unavailable: %v", err)
	}

	if _, err := OpenStore(root, allowAuditResidency); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("symlinked append recovery error = %v, want ErrIntegrity", err)
	}
	if got, err := os.ReadFile(outsideTemp); err != nil || string(got) != "outside" {
		t.Fatalf("append recovery changed outside file: bytes=%q err=%v", got, err)
	}
}

func prepareAuditTestAppend(
	t *testing.T,
	store *Store,
	scope protocol.TenantScope,
) (auditTransaction, []byte) {
	t.Helper()
	ledger, exists, err := store.loadTenantLocked(scope)
	if err != nil || !exists {
		t.Fatalf("load transaction test ledger: exists=%v err=%v", exists, err)
	}
	reference, err := newReference(scope, auditTestEntry("record-02", 1), ledger.lastDigest)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encodeFrame(uint64(len(ledger.references))+1, reference)
	if err != nil {
		t.Fatal(err)
	}
	previous := durableHeadForLedger(ledger)
	return auditTransaction{
		FormatVersion: formatVersion,
		Kind:          transactionAppend,
		Scope:         scope,
		Previous:      &previous,
		Next: durableHead{
			FormatVersion: formatVersion,
			Scope:         scope,
			RecordCount:   previous.RecordCount + 1,
			LedgerSize:    previous.LedgerSize + uint64(len(frame)),
			LastDigest:    reference.RecordDigest,
		},
	}, frame
}

func prepareAuditTestCreateTransaction(
	t *testing.T,
	scope protocol.TenantScope,
) auditTransaction {
	t.Helper()
	genesis, err := GenesisDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := newReference(scope, auditTestEntry("record-create", 1), genesis)
	if err != nil {
		t.Fatal(err)
	}
	header, err := encodeLedgerHeader(ledgerHeader{
		FormatVersion: formatVersion, Scope: scope, GenesisDigest: genesis,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encodeFrame(1, reference)
	if err != nil {
		t.Fatal(err)
	}
	return auditTransaction{
		FormatVersion: formatVersion,
		Kind:          transactionCreate,
		Scope:         scope,
		Next: durableHead{
			FormatVersion: formatVersion,
			Scope:         scope,
			RecordCount:   1,
			LedgerSize:    uint64(len(header) + len(frame)),
			LastDigest:    reference.RecordDigest,
		},
	}
}

func appendAuditTestBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := openAuditAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
