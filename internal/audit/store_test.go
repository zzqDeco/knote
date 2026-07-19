package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var auditTestTime = time.Date(2026, 7, 19, 5, 0, 0, 123456789, time.UTC)

func TestStoreAppendsCanonicalContentFreeChainAndVerifiesOnReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	var residencyChecks atomic.Int64
	store := openAuditTestStore(t, root, func(context.Context, protocol.TenantScope) error {
		residencyChecks.Add(1)
		return nil
	})
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenStore created bytes before an append: %v", err)
	}

	scope := auditTestScope("tenant-main")
	entries := []Entry{
		auditTestEntry("record-01", 0),
		auditTestEntry("record-02", 1),
		auditTestEntry("record-03", 2),
	}
	references := make([]protocol.AuditRecordReference, 0, len(entries))
	for _, entry := range entries {
		reference, err := store.Append(context.Background(), scope, entry)
		if err != nil {
			t.Fatal(err)
		}
		references = append(references, reference)
	}
	if residencyChecks.Load() != int64(len(entries)) {
		t.Fatalf("residency checks = %d, want %d", residencyChecks.Load(), len(entries))
	}

	genesis, err := GenesisDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	previous := genesis
	for index, reference := range references {
		if reference.Version != protocol.EnterpriseContractVersion || reference.TenantID != scope.TenantID {
			t.Fatalf("reference %d scope = %+v", index, reference)
		}
		if reference.PreviousDigest != previous {
			t.Fatalf("reference %d previous = %q, want %q", index, reference.PreviousDigest, previous)
		}
		computed := independentlyComputeRecordDigest(t, reference)
		if reference.RecordDigest != computed {
			t.Fatalf("reference %d digest = %q, want %q", index, reference.RecordDigest, computed)
		}
		previous = reference.RecordDigest
	}

	authorizationCalls := 0
	authorize := func(_ context.Context, got protocol.TenantScope) error {
		authorizationCalls++
		if got != scope {
			t.Fatalf("authorization scope = %+v, want %+v", got, scope)
		}
		return nil
	}
	listed, err := store.ListReferences(context.Background(), scope, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if authorizationCalls != 1 || !reflect.DeepEqual(listed, references) {
		t.Fatalf("listed references = %+v, calls = %d", listed, authorizationCalls)
	}
	listed[0].RecordID = "caller-mutated"
	again, err := store.ListReferences(context.Background(), scope, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, references) {
		t.Fatal("caller mutation changed persisted references")
	}
	if err := store.Verify(context.Background(), scope); err != nil {
		t.Fatal(err)
	}

	assertAuditLayoutIsFramedAndContentFree(t, store, scope)
	reopened := openAuditTestStore(t, root, allowAuditResidency)
	reopenedReferences, err := reopened.ListReferences(context.Background(), scope, allowAuditList)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopenedReferences, references) {
		t.Fatalf("reopened references = %+v, want %+v", reopenedReferences, references)
	}
	if err := reopened.Verify(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsDuplicateRecordIDWithoutChangingDurableBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	scope := auditTestScope("tenant-duplicate")
	entry := auditTestEntry("record-shared", 0)
	if _, err := store.Append(context.Background(), scope, entry); err != nil {
		t.Fatal(err)
	}
	ledgerPath, headPath := auditTestPaths(store, scope)
	ledgerBefore := readAuditTestFile(t, ledgerPath)
	headBefore := readAuditTestFile(t, headPath)

	duplicate := entry
	duplicate.CorrelationID = "correlation-other"
	duplicate.RecordedAt = duplicate.RecordedAt.Add(time.Minute)
	if _, err := store.Append(context.Background(), scope, duplicate); !errors.Is(err, ErrDuplicateRecordID) {
		t.Fatalf("duplicate append error = %v", err)
	}
	if got := readAuditTestFile(t, ledgerPath); !bytes.Equal(got, ledgerBefore) {
		t.Fatal("duplicate append changed ledger bytes")
	}
	if got := readAuditTestFile(t, headPath); !bytes.Equal(got, headBefore) {
		t.Fatal("duplicate append changed durable head bytes")
	}
	if err := store.Verify(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
}

func TestStorePartitionsTenantsAndAuthorizesListBeforeDisclosure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	firstScope := auditTestScope("tenant-alpha")
	secondScope := auditTestScope("tenant-beta")
	first, err := store.Append(context.Background(), firstScope, auditTestEntry("record-alpha", 0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Append(context.Background(), secondScope, auditTestEntry("record-beta", 1))
	if err != nil {
		t.Fatal(err)
	}
	if first.PreviousDigest == second.PreviousDigest {
		t.Fatal("tenant-specific genesis digests unexpectedly match")
	}
	if store.tenantPath(firstScope.TenantID) == store.tenantPath(secondScope.TenantID) {
		t.Fatal("tenant partitions use the same path")
	}

	denied := errors.New("operator cannot read audit counts")
	list, err := store.ListReferences(context.Background(), firstScope, func(context.Context, protocol.TenantScope) error {
		return denied
	})
	if list != nil || !errors.Is(err, ErrAuthorizationDenied) || !errors.Is(err, denied) {
		t.Fatalf("denied list = %+v, %v", list, err)
	}
	if _, err := store.ListReferences(context.Background(), firstScope, nil); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("nil authorizer error = %v", err)
	}

	firstList, err := store.ListReferences(context.Background(), firstScope, allowAuditList)
	if err != nil || len(firstList) != 1 || firstList[0].RecordID != first.RecordID {
		t.Fatalf("first tenant list = %+v, %v", firstList, err)
	}
	secondList, err := store.ListReferences(context.Background(), secondScope, allowAuditList)
	if err != nil || len(secondList) != 1 || secondList[0].RecordID != second.RecordID {
		t.Fatalf("second tenant list = %+v, %v", secondList, err)
	}
}

func TestListAuthorizationPrecedesCorruptionAndExistenceChecks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	scope := auditTestScope("tenant-side-channel")
	if _, err := store.Append(context.Background(), scope, auditTestEntry("record-side-channel", 0)); err != nil {
		t.Fatal(err)
	}
	ledgerPath, _ := auditTestPaths(store, scope)
	data := readAuditTestFile(t, ledgerPath)
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(ledgerPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	denied := errors.New("denied before disclosure")
	_, err := store.ListReferences(context.Background(), scope, func(context.Context, protocol.TenantScope) error {
		return denied
	})
	if !errors.Is(err, ErrAuthorizationDenied) || !errors.Is(err, denied) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("authorization-first list error = %v", err)
	}
	if _, err := store.ListReferences(context.Background(), scope, allowAuditList); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("authorized corrupt list error = %v", err)
	}

	missingScope := auditTestScope("tenant-not-present")
	_, err = store.ListReferences(context.Background(), missingScope, func(context.Context, protocol.TenantScope) error {
		return denied
	})
	if !errors.Is(err, ErrAuthorizationDenied) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing tenant denial error = %v", err)
	}
}

func TestResidencyDenialAndInvalidInputCreateNoBytes(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "denied-audit")
	denied := errors.New("region policy denies audit storage")
	var checks atomic.Int64
	var syncCalls atomic.Int64
	store, err := openStore(
		root,
		func(context.Context, protocol.TenantScope) error {
			checks.Add(1)
			return denied
		},
		func(string) error {
			syncCalls.Add(1)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Append(context.Background(), auditTestScope("tenant-denied"), auditTestEntry("record-denied", 0))
	if !errors.Is(err, ErrResidencyDenied) || !errors.Is(err, denied) {
		t.Fatalf("residency denial error = %v", err)
	}
	if checks.Load() != 1 || syncCalls.Load() != 0 {
		t.Fatalf("checks=%d directory-syncs=%d", checks.Load(), syncCalls.Load())
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("residency denial left audit bytes: %v", err)
	}

	invalidRoot := filepath.Join(parent, "invalid-audit")
	var invalidChecks atomic.Int64
	invalidStore := openAuditTestStore(t, invalidRoot, func(context.Context, protocol.TenantScope) error {
		invalidChecks.Add(1)
		return nil
	})
	invalid := auditTestEntry("record-invalid", 0)
	invalid.RecordID = "protected content with spaces"
	if _, err := invalidStore.Append(context.Background(), auditTestScope("tenant-invalid"), invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid entry error = %v", err)
	}
	if invalidChecks.Load() != 0 {
		t.Fatal("residency was consulted for structurally invalid input")
	}
	if _, err := os.Stat(invalidRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid input left audit bytes: %v", err)
	}
}

func TestConcurrentStoreInstancesSerializeThreadAppends(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	first := openAuditTestStore(t, root, allowAuditResidency)
	second := openAuditTestStore(t, root, allowAuditResidency)
	scope := auditTestScope("tenant-concurrent")

	const recordCount = 64
	errorsSeen := make(chan error, recordCount)
	var wait sync.WaitGroup
	for index := 0; index < recordCount; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			entry := auditTestEntry(fmt.Sprintf("record-%03d", index), index)
			if _, err := store.Append(context.Background(), scope, entry); err != nil {
				errorsSeen <- err
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	if err := first.Verify(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	references, err := second.ListReferences(context.Background(), scope, allowAuditList)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != recordCount {
		t.Fatalf("concurrent record count = %d, want %d", len(references), recordCount)
	}
	identifiers := make([]string, 0, len(references))
	for index, reference := range references {
		identifiers = append(identifiers, reference.RecordID)
		if index > 0 && reference.PreviousDigest != references[index-1].RecordDigest {
			t.Fatalf("concurrent chain link %d is broken", index)
		}
	}
	sort.Strings(identifiers)
	for index, identifier := range identifiers {
		want := fmt.Sprintf("record-%03d", index)
		if identifier != want {
			t.Fatalf("sorted concurrent id %d = %q, want %q", index, identifier, want)
		}
	}
	reopened := openAuditTestStore(t, root, allowAuditResidency)
	if err := reopened.Verify(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
}

func TestEntrySurfaceRemainsContentFreeByConstruction(t *testing.T) {
	typeOfEntry := reflect.TypeOf(Entry{})
	want := []string{"Action", "ActorID", "CorrelationID", "Outcome", "RecordID", "RecordedAt"}
	got := make([]string, 0, typeOfEntry.NumField())
	for index := 0; index < typeOfEntry.NumField(); index++ {
		got = append(got, typeOfEntry.Field(index).Name)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Entry fields = %v, want only %v", got, want)
	}
	forbidden := []string{
		"prompt", "content", "body", "title", "path", "credential", "secret",
		"token", "password", "assertion", "answer", "graph", "resource",
	}
	for _, field := range got {
		lower := strings.ToLower(field)
		for _, marker := range forbidden {
			if strings.Contains(lower, marker) {
				t.Fatalf("Entry exposes forbidden field %q", field)
			}
		}
	}
}

func openAuditTestStore(t *testing.T, root string, residency ResidencyChecker) *Store {
	t.Helper()
	store, err := OpenStore(root, residency)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func auditTestScope(tenantID string) protocol.TenantScope {
	return protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: tenantID,
		Region:   "cn-north-1",
	}
}

func auditTestEntry(recordID string, sequence int) Entry {
	return Entry{
		RecordID: recordID, CorrelationID: fmt.Sprintf("correlation-%03d", sequence),
		ActorID: "actor-operator", Action: "governance.audit",
		Outcome: protocol.DecisionAllow, RecordedAt: auditTestTime.Add(time.Duration(sequence) * time.Second),
	}
}

func allowAuditResidency(context.Context, protocol.TenantScope) error { return nil }

func allowAuditList(context.Context, protocol.TenantScope) error { return nil }

func auditTestPaths(store *Store, scope protocol.TenantScope) (string, string) {
	tenantPath := store.tenantPath(scope.TenantID)
	return filepath.Join(tenantPath, ledgerFileName), filepath.Join(tenantPath, headFileName)
}

func readAuditTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func independentlyComputeRecordDigest(
	t *testing.T,
	reference protocol.AuditRecordReference,
) protocol.ContentDigest {
	t.Helper()
	fields := struct {
		Version       string                   `json:"version"`
		TenantID      string                   `json:"tenant_id"`
		RecordID      string                   `json:"record_id"`
		CorrelationID string                   `json:"correlation_id"`
		ActorID       string                   `json:"actor_id"`
		Action        string                   `json:"action"`
		Outcome       protocol.DecisionOutcome `json:"outcome"`
		RecordedAt    time.Time                `json:"recorded_at"`
	}{
		Version: reference.Version, TenantID: reference.TenantID,
		RecordID: reference.RecordID, CorrelationID: reference.CorrelationID,
		ActorID: reference.ActorID, Action: reference.Action,
		Outcome: reference.Outcome, RecordedAt: reference.RecordedAt,
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var canonical bytes.Buffer
	canonical.WriteString(recordDigestDomain)
	canonical.WriteByte(0)
	for _, part := range [][]byte{[]byte(reference.PreviousDigest), payload} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		canonical.Write(size[:])
		canonical.Write(part)
	}
	return protocol.NewContentDigest(canonical.String())
}

func assertAuditLayoutIsFramedAndContentFree(t *testing.T, store *Store, scope protocol.TenantScope) {
	t.Helper()
	ledgerPath, _ := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	if !bytes.HasPrefix(ledger, ledgerMagic[:]) {
		t.Fatal("audit ledger does not use the framed format")
	}
	for _, marker := range [][]byte{
		[]byte(`"prompt"`), []byte(`"content"`), []byte(`"credential"`),
		[]byte(`"password"`), []byte(`"token"`), []byte("\n{"),
	} {
		if bytes.Contains(ledger, marker) {
			t.Fatalf("audit ledger contains forbidden or JSONL marker %q", marker)
		}
	}
	err := filepath.Walk(store.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".jsonl") {
			return fmt.Errorf("telemetry JSONL file found: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
