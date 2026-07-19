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
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestStoreFailsClosedOnRecordTamper(t *testing.T) {
	store, scope := newTwoRecordAuditStore(t, "tenant-tamper")
	ledgerPath, _ := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	marker := []byte("actor-operator")
	index := bytes.Index(ledger, marker)
	if index < 0 {
		t.Fatal("actor marker not found in ledger")
	}
	ledger[index] ^= 1
	writeAuditTestFile(t, ledgerPath, ledger)
	assertAuditIntegrityFailure(t, store, scope)
}

func TestStoreFailsClosedOnPartialAndCleanBoundaryTruncation(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		truncate func(t *testing.T, store *Store, scope protocol.TenantScope, ledgerPath string)
	}{
		{
			name: "partial-frame",
			truncate: func(t *testing.T, _ *Store, _ protocol.TenantScope, ledgerPath string) {
				info, err := os.Stat(ledgerPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(ledgerPath, info.Size()-1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "whole-tail-record",
			truncate: func(t *testing.T, store *Store, scope protocol.TenantScope, ledgerPath string) {
				ledger := readAuditTestFile(t, ledgerPath)
				spans := auditFrameSpans(t, ledger)
				if len(spans) != 2 {
					t.Fatalf("frame count = %d", len(spans))
				}
				if err := os.Truncate(ledgerPath, int64(spans[1].start)); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store, scope := newTwoRecordAuditStore(t, "tenant-truncate-"+testCase.name)
			ledgerPath, _ := auditTestPaths(store, scope)
			testCase.truncate(t, store, scope, ledgerPath)
			assertAuditIntegrityFailure(t, store, scope)
		})
	}
}

func TestStoreFailsClosedOnReorderedFrames(t *testing.T) {
	store, scope := newTwoRecordAuditStore(t, "tenant-reorder")
	ledgerPath, _ := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	spans := auditFrameSpans(t, ledger)
	if len(spans) != 2 {
		t.Fatalf("frame count = %d", len(spans))
	}
	reordered := make([]byte, 0, len(ledger))
	reordered = append(reordered, ledger[:spans[0].start]...)
	reordered = append(reordered, ledger[spans[1].start:spans[1].end]...)
	reordered = append(reordered, ledger[spans[0].start:spans[0].end]...)
	writeAuditTestFile(t, ledgerPath, reordered)
	assertAuditIntegrityFailure(t, store, scope)
}

func TestStoreFailsClosedOnMissingPredecessorWithValidFrameAndHead(t *testing.T) {
	store, scope := newTwoRecordAuditStore(t, "tenant-missing-predecessor")
	ledgerPath, headPath := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	spans := auditFrameSpans(t, ledger)
	second := decodeAuditTestFrame(t, ledger, spans[1])
	second.PreviousDigest = protocol.NewContentDigest("missing-predecessor")
	second.RecordDigest = computeAuditTestDigest(t, scope, second)
	replacement, err := encodeFrame(2, second)
	if err != nil {
		t.Fatal(err)
	}
	ledger = replaceAuditTestFrame(ledger, spans[1], replacement)
	writeAuditTestFile(t, ledgerPath, ledger)
	rewriteAuditTestHead(t, headPath, uint64(len(ledger)), 2, second.RecordDigest)
	assertAuditIntegrityFailure(t, store, scope)
}

func TestStoreFailsClosedOnCrossTenantPredecessor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	firstScope := auditTestScope("tenant-cross-source")
	secondScope := auditTestScope("tenant-cross-target")
	source, err := store.Append(context.Background(), firstScope, auditTestEntry("source-record", 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(context.Background(), secondScope, auditTestEntry("target-record-01", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(context.Background(), secondScope, auditTestEntry("target-record-02", 2)); err != nil {
		t.Fatal(err)
	}

	ledgerPath, headPath := auditTestPaths(store, secondScope)
	ledger := readAuditTestFile(t, ledgerPath)
	spans := auditFrameSpans(t, ledger)
	second := decodeAuditTestFrame(t, ledger, spans[1])
	second.PreviousDigest = source.RecordDigest
	second.RecordDigest = computeAuditTestDigest(t, secondScope, second)
	replacement, err := encodeFrame(2, second)
	if err != nil {
		t.Fatal(err)
	}
	ledger = replaceAuditTestFrame(ledger, spans[1], replacement)
	writeAuditTestFile(t, ledgerPath, ledger)
	rewriteAuditTestHead(t, headPath, uint64(len(ledger)), 2, second.RecordDigest)
	assertAuditIntegrityFailure(t, store, secondScope)
}

func TestStoreFailsClosedOnPersistedDuplicateID(t *testing.T) {
	store, scope := newTwoRecordAuditStore(t, "tenant-persisted-duplicate")
	ledgerPath, headPath := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	spans := auditFrameSpans(t, ledger)
	first := decodeAuditTestFrame(t, ledger, spans[0])
	second := decodeAuditTestFrame(t, ledger, spans[1])
	second.RecordID = first.RecordID
	second.RecordDigest = computeAuditTestDigest(t, scope, second)
	replacement, err := encodeFrame(2, second)
	if err != nil {
		t.Fatal(err)
	}
	ledger = replaceAuditTestFrame(ledger, spans[1], replacement)
	writeAuditTestFile(t, ledgerPath, ledger)
	rewriteAuditTestHead(t, headPath, uint64(len(ledger)), 2, second.RecordDigest)
	assertAuditIntegrityFailure(t, store, scope)
}

func TestStoreFailsClosedWhenTenantLedgerIsCopiedAcrossPartitions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	firstScope := auditTestScope("tenant-copy-source")
	secondScope := auditTestScope("tenant-copy-target")
	if _, err := store.Append(context.Background(), firstScope, auditTestEntry("source-record", 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(context.Background(), secondScope, auditTestEntry("target-record", 1)); err != nil {
		t.Fatal(err)
	}
	firstLedger, firstHead := auditTestPaths(store, firstScope)
	secondLedger, secondHead := auditTestPaths(store, secondScope)
	writeAuditTestFile(t, secondLedger, readAuditTestFile(t, firstLedger))
	writeAuditTestFile(t, secondHead, readAuditTestFile(t, firstHead))
	assertAuditIntegrityFailure(t, store, secondScope)
}

func TestStoreRejectsInjectedProtectedFieldEvenWithValidFrameChecksum(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	store := openAuditTestStore(t, root, allowAuditResidency)
	scope := auditTestScope("tenant-forbidden-field")
	reference, err := store.Append(context.Background(), scope, auditTestEntry("record-forbidden", 0))
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath, headPath := auditTestPaths(store, scope)
	ledger := readAuditTestFile(t, ledgerPath)
	spans := auditFrameSpans(t, ledger)
	payload := append([]byte(nil), ledger[spans[0].payloadStart:spans[0].payloadEnd]...)
	if payload[len(payload)-1] != '}' {
		t.Fatal("reference payload is not a JSON object")
	}
	payload = append(payload[:len(payload)-1], []byte(`,"credential":"super-secret"}`)...)
	injected := encodeRawAuditTestFrame(1, payload)
	ledger = replaceAuditTestFrame(ledger, spans[0], injected)
	writeAuditTestFile(t, ledgerPath, ledger)
	rewriteAuditTestHead(t, headPath, uint64(len(ledger)), 1, reference.RecordDigest)
	assertAuditIntegrityFailure(t, store, scope)
}

func TestStoreFailsClosedOnDurableHeadTamper(t *testing.T) {
	store, scope := newTwoRecordAuditStore(t, "tenant-head-tamper")
	_, headPath := auditTestPaths(store, scope)
	head := readAuditTestFile(t, headPath)
	head[len(head)-1] ^= 0xff
	writeAuditTestFile(t, headPath, head)
	assertAuditIntegrityFailure(t, store, scope)
}

type auditFrameSpan struct {
	start        int
	end          int
	payloadStart int
	payloadEnd   int
}

func newTwoRecordAuditStore(t *testing.T, tenantID string) (*Store, protocol.TenantScope) {
	t.Helper()
	store := openAuditTestStore(t, filepath.Join(t.TempDir(), "audit"), allowAuditResidency)
	scope := auditTestScope(tenantID)
	if _, err := store.Append(context.Background(), scope, auditTestEntry("record-01", 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(context.Background(), scope, auditTestEntry("record-02", 1)); err != nil {
		t.Fatal(err)
	}
	return store, scope
}

func auditFrameSpans(t *testing.T, ledger []byte) []auditFrameSpan {
	t.Helper()
	if len(ledger) < ledgerEnvelopeOverhead || !bytes.Equal(ledger[:8], ledgerMagic[:]) {
		t.Fatal("invalid test ledger header")
	}
	headerPayloadSize := int(binary.BigEndian.Uint32(ledger[8:12]))
	position := ledgerEnvelopeOverhead + headerPayloadSize
	spans := make([]auditFrameSpan, 0, 2)
	for position < len(ledger) {
		if position+20 > len(ledger) || !bytes.Equal(ledger[position:position+8], frameMagic[:]) {
			t.Fatalf("invalid frame prefix at %d", position)
		}
		payloadSize := int(binary.BigEndian.Uint32(ledger[position+16 : position+20]))
		end := position + frameEnvelopeOverhead + payloadSize
		if end > len(ledger) {
			t.Fatalf("frame at %d exceeds ledger", position)
		}
		spans = append(spans, auditFrameSpan{
			start: position, end: end,
			payloadStart: position + 20, payloadEnd: position + 20 + payloadSize,
		})
		position = end
	}
	if position != len(ledger) {
		t.Fatal("test ledger has trailing partial frame")
	}
	return spans
}

func decodeAuditTestFrame(
	t *testing.T,
	ledger []byte,
	span auditFrameSpan,
) protocol.AuditRecordReference {
	t.Helper()
	var reference protocol.AuditRecordReference
	if err := json.Unmarshal(ledger[span.payloadStart:span.payloadEnd], &reference); err != nil {
		t.Fatal(err)
	}
	return reference
}

func replaceAuditTestFrame(ledger []byte, span auditFrameSpan, replacement []byte) []byte {
	updated := make([]byte, 0, len(ledger)-(span.end-span.start)+len(replacement))
	updated = append(updated, ledger[:span.start]...)
	updated = append(updated, replacement...)
	updated = append(updated, ledger[span.end:]...)
	return updated
}

func encodeRawAuditTestFrame(sequence uint64, payload []byte) []byte {
	var sequenceBytes [8]byte
	var size [4]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	digest := checksum(frameChecksumDomain, frameMagic[:], sequenceBytes[:], size[:], payload)
	frame := make([]byte, 0, frameEnvelopeOverhead+len(payload))
	frame = append(frame, frameMagic[:]...)
	frame = append(frame, sequenceBytes[:]...)
	frame = append(frame, size[:]...)
	frame = append(frame, payload...)
	frame = append(frame, digest[:]...)
	return frame
}

func rewriteAuditTestHead(
	t *testing.T,
	headPath string,
	ledgerSize uint64,
	recordCount uint64,
	lastDigest protocol.ContentDigest,
) {
	t.Helper()
	head, err := decodeHead(readAuditTestFile(t, headPath))
	if err != nil {
		t.Fatal(err)
	}
	head.LedgerSize = ledgerSize
	head.RecordCount = recordCount
	head.LastDigest = lastDigest
	data, err := encodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	writeAuditTestFile(t, headPath, data)
}

func computeAuditTestDigest(
	t *testing.T,
	scope protocol.TenantScope,
	reference protocol.AuditRecordReference,
) protocol.ContentDigest {
	t.Helper()
	digest, err := ComputeRecordDigest(scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func writeAuditTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertAuditIntegrityFailure(t *testing.T, store *Store, scope protocol.TenantScope) {
	t.Helper()
	if err := store.Verify(context.Background(), scope); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Verify error = %v, want ErrIntegrity", err)
	}
	if _, err := OpenStore(store.root, allowAuditResidency); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("reopen error = %v, want ErrIntegrity", err)
	}
	if _, err := store.Append(
		context.Background(), scope, auditTestEntry("record-after-corruption", 99),
	); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("append-after-corruption error = %v, want ErrIntegrity", err)
	}
}

func ExampleComputeRecordDigest() {
	scope := auditTestScope("tenant-example")
	genesis, _ := GenesisDigest(scope)
	reference := protocol.AuditRecordReference{
		Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
		RecordID: "record-01", CorrelationID: "correlation-01",
		ActorID: "operator-01", Action: "governance.audit",
		Outcome: protocol.DecisionAllow, PreviousDigest: genesis,
		RecordedAt: auditTestTime,
	}
	digest, _ := ComputeRecordDigest(scope, reference)
	fmt.Println(len(digest), digest[:7])
	// Output: 71 sha256:
}
