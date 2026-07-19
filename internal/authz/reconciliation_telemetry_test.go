package authz

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/telemetry"
	phase3contract "github.com/zzqDeco/knote/tests/phase3/contract"
)

func TestTupleReconcilerTelemetryFailureDoesNotChangePublishedResult(t *testing.T) {
	if phase3contract.ReconciliationSampleCount != 1 {
		t.Fatalf("reconciliation test supports exactly one sample, contract requires %d", phase3contract.ReconciliationSampleCount)
	}
	resourceID := testClaimResourceID(t, "telemetry")
	current := testTupleProjection(t, "projection-telemetry-v1", nil)
	desired := testTupleProjection(t, "projection-telemetry-v2", []testClaimTupleSpec{{
		resourceID: resourceID,
		object:     "claim:telemetry",
		source:     "document:source",
		subject:    "entity:subject",
		target:     "entity:target",
	}})
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)
	plan, err := PlanCatalogTupleReconciliation(current, desired, base, target)
	if err != nil {
		t.Fatal(err)
	}
	revisions, err := NewAtomicRevisionPublisher(base)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewEpochRevocationLifecycle(ResourceInvalidatorFunc(
		func(context.Context, InvalidationRequest) error { return nil },
	))
	if err != nil {
		t.Fatal(err)
	}
	sink := &reconciliationRecordingTelemetrySink{err: errors.New("telemetry unavailable")}
	reconciler, err := NewTupleReconcilerWithOptions(
		TupleWriterFunc(func(_ context.Context, request TupleWriteRequest) error {
			return request.Validate()
		}),
		revisions,
		lifecycle,
		TupleReconcilerOptions{Telemetry: sink},
	)
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	report, err := reconciler.Reconcile(context.Background(), plan)
	if err != nil {
		t.Fatalf("reconciliation inherited telemetry failure: %v", err)
	}
	if elapsed := time.Since(started); elapsed > phase3contract.ReconciliationMaxBudget {
		t.Fatalf("full reconciliation took %s, want at most %s", elapsed, phase3contract.ReconciliationMaxBudget)
	}
	if report.Outcome != ReconciliationSucceeded || !report.RevisionPublished {
		t.Fatalf("reconciliation report changed after telemetry failure: %+v", report)
	}
	currentRevision, err := revisions.Current(context.Background())
	if err != nil || currentRevision != target {
		t.Fatalf("published revision = %+v, %v; want %+v", currentRevision, err, target)
	}
	record := sink.only(t)
	if err := record.Validate(); err != nil {
		t.Fatalf("telemetry record: %v", err)
	}
	if record.Event != telemetry.EventPermissionedReconciliation ||
		record.Stage != telemetry.StageReconciliation || record.Outcome != telemetry.OutcomeOK ||
		record.Counts.ReconciliationAdditions != uint64(report.WriteCount) ||
		record.Counts.ReconciliationRemovals != uint64(report.DeleteCount) {
		t.Fatalf("unexpected reconciliation telemetry: %+v", record)
	}
}

type reconciliationRecordingTelemetrySink struct {
	mu      sync.Mutex
	records []telemetry.Record
	err     error
}

func (s *reconciliationRecordingTelemetrySink) Emit(_ context.Context, record telemetry.Record) error {
	s.mu.Lock()
	s.records = append(s.records, record)
	s.mu.Unlock()
	return s.err
}

func (s *reconciliationRecordingTelemetrySink) only(t testing.TB) telemetry.Record {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) != 1 {
		t.Fatalf("telemetry records = %d, want 1", len(s.records))
	}
	return s.records[0]
}
