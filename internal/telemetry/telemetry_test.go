package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func testRecord() Record {
	return Record{ContractVersion: ContractVersion1, MetricScope: MetricScopeCohort, Event: EventPermissionedQuery, Stage: StageComplete, Outcome: OutcomeAllowed, Budget: Budget{BudgetLocalHardLatency, BudgetPass}, Counts: Counts{Samples: 1, Candidates: 1, Allowed: 1}, Rates: Rates{RecallAt4: 1, PrecisionAt4: 1}, Durations: Durations{Latency: 3}}
}

func TestRecordValidation(t *testing.T) {
	if err := testRecord().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.Event = "" },
		func(r *Record) { r.MetricScope = "" },
		func(r *Record) { r.Budget.Result = "" },
		func(r *Record) { r.Rates.RecallAt4 = 2 },
		func(r *Record) { r.Counts.Candidates = 2 },
		func(r *Record) { r.Counts.FinalFilterCandidates = 1 },
		func(r *Record) { r.Counts.CompletePaths = 2 },
	} {
		r := testRecord()
		mutate(&r)
		if !errors.Is(r.Validate(), ErrInvalidRecord) {
			t.Fatalf("record accepted invalid value: %+v", r)
		}
	}
}

func TestOperationalRecordRejectsCohortOnlyMeasurements(t *testing.T) {
	record := testRecord()
	record.MetricScope = MetricScopeOperational
	if !errors.Is(record.Validate(), ErrInvalidRecord) {
		t.Fatalf("operational record accepted cohort-only measurements: %+v", record)
	}
	record.Rates.RecallAt4 = 0
	record.Rates.PrecisionAt4 = 0
	record.Counts.UnauthorizedPaths = 1
	if !errors.Is(record.Validate(), ErrInvalidRecord) {
		t.Fatal("operational record accepted unauthorized-path cohort metric")
	}
	record.Counts.UnauthorizedPaths = 0
	if err := record.Validate(); err != nil {
		t.Fatalf("operational record rejected operational fields: %v", err)
	}
}

func TestJSONLDeterministicOutput(t *testing.T) {
	var first, second bytes.Buffer
	if err := NewJSONLSink(&first).Emit(context.Background(), testRecord()); err != nil {
		t.Fatal(err)
	}
	if err := NewJSONLSink(&second).Emit(context.Background(), testRecord()); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || strings.Count(first.String(), "\n") != 1 {
		t.Fatalf("non-deterministic JSONL: %q / %q", first.String(), second.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(first.Bytes()), &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["contract_version"]; !ok {
		t.Fatal("missing contract version")
	}
	if decoded["event"] != string(EventPermissionedQuery) || decoded["metric_scope"] != string(MetricScopeCohort) || decoded["budget"] != string(BudgetLocalHardLatency) {
		t.Fatalf("fixed enums were not encoded as strings: %#v", decoded)
	}
	for _, nested := range []string{"counts", "rates", "durations"} {
		if _, ok := decoded[nested]; ok {
			t.Fatalf("telemetry schema unexpectedly nested %q: %#v", nested, decoded)
		}
	}
}

func TestJSONLConcurrentRecords(t *testing.T) {
	var output bytes.Buffer
	sink := NewJSONLSink(&output)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.Emit(context.Background(), testRecord()); err != nil {
				t.Errorf("emit: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := strings.Count(output.String(), "\n"); got != 32 {
		t.Fatalf("records = %d, want 32", got)
	}
}

func TestJSONLCanceledContextAndNop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := NewJSONLSink(&output).Emit(ctx, testRecord()); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("canceled emit wrote data")
	}
	if err := (NopSink{}).Emit(ctx, testRecord()); err != nil {
		t.Fatal(err)
	}
}
