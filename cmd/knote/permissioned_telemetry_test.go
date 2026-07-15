package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/telemetry"
)

func TestPermissionedTelemetryFileSinkAppendsCanonicalRecordsConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissioned.jsonl")
	sink := newPermissionedTelemetrySink(path)
	record := permissionedTelemetryTestRecord()

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.Emit(context.Background(), record); err != nil {
				t.Errorf("emit: %v", err)
			}
		}()
	}
	wg.Wait()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
		var decoded map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &decoded); err != nil {
			t.Fatalf("record %d: %v", count, err)
		}
		if decoded["event"] != string(telemetry.EventPermissionedQuery) {
			t.Fatalf("record %d event = %#v", count, decoded["event"])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 16 {
		t.Fatalf("records = %d, want 16", count)
	}
}

func TestPermissionedTelemetryFileSinkDefersFilesystemFailureToEmit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "permissioned.jsonl")
	sink := newPermissionedTelemetrySink(path)
	if err := sink.Emit(context.Background(), permissionedTelemetryTestRecord()); err == nil {
		t.Fatal("unwritable telemetry destination unexpectedly succeeded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("telemetry destination state = %v", err)
	}
}

func TestPermissionedTelemetryFileSinkBoundsBlockingIO(t *testing.T) {
	sink := newPermissionedTelemetrySink(filepath.Join(t.TempDir(), "permissioned.jsonl")).(*permissionedTelemetryFileSink)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	sink.appendRecord = func(string, []byte) error {
		close(started)
		defer close(finished)
		<-release
		return nil
	}

	startedAt := time.Now()
	err := sink.Emit(context.Background(), permissionedTelemetryTestRecord())
	if !errors.Is(err, errPermissionedTelemetryTimeout) {
		t.Fatalf("emit error = %v, want %v", err, errPermissionedTelemetryTimeout)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*permissionedTelemetryEmitTimeout {
		t.Fatalf("blocking emit took %v, want at most %v", elapsed, 2*permissionedTelemetryEmitTimeout)
	}
	select {
	case <-started:
	default:
		t.Fatal("blocking writer did not start")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("blocking writer did not finish after release")
	}
}

func permissionedTelemetryTestRecord() telemetry.Record {
	return telemetry.Record{
		ContractVersion: telemetry.ContractVersion1,
		MetricScope:     telemetry.MetricScopeOperational,
		Event:           telemetry.EventPermissionedQuery,
		Stage:           telemetry.StageTraversal,
		Outcome:         telemetry.OutcomeAllowed,
		Budget: telemetry.Budget{
			Name: telemetry.BudgetLocalHardLatency, Result: telemetry.BudgetPass,
		},
		Counts: telemetry.Counts{Samples: 1, Candidates: 1, Allowed: 1},
	}
}
