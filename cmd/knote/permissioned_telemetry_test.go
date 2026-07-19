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

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

func TestPermissionedToolInvocationDeniedHandlerEmitsContentFreeQueryTelemetry(t *testing.T) {
	sink := &recordingPermissionedTelemetrySink{}
	handler := newPermissionedToolInvocationDeniedHandler(sink)
	handler(context.Background(), protocol.ToolAuthorizationManifest{ToolName: einotools.NameBuild})
	handler(context.Background(), protocol.ToolAuthorizationManifest{})
	if len(sink.records) != 0 {
		t.Fatalf("non-query denial records = %d, want 0", len(sink.records))
	}

	handler(context.Background(), protocol.ToolAuthorizationManifest{ToolName: einotools.NameQuery})
	if len(sink.records) != 1 {
		t.Fatalf("query denial records = %d, want 1", len(sink.records))
	}
	record := sink.records[0]
	if err := record.Validate(); err != nil {
		t.Fatalf("denied query telemetry: %v", err)
	}
	if want := permissionedToolInvocationDeniedTelemetryRecord(); record != want {
		t.Fatalf("denied query telemetry = %+v, want %+v", record, want)
	}

	failing := &recordingPermissionedTelemetrySink{err: errors.New("telemetry unavailable")}
	newPermissionedToolInvocationDeniedHandler(failing)(context.Background(), protocol.ToolAuthorizationManifest{ToolName: einotools.NameExplain})
	if len(failing.records) != 1 {
		t.Fatalf("telemetry failure changed denial observation, records=%d", len(failing.records))
	}
}

func TestPermissionedToolInvocationDeniedHandlerSupportsAuditWithoutTelemetry(t *testing.T) {
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := newPermissionedAuditRecorder(t.TempDir(), boundary)
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-audit-only-denial")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}

	handler := newPermissionedToolInvocationDeniedHandlerWithAudit(nil, recorder)
	if handler == nil {
		t.Fatal("audit-only denial handler is nil")
	}
	handler(ctx, protocol.ToolAuthorizationManifest{
		ToolName: einotools.NameQuery,
		Action:   "query",
	})

	scope := protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: authorization.TenantID,
		Region:   boundary.Region(),
	}
	references, err := recorder.store.ListReferences(
		ctx,
		scope,
		func(context.Context, protocol.TenantScope) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 1 || references[0].Outcome != protocol.DecisionDeny {
		t.Fatalf("audit references = %+v, want one denied record", references)
	}
}

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

func TestPermissionedTelemetryResidencyDenialPrecedesFilesystemWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissioned.jsonl")
	denied := errors.New("residency denied")
	sink := newPermissionedTelemetrySinkWithResidency(path, func(context.Context) error { return denied })
	if err := sink.Emit(context.Background(), permissionedTelemetryTestRecord()); !errors.Is(err, denied) {
		t.Fatalf("Emit error = %v, want residency denial", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("telemetry file exists after residency denial: %v", err)
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

type recordingPermissionedTelemetrySink struct {
	err     error
	records []telemetry.Record
}

func (s *recordingPermissionedTelemetrySink) Emit(_ context.Context, record telemetry.Record) error {
	s.records = append(s.records, record)
	return s.err
}
