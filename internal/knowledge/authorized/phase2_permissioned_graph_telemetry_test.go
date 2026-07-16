package authorized_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

func TestPhase2TraversalTelemetryIsContentFreeAndNonAuthoritative(t *testing.T) {
	const invariant = "Phase 2 traversal telemetry never changes authorization or exposes protected values"

	t.Run("allowed query survives sink failure", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		sink := &phase2RecordingTelemetrySink{err: errors.New("telemetry unavailable")}
		service := graph.newServiceWithTelemetry(
			t, invariant, graph.newPolicyOracle(t, invariant), nil, phase2TraversalConfig(3), sink,
		)
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question:      "authorized telemetry query",
			Authorization: fixture.Authorization(fixture.Alice, "session-phase2-telemetry-allow"),
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "allowed query inherited sink failure: %v", err)
		}
		if len(result.Evidence.Items) != 2 || len(result.Generation.EvidenceResourceIDs) != 2 {
			acceptanceFatalf(t, invariant, "allowed result changed after sink failure")
		}
		record := sink.only(t)
		if record.Event != telemetry.EventPermissionedQuery || record.Stage != telemetry.StageTraversal ||
			record.Outcome != telemetry.OutcomeAllowed || record.Counts.FinalFilterCandidates != 2 {
			acceptanceFatalf(t, invariant, "unexpected allowed telemetry record: %+v", record)
		}
		assertPhase2TelemetryContentFree(t, invariant, record)
	})

	t.Run("denied query preserves denial with sink failure", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		sink := &phase2RecordingTelemetrySink{err: errors.New("telemetry unavailable")}
		service := graph.newServiceWithTelemetry(
			t, invariant, graph.newPolicyOracle(t, invariant), nil, phase2TraversalConfig(3), sink,
		)
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question:      "denied telemetry query",
			Authorization: fixture.Authorization(phase2UnknownPrincipal, "session-phase2-telemetry-deny"),
		})
		if err == nil || len(result.Evidence.Items) != 0 || len(graph.backend.graphStats().retrieveRequests) != 0 {
			acceptanceFatalf(t, invariant, "denied query changed after sink failure: result=%+v err=%v", result, err)
		}
		record := sink.only(t)
		if record.Outcome != telemetry.OutcomeDenied || record.Counts.Candidates != 6 ||
			record.Counts.Allowed != 0 || record.Counts.Dropped != 6 {
			acceptanceFatalf(t, invariant, "unexpected denied telemetry record: %+v", record)
		}
		assertPhase2TelemetryContentFree(t, invariant, record)
	})
}

type phase2RecordingTelemetrySink struct {
	mu      sync.Mutex
	records []telemetry.Record
	err     error
}

func (s *phase2RecordingTelemetrySink) Emit(_ context.Context, record telemetry.Record) error {
	s.mu.Lock()
	s.records = append(s.records, record)
	s.mu.Unlock()
	return s.err
}

func (s *phase2RecordingTelemetrySink) only(t testing.TB) telemetry.Record {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) != 1 {
		t.Fatalf("telemetry records = %d, want 1", len(s.records))
	}
	return s.records[0]
}

func assertPhase2TelemetryContentFree(
	t testing.TB,
	invariant string,
	record telemetry.Record,
) {
	t.Helper()
	if err := record.Validate(); err != nil {
		acceptanceFatalf(t, invariant, "telemetry validation: %v", err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		acceptanceFatalf(t, invariant, "telemetry encode: %v", err)
	}
	for _, forbidden := range []string{
		fixture.Alice,
		phase2UnknownPrincipal,
		string(phase2StartID),
		string(phase2SharedTerminalID),
		"shared authorized terminal",
		"deep authorized terminal",
		"telemetry unavailable",
	} {
		if strings.Contains(string(encoded), forbidden) {
			acceptanceFatalf(t, invariant, "telemetry exposed a forbidden value")
		}
	}
}
