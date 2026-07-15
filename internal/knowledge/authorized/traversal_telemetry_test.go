package authorized

import (
	"testing"

	"github.com/zzqDeco/knote/internal/telemetry"
)

func TestTraversalTelemetryDistinguishesNotFoundFromAuthorizationDenial(t *testing.T) {
	tests := []struct {
		name   string
		report TraversalReport
		want   telemetry.Outcome
	}{
		{name: "empty discovery", want: telemetry.OutcomeNotFound},
		{
			name: "authorized discovery with empty retrieval",
			report: TraversalReport{HopDrops: []TraversalHopDrop{{
				Phase: TraversalPhaseDiscovery, CandidateCount: 2, AllowedCount: 2,
			}}},
			want: telemetry.OutcomeNotFound,
		},
		{
			name: "discovery denied",
			report: TraversalReport{HopDrops: []TraversalHopDrop{{
				Phase: TraversalPhaseDiscovery, CandidateCount: 2, DroppedCount: 2,
			}}},
			want: telemetry.OutcomeDenied,
		},
		{
			name: "final filter denied",
			report: TraversalReport{
				FinalFilterCandidateCount: 2,
				FinalFilterDroppedCount:   2,
			},
			want: telemetry.OutcomeDenied,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := traversalTelemetryRecord(test.report, QueryResult{}, errNoEvidence)
			if record.Outcome != test.want {
				t.Fatalf("outcome = %q, want %q", record.Outcome, test.want)
			}
		})
	}
}
