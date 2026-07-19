package policysim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var testGeneratedAt = time.Date(2026, time.July, 19, 2, 0, 0, 0, time.UTC)

func TestEngineClassifiesIndependentEvaluationsWithStableReasons(t *testing.T) {
	type response struct {
		outcome    protocol.DecisionOutcome
		err        error
		panicValue any
	}
	tests := []struct {
		correlationID string
		base          response
		proposed      response
		kind          protocol.PolicyImpactKind
		before        protocol.DecisionOutcome
		after         protocol.DecisionOutcome
		reason        string
	}{
		{correlationID: "impact-01", base: response{outcome: protocol.DecisionDeny}, proposed: response{outcome: protocol.DecisionAllow}, kind: protocol.PolicyImpactGrant, before: protocol.DecisionDeny, after: protocol.DecisionAllow, reason: ReasonGrant},
		{correlationID: "impact-02", base: response{outcome: protocol.DecisionAllow}, proposed: response{outcome: protocol.DecisionDeny}, kind: protocol.PolicyImpactRevoke, before: protocol.DecisionAllow, after: protocol.DecisionDeny, reason: ReasonRevoke},
		{correlationID: "impact-03", base: response{outcome: protocol.DecisionAllow}, proposed: response{outcome: protocol.DecisionAllow}, kind: protocol.PolicyImpactUnchanged, before: protocol.DecisionAllow, after: protocol.DecisionAllow, reason: ReasonUnchangedAllow},
		{correlationID: "impact-04", base: response{outcome: protocol.DecisionDeny}, proposed: response{outcome: protocol.DecisionDeny}, kind: protocol.PolicyImpactUnchanged, before: protocol.DecisionDeny, after: protocol.DecisionDeny, reason: ReasonUnchangedDeny},
		{correlationID: "impact-05", base: response{outcome: protocol.DecisionIndeterminate}, proposed: response{outcome: protocol.DecisionAllow}, kind: protocol.PolicyImpactUnknown, before: protocol.DecisionIndeterminate, after: protocol.DecisionAllow, reason: ReasonBaseUnknown},
		{correlationID: "impact-06", base: response{outcome: protocol.DecisionDeny}, proposed: response{outcome: protocol.DecisionIndeterminate}, kind: protocol.PolicyImpactUnknown, before: protocol.DecisionDeny, after: protocol.DecisionIndeterminate, reason: ReasonProposedUnknown},
		{correlationID: "impact-07", base: response{outcome: protocol.DecisionIndeterminate}, proposed: response{outcome: protocol.DecisionIndeterminate}, kind: protocol.PolicyImpactUnknown, before: protocol.DecisionIndeterminate, after: protocol.DecisionIndeterminate, reason: ReasonBothUnknown},
		{correlationID: "impact-08", base: response{err: errors.New("base provider secret")}, proposed: response{outcome: protocol.DecisionAllow}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionIndeterminate, after: protocol.DecisionAllow, reason: ReasonBaseFailure},
		{correlationID: "impact-09", base: response{outcome: protocol.DecisionDeny}, proposed: response{err: errors.New("proposed provider secret")}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionDeny, after: protocol.DecisionIndeterminate, reason: ReasonProposedFailure},
		{correlationID: "impact-10", base: response{err: errors.New("base failed")}, proposed: response{err: errors.New("proposed failed")}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionIndeterminate, after: protocol.DecisionIndeterminate, reason: ReasonBothFailure},
		{correlationID: "impact-11", base: response{err: errors.New("base failed")}, proposed: response{outcome: protocol.DecisionIndeterminate}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionIndeterminate, after: protocol.DecisionIndeterminate, reason: ReasonBaseFailureProposedUnknown},
		{correlationID: "impact-12", base: response{outcome: protocol.DecisionIndeterminate}, proposed: response{err: errors.New("proposed failed")}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionIndeterminate, after: protocol.DecisionIndeterminate, reason: ReasonBaseUnknownProposedFailure},
		{correlationID: "impact-13", base: response{outcome: "not-a-decision"}, proposed: response{outcome: protocol.DecisionAllow}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionIndeterminate, after: protocol.DecisionAllow, reason: ReasonBaseFailure},
		{correlationID: "impact-14", base: response{outcome: protocol.DecisionDeny}, proposed: response{panicValue: "provider panic secret"}, kind: protocol.PolicyImpactFailure, before: protocol.DecisionDeny, after: protocol.DecisionIndeterminate, reason: ReasonProposedFailure},
	}

	baseResponses := make(map[string]response, len(tests))
	proposedResponses := make(map[string]response, len(tests))
	candidates := make([]Candidate, 0, len(tests))
	for index := len(tests) - 1; index >= 0; index-- {
		test := tests[index]
		baseResponses[test.correlationID] = test.base
		proposedResponses[test.correlationID] = test.proposed
		candidates = append(candidates, nonTupleCandidate(
			test.correlationID,
			fmt.Sprintf("membership-%02d", index+1),
			protocol.PolicyTargetIdentityMembership,
		))
	}

	basePins := testBasePins()
	proposedPins := testProposedPins()
	var baseCalls atomic.Int64
	var proposedCalls atomic.Int64
	baseEvaluator := SnapshotEvaluatorFunc(func(_ context.Context, snapshot Snapshot, candidate Candidate) (protocol.DecisionOutcome, error) {
		baseCalls.Add(1)
		if got := snapshot.Pins(); got != basePins {
			t.Errorf("base evaluator snapshot = %+v, want %+v", got, basePins)
		}
		return returnResponse(baseResponses[candidate.CorrelationID])
	})
	proposedEvaluator := SnapshotEvaluatorFunc(func(_ context.Context, snapshot Snapshot, candidate Candidate) (protocol.DecisionOutcome, error) {
		proposedCalls.Add(1)
		if got := snapshot.Pins(); got != proposedPins {
			t.Errorf("proposed evaluator snapshot = %+v, want %+v", got, proposedPins)
		}
		return returnResponse(proposedResponses[candidate.CorrelationID])
	})
	engine, request, base, proposed := testFixture(t, baseEvaluator, proposedEvaluator, fixedClock())

	report, err := engine.Simulate(context.Background(), request, base, proposed, candidates)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if got, want := baseCalls.Load(), int64(len(tests)); got != want {
		t.Fatalf("base calls = %d, want %d", got, want)
	}
	if got, want := proposedCalls.Load(), int64(len(tests)); got != want {
		t.Fatalf("proposed calls = %d, want %d", got, want)
	}
	if len(report.Entries) != len(tests) {
		t.Fatalf("entries = %d, want %d", len(report.Entries), len(tests))
	}
	for index, test := range tests {
		entry := report.Entries[index]
		if entry.CorrelationID != test.correlationID || entry.Kind != test.kind ||
			entry.Before != test.before || entry.After != test.after || entry.ReasonCode != test.reason {
			t.Errorf("entry %d = %+v, want correlation=%q kind=%q before=%q after=%q reason=%q",
				index, entry, test.correlationID, test.kind, test.before, test.after, test.reason)
		}
	}
	if err := report.ValidateFor(request, testScope()); err != nil {
		t.Fatalf("report does not satisfy protocol: %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("report leaked evaluator error or panic text: %s", encoded)
	}
}

func TestEngineCanonicalizesAllTargetKindsWithoutMutatingInput(t *testing.T) {
	candidates := []Candidate{
		nonTupleCandidate("impact-d", "route-d", protocol.PolicyTargetResidencyRoute),
		{
			TenantID: "tenant-a", CorrelationID: "impact-b",
			TargetKind: protocol.PolicyTargetAuthorizationTuple, TargetID: "tuple-b",
			SubjectID: "user:alice", Relation: "can_view", Object: "document:doc-b",
		},
		nonTupleCandidate("impact-c", "connector-c", protocol.PolicyTargetConnectorState),
		nonTupleCandidate("impact-a", "membership-a", protocol.PolicyTargetIdentityMembership),
		{
			TenantID: "tenant-a", CorrelationID: "impact-e",
			TargetKind: protocol.PolicyTargetAuthorizationTuple, TargetID: "tuple-b",
			SubjectID: "user:bob", Relation: "can_edit", Object: "document:doc-e",
		},
	}
	original := slices.Clone(candidates)
	var baseOrder []string
	var proposedOrder []string
	baseEvaluator := SnapshotEvaluatorFunc(func(_ context.Context, _ Snapshot, candidate Candidate) (protocol.DecisionOutcome, error) {
		baseOrder = append(baseOrder, candidate.CorrelationID)
		candidate.TargetID = "evaluator-local-change"
		return protocol.DecisionDeny, nil
	})
	proposedEvaluator := SnapshotEvaluatorFunc(func(_ context.Context, _ Snapshot, candidate Candidate) (protocol.DecisionOutcome, error) {
		proposedOrder = append(proposedOrder, candidate.CorrelationID)
		return protocol.DecisionDeny, nil
	})
	engine, request, base, proposed := testFixture(t, baseEvaluator, proposedEvaluator, fixedClock())

	first, err := engine.Simulate(context.Background(), request, base, proposed, candidates)
	if err != nil {
		t.Fatalf("first Simulate() error = %v", err)
	}
	if !reflect.DeepEqual(candidates, original) {
		t.Fatalf("Simulate mutated candidates: got %+v, want %+v", candidates, original)
	}
	wantOrder := []string{"impact-a", "impact-b", "impact-c", "impact-d", "impact-e"}
	if !slices.Equal(baseOrder, wantOrder) || !slices.Equal(proposedOrder, wantOrder) {
		t.Fatalf("evaluation order base=%v proposed=%v, want %v", baseOrder, proposedOrder, wantOrder)
	}
	for index, correlationID := range wantOrder {
		if first.Entries[index].CorrelationID != correlationID {
			t.Fatalf("entry %d correlation = %q, want %q", index, first.Entries[index].CorrelationID, correlationID)
		}
	}

	baseOrder = nil
	proposedOrder = nil
	second, err := engine.Simulate(context.Background(), request, base, proposed, candidates)
	if err != nil {
		t.Fatalf("second Simulate() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("reports are not deterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestEngineRejectsMalformedDuplicateAndCrossTenantCandidatesBeforeEvaluation(t *testing.T) {
	valid := nonTupleCandidate("impact-a", "membership-a", protocol.PolicyTargetIdentityMembership)
	tests := []struct {
		name       string
		candidates []Candidate
	}{
		{name: "cross tenant", candidates: []Candidate{{TenantID: "tenant-b", CorrelationID: "impact-a", TargetKind: protocol.PolicyTargetIdentityMembership, TargetID: "membership-a"}}},
		{name: "malformed tuple", candidates: []Candidate{{TenantID: "tenant-a", CorrelationID: "impact-a", TargetKind: protocol.PolicyTargetAuthorizationTuple, TargetID: "tuple-a", SubjectID: "alice", Relation: "can_view", Object: "document:doc-a"}}},
		{name: "tuple fields on non tuple", candidates: []Candidate{{TenantID: "tenant-a", CorrelationID: "impact-a", TargetKind: protocol.PolicyTargetConnectorState, TargetID: "connector-a", SubjectID: "user:alice"}}},
		{name: "unsupported target kind", candidates: []Candidate{{TenantID: "tenant-a", CorrelationID: "impact-a", TargetKind: "other", TargetID: "target-a"}}},
		{name: "duplicate correlation", candidates: []Candidate{valid, nonTupleCandidate("impact-a", "membership-b", protocol.PolicyTargetIdentityMembership)}},
		{name: "duplicate target", candidates: []Candidate{valid, nonTupleCandidate("impact-b", "membership-a", protocol.PolicyTargetIdentityMembership)}},
		{name: "duplicate tuple target", candidates: []Candidate{
			{TenantID: "tenant-a", CorrelationID: "impact-a", TargetKind: protocol.PolicyTargetAuthorizationTuple, TargetID: "tuple-a", SubjectID: "user:alice", Relation: "can_view", Object: "document:doc-a"},
			{TenantID: "tenant-a", CorrelationID: "impact-b", TargetKind: protocol.PolicyTargetAuthorizationTuple, TargetID: "tuple-a", SubjectID: "user:alice", Relation: "can_view", Object: "document:doc-a"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			evaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
				calls.Add(1)
				return protocol.DecisionDeny, nil
			})
			engine, request, base, proposed := testFixture(t, evaluator, evaluator, fixedClock())
			report, err := engine.Simulate(context.Background(), request, base, proposed, test.candidates)
			if !errors.Is(err, ErrInvalidCandidate) {
				t.Fatalf("Simulate() error = %v, want ErrInvalidCandidate", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("evaluator calls = %d, want 0", calls.Load())
			}
			if !reflect.DeepEqual(report, protocol.PolicyImpactReport{}) {
				t.Fatalf("failed simulation returned partial report: %+v", report)
			}
		})
	}
}

func TestEngineRejectsInvalidRequestsBeforeEvaluation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.PolicySimulationRequest)
	}{
		{name: "legacy version", mutate: func(r *protocol.PolicySimulationRequest) { r.Version = protocol.EnterpriseContractVersion }},
		{name: "mutating mode", mutate: func(r *protocol.PolicySimulationRequest) { r.Mode = "apply" }},
		{name: "cross tenant", mutate: func(r *protocol.PolicySimulationRequest) { r.TenantID = "tenant-b" }},
		{name: "missing connector pin", mutate: func(r *protocol.PolicySimulationRequest) { r.ProposedConnectorWatermark = "" }},
		{name: "non utc request time", mutate: func(r *protocol.PolicySimulationRequest) {
			r.RequestedAt = time.Date(2026, time.July, 19, 10, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			evaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
				calls.Add(1)
				return protocol.DecisionDeny, nil
			})
			engine, request, base, proposed := testFixture(t, evaluator, evaluator, fixedClock())
			test.mutate(&request)
			_, err := engine.Simulate(context.Background(), request, base, proposed, nil)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Simulate() error = %v, want ErrInvalidRequest", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("evaluator calls = %d, want 0", calls.Load())
			}
		})
	}
}

func TestEngineRequiresEveryExactBaseAndProposedPin(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*SnapshotPins)
	}{
		{name: "tenant", mutate: func(p *SnapshotPins) { p.TenantID = "tenant-b" }},
		{name: "agent", mutate: func(p *SnapshotPins) { p.AgentID = "agent-other" }},
		{name: "task", mutate: func(p *SnapshotPins) { p.TaskID = "task-other" }},
		{name: "authorization model", mutate: func(p *SnapshotPins) { p.AuthorizationModelID = "model-other" }},
		{name: "identity", mutate: func(p *SnapshotPins) { p.IdentityWatermark = "identity-other" }},
		{name: "acl", mutate: func(p *SnapshotPins) { p.ACLWatermark = "acl-other" }},
		{name: "delegation", mutate: func(p *SnapshotPins) { p.DelegationWatermark = "delegation-other" }},
		{name: "agent task fingerprint", mutate: func(p *SnapshotPins) {
			p.AgentTaskScopeFingerprint = "scope_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "connector", mutate: func(p *SnapshotPins) { p.ConnectorWatermark = "connector-other" }},
		{name: "residency", mutate: func(p *SnapshotPins) { p.ResidencyWatermark = "residency-other" }},
	}
	for _, side := range []string{"base", "proposed"} {
		for _, mutation := range mutations {
			t.Run(side+" "+mutation.name, func(t *testing.T) {
				var calls atomic.Int64
				evaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
					calls.Add(1)
					return protocol.DecisionDeny, nil
				})
				engine, request, base, proposed := testFixture(t, evaluator, evaluator, fixedClock())
				if side == "base" {
					pins := base.Pins()
					mutation.mutate(&pins)
					base = mustSnapshot(t, pins)
				} else {
					pins := proposed.Pins()
					mutation.mutate(&pins)
					proposed = mustSnapshot(t, pins)
				}
				_, err := engine.Simulate(context.Background(), request, base, proposed, nil)
				if !errors.Is(err, ErrSnapshotPinMismatch) {
					t.Fatalf("Simulate() error = %v, want ErrSnapshotPinMismatch", err)
				}
				if calls.Load() != 0 {
					t.Fatalf("evaluator calls = %d, want 0", calls.Load())
				}
			})
		}
	}
}

func TestEngineSupportsEmptyAndMoreThanFiftyCandidates(t *testing.T) {
	var baseCalls atomic.Int64
	var proposedCalls atomic.Int64
	baseEvaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
		baseCalls.Add(1)
		return protocol.DecisionDeny, nil
	})
	proposedEvaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
		proposedCalls.Add(1)
		return protocol.DecisionAllow, nil
	})
	engine, request, base, proposed := testFixture(t, baseEvaluator, proposedEvaluator, fixedClock())

	empty, err := engine.Simulate(context.Background(), request, base, proposed, nil)
	if err != nil {
		t.Fatalf("empty Simulate() error = %v", err)
	}
	if empty.Entries == nil || len(empty.Entries) != 0 {
		t.Fatalf("empty entries = %#v, want explicit empty slice", empty.Entries)
	}

	const candidateCount = 73
	candidates := make([]Candidate, 0, candidateCount)
	for index := candidateCount - 1; index >= 0; index-- {
		candidates = append(candidates, nonTupleCandidate(
			fmt.Sprintf("impact-%03d", index),
			fmt.Sprintf("connector-%03d", index),
			protocol.PolicyTargetConnectorState,
		))
	}
	report, err := engine.Simulate(context.Background(), request, base, proposed, candidates)
	if err != nil {
		t.Fatalf("large Simulate() error = %v", err)
	}
	if len(report.Entries) != candidateCount {
		t.Fatalf("entries = %d, want %d", len(report.Entries), candidateCount)
	}
	if baseCalls.Load() != candidateCount || proposedCalls.Load() != candidateCount {
		t.Fatalf("per-candidate calls base=%d proposed=%d, want %d each", baseCalls.Load(), proposedCalls.Load(), candidateCount)
	}
	for index, entry := range report.Entries {
		wantID := fmt.Sprintf("impact-%03d", index)
		if entry.CorrelationID != wantID || entry.Kind != protocol.PolicyImpactGrant || entry.ReasonCode != ReasonGrant {
			t.Fatalf("entry %d = %+v, want sorted grant %q", index, entry, wantID)
		}
	}
}

func TestEngineHonorsCancellationWithoutPartialReports(t *testing.T) {
	candidate := nonTupleCandidate("impact-a", "membership-a", protocol.PolicyTargetIdentityMembership)
	t.Run("already canceled", func(t *testing.T) {
		var calls atomic.Int64
		evaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
			calls.Add(1)
			return protocol.DecisionDeny, nil
		})
		engine, request, base, proposed := testFixture(t, evaluator, evaluator, fixedClock())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report, err := engine.Simulate(ctx, request, base, proposed, []Candidate{candidate})
		if !errors.Is(err, context.Canceled) || calls.Load() != 0 {
			t.Fatalf("Simulate() report=%+v error=%v calls=%d, want cancellation before evaluation", report, err, calls.Load())
		}
	})

	t.Run("between snapshots", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var proposedCalls atomic.Int64
		var clockCalls atomic.Int64
		baseEvaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
			cancel()
			return protocol.DecisionDeny, nil
		})
		proposedEvaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
			proposedCalls.Add(1)
			return protocol.DecisionAllow, nil
		})
		clock := ClockFunc(func() time.Time {
			clockCalls.Add(1)
			return testGeneratedAt
		})
		engine, request, base, proposed := testFixture(t, baseEvaluator, proposedEvaluator, clock)
		report, err := engine.Simulate(ctx, request, base, proposed, []Candidate{candidate})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Simulate() error = %v, want context.Canceled", err)
		}
		if proposedCalls.Load() != 0 || clockCalls.Load() != 0 {
			t.Fatalf("proposed calls=%d clock calls=%d, want zero", proposedCalls.Load(), clockCalls.Load())
		}
		if !reflect.DeepEqual(report, protocol.PolicyImpactReport{}) {
			t.Fatalf("canceled simulation returned partial report: %+v", report)
		}
	})

	t.Run("during evaluator", func(t *testing.T) {
		started := make(chan struct{})
		var proposedCalls atomic.Int64
		baseEvaluator := SnapshotEvaluatorFunc(func(ctx context.Context, _ Snapshot, _ Candidate) (protocol.DecisionOutcome, error) {
			close(started)
			<-ctx.Done()
			return protocol.DecisionIndeterminate, ctx.Err()
		})
		proposedEvaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
			proposedCalls.Add(1)
			return protocol.DecisionAllow, nil
		})
		engine, request, base, proposed := testFixture(t, baseEvaluator, proposedEvaluator, fixedClock())
		ctx, cancel := context.WithCancel(context.Background())
		type result struct {
			report protocol.PolicyImpactReport
			err    error
		}
		done := make(chan result, 1)
		go func() {
			report, err := engine.Simulate(ctx, request, base, proposed, []Candidate{candidate})
			done <- result{report: report, err: err}
		}()
		<-started
		cancel()
		select {
		case got := <-done:
			if !errors.Is(got.err, context.Canceled) || proposedCalls.Load() != 0 ||
				!reflect.DeepEqual(got.report, protocol.PolicyImpactReport{}) {
				t.Fatalf("canceled result report=%+v error=%v proposed calls=%d", got.report, got.err, proposedCalls.Load())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Simulate did not return after cancellation")
		}
	})
}

func TestEngineValidatesDependenciesContextAndClock(t *testing.T) {
	evaluator := SnapshotEvaluatorFunc(func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error) {
		return protocol.DecisionDeny, nil
	})
	var nilEvaluator SnapshotEvaluatorFunc
	if _, err := NewEngine(testScope(), nilEvaluator, evaluator, fixedClock()); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil evaluator error = %v, want ErrInvalidConfiguration", err)
	}
	var nilClock ClockFunc
	if _, err := NewEngine(testScope(), evaluator, evaluator, nilClock); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil clock error = %v, want ErrInvalidConfiguration", err)
	}

	engine, request, base, proposed := testFixture(t, evaluator, evaluator, fixedClock())
	var nilContext context.Context
	if _, err := engine.Simulate(nilContext, request, base, proposed, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil context error = %v, want ErrInvalidRequest", err)
	}

	clocks := []struct {
		name  string
		clock Clock
	}{
		{name: "zero", clock: ClockFunc(func() time.Time { return time.Time{} })},
		{name: "non utc", clock: ClockFunc(func() time.Time {
			return time.Date(2026, time.July, 19, 10, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
		})},
		{name: "panic", clock: ClockFunc(func() time.Time { panic("clock secret") })},
	}
	for _, test := range clocks {
		t.Run(test.name, func(t *testing.T) {
			engine, request, base, proposed := testFixture(t, evaluator, evaluator, test.clock)
			report, err := engine.Simulate(context.Background(), request, base, proposed, nil)
			if !errors.Is(err, ErrInvalidClock) {
				t.Fatalf("Simulate() error = %v, want ErrInvalidClock", err)
			}
			if !reflect.DeepEqual(report, protocol.PolicyImpactReport{}) {
				t.Fatalf("invalid clock returned partial report: %+v", report)
			}
		})
	}
}

func TestEngineIsRaceFriendlyForConcurrentSimulation(t *testing.T) {
	evaluator := SnapshotEvaluatorFunc(func(_ context.Context, snapshot Snapshot, candidate Candidate) (protocol.DecisionOutcome, error) {
		pins := snapshot.Pins()
		if pins.AuthorizationModelID == "" || candidate.TargetID == "" {
			return protocol.DecisionIndeterminate, errors.New("missing immutable input")
		}
		return protocol.DecisionDeny, nil
	})
	engine, request, base, proposed := testFixture(t, evaluator, evaluator, fixedClock())
	candidates := make([]Candidate, 0, 8)
	for index := 7; index >= 0; index-- {
		candidates = append(candidates, nonTupleCandidate(
			fmt.Sprintf("impact-%02d", index),
			fmt.Sprintf("membership-%02d", index),
			protocol.PolicyTargetIdentityMembership,
		))
	}

	const workers = 32
	errorsOut := make(chan error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			report, err := engine.Simulate(context.Background(), request, base, proposed, candidates)
			if err != nil {
				errorsOut <- err
				return
			}
			if len(report.Entries) != len(candidates) || report.Entries[0].CorrelationID != "impact-00" {
				errorsOut <- fmt.Errorf("unexpected concurrent report: %+v", report)
			}
		}()
	}
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Error(err)
	}
}

func returnResponse(response struct {
	outcome    protocol.DecisionOutcome
	err        error
	panicValue any
}) (protocol.DecisionOutcome, error) {
	if response.panicValue != nil {
		panic(response.panicValue)
	}
	return response.outcome, response.err
}

func testFixture(
	t *testing.T,
	baseEvaluator SnapshotEvaluator,
	proposedEvaluator SnapshotEvaluator,
	clock Clock,
) (*Engine, protocol.PolicySimulationRequest, Snapshot, Snapshot) {
	t.Helper()
	engine, err := NewEngine(testScope(), baseEvaluator, proposedEvaluator, clock)
	if err != nil {
		t.Fatalf("NewEngine(): %v", err)
	}
	return engine, testRequest(), mustSnapshot(t, testBasePins()), mustSnapshot(t, testProposedPins())
}

func testScope() protocol.TenantScope {
	return protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: "tenant-a", Region: "cn-east",
	}
}

func testRequest() protocol.PolicySimulationRequest {
	return protocol.PolicySimulationRequest{
		Version: protocol.GovernanceContractVersion, TenantID: "tenant-a",
		SimulationID: "simulation-a", RequestID: "request-a", ActorID: "operator-a",
		Mode: protocol.PolicySimulationReadOnly, AgentID: "agent-a", TaskID: "task-a",
		BaseAuthorizationModelID: "model-v1", ProposedAuthorizationModelID: "model-v2",
		BaseIdentityWatermark: "identity-v1", ProposedIdentityWatermark: "identity-v2",
		BaseACLWatermark: "acl-v1", ProposedACLWatermark: "acl-v2",
		BaseDelegationWatermark: "delegation-v1", ProposedDelegationWatermark: "delegation-v2",
		BaseAgentTaskScope:     "scope_00000000000000000000000000000001",
		ProposedAgentTaskScope: "scope_00000000000000000000000000000002",
		BaseConnectorWatermark: "connector-v1", ProposedConnectorWatermark: "connector-v2",
		BaseResidencyWatermark: "residency-v1", ProposedResidencyWatermark: "residency-v2",
		RequestedAt: time.Date(2026, time.July, 19, 1, 0, 0, 0, time.UTC),
	}
}

func testBasePins() SnapshotPins {
	request := testRequest()
	return SnapshotPins{
		TenantID: request.TenantID, AgentID: request.AgentID, TaskID: request.TaskID,
		AuthorizationModelID: request.BaseAuthorizationModelID,
		IdentityWatermark:    request.BaseIdentityWatermark, ACLWatermark: request.BaseACLWatermark,
		DelegationWatermark: request.BaseDelegationWatermark, AgentTaskScopeFingerprint: request.BaseAgentTaskScope,
		ConnectorWatermark: request.BaseConnectorWatermark, ResidencyWatermark: request.BaseResidencyWatermark,
	}
}

func testProposedPins() SnapshotPins {
	request := testRequest()
	return SnapshotPins{
		TenantID: request.TenantID, AgentID: request.AgentID, TaskID: request.TaskID,
		AuthorizationModelID: request.ProposedAuthorizationModelID,
		IdentityWatermark:    request.ProposedIdentityWatermark, ACLWatermark: request.ProposedACLWatermark,
		DelegationWatermark: request.ProposedDelegationWatermark, AgentTaskScopeFingerprint: request.ProposedAgentTaskScope,
		ConnectorWatermark: request.ProposedConnectorWatermark, ResidencyWatermark: request.ProposedResidencyWatermark,
	}
}

func mustSnapshot(t *testing.T, pins SnapshotPins) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(pins)
	if err != nil {
		t.Fatalf("NewSnapshot(): %v", err)
	}
	return snapshot
}

func fixedClock() Clock {
	return ClockFunc(func() time.Time { return testGeneratedAt })
}

func nonTupleCandidate(correlationID, targetID string, kind protocol.PolicyImpactTargetKind) Candidate {
	return Candidate{
		TenantID: "tenant-a", CorrelationID: correlationID, TargetKind: kind, TargetID: targetID,
	}
}
