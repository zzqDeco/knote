// Package policysim provides deterministic, read-only governance policy
// simulation over explicitly pinned immutable snapshots.
package policysim

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	ErrInvalidConfiguration = errors.New("invalid policy simulation configuration")
	ErrInvalidRequest       = errors.New("invalid policy simulation request")
	ErrSnapshotPinMismatch  = errors.New("policy simulation snapshot pins do not match request")
	ErrInvalidCandidate     = errors.New("invalid policy simulation candidate")
	ErrInvalidClock         = errors.New("invalid policy simulation clock")
	ErrInvalidReport        = errors.New("invalid policy simulation report")
)

const (
	ReasonGrant                      = "base-deny-proposed-allow"
	ReasonRevoke                     = "base-allow-proposed-deny"
	ReasonUnchangedAllow             = "allow-unchanged"
	ReasonUnchangedDeny              = "deny-unchanged"
	ReasonBaseUnknown                = "base-evaluation-unknown"
	ReasonProposedUnknown            = "proposed-evaluation-unknown"
	ReasonBothUnknown                = "base-and-proposed-evaluation-unknown"
	ReasonBaseFailure                = "base-evaluation-failure"
	ReasonProposedFailure            = "proposed-evaluation-failure"
	ReasonBothFailure                = "base-and-proposed-evaluation-failure"
	ReasonBaseFailureProposedUnknown = "base-failure-proposed-unknown"
	ReasonBaseUnknownProposedFailure = "base-unknown-proposed-failure"
)

// Candidate identifies one content-free impact target. Tuple fields are used
// only for authorization tuple targets and must be empty for all other kinds.
type Candidate struct {
	TenantID      string
	CorrelationID string
	TargetKind    protocol.PolicyImpactTargetKind
	TargetID      string
	SubjectID     string
	Relation      string
	Object        string
}

// SnapshotEvaluator evaluates exactly one candidate against the supplied
// immutable snapshot. Allow and deny are determinate; indeterminate means the
// result is unknown. A non-nil error is recorded as an evaluation failure.
type SnapshotEvaluator interface {
	Evaluate(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error)
}

type SnapshotEvaluatorFunc func(context.Context, Snapshot, Candidate) (protocol.DecisionOutcome, error)

func (f SnapshotEvaluatorFunc) Evaluate(
	ctx context.Context,
	snapshot Snapshot,
	candidate Candidate,
) (protocol.DecisionOutcome, error) {
	return f(ctx, snapshot, candidate)
}

type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

// Engine is stateless after construction and is safe for concurrent use when
// its injected evaluators and clock are safe for concurrent use.
type Engine struct {
	scope             protocol.TenantScope
	baseEvaluator     SnapshotEvaluator
	proposedEvaluator SnapshotEvaluator
	clock             Clock
}

func NewEngine(
	scope protocol.TenantScope,
	baseEvaluator SnapshotEvaluator,
	proposedEvaluator SnapshotEvaluator,
	clock Clock,
) (*Engine, error) {
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("%w: tenant scope: %v", ErrInvalidConfiguration, err)
	}
	if isNilInterface(baseEvaluator) {
		return nil, fmt.Errorf("%w: base evaluator is required", ErrInvalidConfiguration)
	}
	if isNilInterface(proposedEvaluator) {
		return nil, fmt.Errorf("%w: proposed evaluator is required", ErrInvalidConfiguration)
	}
	if isNilInterface(clock) {
		return nil, fmt.Errorf("%w: clock is required", ErrInvalidConfiguration)
	}
	return &Engine{
		scope:             scope,
		baseEvaluator:     baseEvaluator,
		proposedEvaluator: proposedEvaluator,
		clock:             clock,
	}, nil
}

// Simulate compares independently evaluated base and proposed snapshots. It
// never mutates either snapshot, candidate input, or serving state.
func (e *Engine) Simulate(
	ctx context.Context,
	request protocol.PolicySimulationRequest,
	base Snapshot,
	proposed Snapshot,
	candidates []Candidate,
) (protocol.PolicyImpactReport, error) {
	if e == nil {
		return protocol.PolicyImpactReport{}, fmt.Errorf("%w: engine is nil", ErrInvalidConfiguration)
	}
	if isNilInterface(ctx) {
		return protocol.PolicyImpactReport{}, fmt.Errorf("%w: context is required", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return protocol.PolicyImpactReport{}, err
	}
	if request.Version != protocol.GovernanceContractVersion {
		return protocol.PolicyImpactReport{}, fmt.Errorf(
			"%w: version must be %s", ErrInvalidRequest, protocol.GovernanceContractVersion,
		)
	}
	if err := request.ValidateFor(e.scope); err != nil {
		return protocol.PolicyImpactReport{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := validateRequestedSnapshot("base", base.Pins(), request, true); err != nil {
		return protocol.PolicyImpactReport{}, err
	}
	if err := validateRequestedSnapshot("proposed", proposed.Pins(), request, false); err != nil {
		return protocol.PolicyImpactReport{}, err
	}

	canonical, err := e.canonicalizeCandidates(ctx, request, candidates)
	if err != nil {
		return protocol.PolicyImpactReport{}, err
	}
	entries := make([]protocol.PolicyImpactEntry, 0, len(canonical))
	for _, candidate := range canonical {
		if err := ctx.Err(); err != nil {
			return protocol.PolicyImpactReport{}, err
		}
		before := evaluate(ctx, e.baseEvaluator, base, candidate)
		if err := ctx.Err(); err != nil {
			return protocol.PolicyImpactReport{}, err
		}
		after := evaluate(ctx, e.proposedEvaluator, proposed, candidate)
		if err := ctx.Err(); err != nil {
			return protocol.PolicyImpactReport{}, err
		}
		kind, reasonCode := classify(before, after)
		entries = append(entries, protocol.PolicyImpactEntry{
			CorrelationID: candidate.CorrelationID,
			TargetKind:    candidate.TargetKind,
			TargetID:      candidate.TargetID,
			SubjectID:     candidate.SubjectID,
			Relation:      candidate.Relation,
			Object:        candidate.Object,
			Kind:          kind,
			Before:        before.outcome,
			After:         after.outcome,
			ReasonCode:    reasonCode,
		})
	}
	if err := ctx.Err(); err != nil {
		return protocol.PolicyImpactReport{}, err
	}
	generatedAt, err := readClock(e.clock)
	if err != nil {
		return protocol.PolicyImpactReport{}, err
	}
	report := protocol.PolicyImpactReport{
		Version:      protocol.GovernanceContractVersion,
		TenantID:     request.TenantID,
		SimulationID: request.SimulationID,
		GeneratedAt:  generatedAt,
		Entries:      entries,
	}
	if err := report.ValidateFor(request, e.scope); err != nil {
		return protocol.PolicyImpactReport{}, fmt.Errorf("%w: %v", ErrInvalidReport, err)
	}
	return report, nil
}

func (e *Engine) canonicalizeCandidates(
	ctx context.Context,
	request protocol.PolicySimulationRequest,
	candidates []Candidate,
) ([]Candidate, error) {
	canonical := append([]Candidate(nil), candidates...)
	for index, candidate := range canonical {
		if index%64 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if candidate.TenantID != request.TenantID || candidate.TenantID != e.scope.TenantID {
			return nil, fmt.Errorf("%w: candidate %d crosses the tenant scope", ErrInvalidCandidate, index)
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		return canonical[left].CorrelationID < canonical[right].CorrelationID
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	entries := make([]protocol.PolicyImpactEntry, 0, len(canonical))
	for _, candidate := range canonical {
		entries = append(entries, protocol.PolicyImpactEntry{
			CorrelationID: candidate.CorrelationID,
			TargetKind:    candidate.TargetKind,
			TargetID:      candidate.TargetID,
			SubjectID:     candidate.SubjectID,
			Relation:      candidate.Relation,
			Object:        candidate.Object,
			Kind:          protocol.PolicyImpactUnchanged,
			Before:        protocol.DecisionDeny,
			After:         protocol.DecisionDeny,
			ReasonCode:    ReasonUnchangedDeny,
		})
	}
	validationReport := protocol.PolicyImpactReport{
		Version:      protocol.GovernanceContractVersion,
		TenantID:     request.TenantID,
		SimulationID: request.SimulationID,
		GeneratedAt:  request.RequestedAt,
		Entries:      entries,
	}
	if err := validationReport.ValidateFor(request, e.scope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCandidate, err)
	}
	return canonical, nil
}

func validateRequestedSnapshot(
	name string,
	pins SnapshotPins,
	request protocol.PolicySimulationRequest,
	base bool,
) error {
	expected := SnapshotPins{
		TenantID: request.TenantID,
		AgentID:  request.AgentID,
		TaskID:   request.TaskID,
	}
	if base {
		expected.AuthorizationModelID = request.BaseAuthorizationModelID
		expected.IdentityWatermark = request.BaseIdentityWatermark
		expected.ACLWatermark = request.BaseACLWatermark
		expected.DelegationWatermark = request.BaseDelegationWatermark
		expected.AgentTaskScopeFingerprint = request.BaseAgentTaskScope
		expected.ConnectorWatermark = request.BaseConnectorWatermark
		expected.ResidencyWatermark = request.BaseResidencyWatermark
	} else {
		expected.AuthorizationModelID = request.ProposedAuthorizationModelID
		expected.IdentityWatermark = request.ProposedIdentityWatermark
		expected.ACLWatermark = request.ProposedACLWatermark
		expected.DelegationWatermark = request.ProposedDelegationWatermark
		expected.AgentTaskScopeFingerprint = request.ProposedAgentTaskScope
		expected.ConnectorWatermark = request.ProposedConnectorWatermark
		expected.ResidencyWatermark = request.ProposedResidencyWatermark
	}
	if pins != expected {
		return fmt.Errorf("%w: %s snapshot", ErrSnapshotPinMismatch, name)
	}
	return nil
}

type evaluationState uint8

const (
	evaluationKnown evaluationState = iota
	evaluationUnknown
	evaluationFailure
)

type evaluation struct {
	outcome protocol.DecisionOutcome
	state   evaluationState
}

func evaluate(
	ctx context.Context,
	evaluator SnapshotEvaluator,
	snapshot Snapshot,
	candidate Candidate,
) (result evaluation) {
	result = evaluation{outcome: protocol.DecisionIndeterminate, state: evaluationFailure}
	defer func() {
		if recover() != nil {
			result = evaluation{outcome: protocol.DecisionIndeterminate, state: evaluationFailure}
		}
	}()
	outcome, err := evaluator.Evaluate(ctx, snapshot, candidate)
	if err != nil {
		return result
	}
	switch outcome {
	case protocol.DecisionAllow, protocol.DecisionDeny:
		return evaluation{outcome: outcome, state: evaluationKnown}
	case protocol.DecisionIndeterminate:
		return evaluation{outcome: outcome, state: evaluationUnknown}
	default:
		return result
	}
}

func classify(before, after evaluation) (protocol.PolicyImpactKind, string) {
	if before.state == evaluationFailure || after.state == evaluationFailure {
		switch {
		case before.state == evaluationFailure && after.state == evaluationFailure:
			return protocol.PolicyImpactFailure, ReasonBothFailure
		case before.state == evaluationFailure && after.state == evaluationUnknown:
			return protocol.PolicyImpactFailure, ReasonBaseFailureProposedUnknown
		case before.state == evaluationUnknown && after.state == evaluationFailure:
			return protocol.PolicyImpactFailure, ReasonBaseUnknownProposedFailure
		case before.state == evaluationFailure:
			return protocol.PolicyImpactFailure, ReasonBaseFailure
		default:
			return protocol.PolicyImpactFailure, ReasonProposedFailure
		}
	}
	if before.state == evaluationUnknown || after.state == evaluationUnknown {
		switch {
		case before.state == evaluationUnknown && after.state == evaluationUnknown:
			return protocol.PolicyImpactUnknown, ReasonBothUnknown
		case before.state == evaluationUnknown:
			return protocol.PolicyImpactUnknown, ReasonBaseUnknown
		default:
			return protocol.PolicyImpactUnknown, ReasonProposedUnknown
		}
	}
	switch {
	case before.outcome == protocol.DecisionDeny && after.outcome == protocol.DecisionAllow:
		return protocol.PolicyImpactGrant, ReasonGrant
	case before.outcome == protocol.DecisionAllow && after.outcome == protocol.DecisionDeny:
		return protocol.PolicyImpactRevoke, ReasonRevoke
	case before.outcome == protocol.DecisionAllow:
		return protocol.PolicyImpactUnchanged, ReasonUnchangedAllow
	default:
		return protocol.PolicyImpactUnchanged, ReasonUnchangedDeny
	}
}

func readClock(clock Clock) (at time.Time, err error) {
	defer func() {
		if recover() != nil {
			at = time.Time{}
			err = fmt.Errorf("%w: clock panicked", ErrInvalidClock)
		}
	}()
	at = clock.Now()
	_, offset := at.Zone()
	if at.IsZero() || offset != 0 {
		return time.Time{}, fmt.Errorf("%w: generated time must be non-zero UTC", ErrInvalidClock)
	}
	return at, nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
