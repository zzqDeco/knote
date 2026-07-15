package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type ProtectedQueryInternalOutcome string

const (
	ProtectedQueryInternalAllowed         ProtectedQueryInternalOutcome = "allowed"
	ProtectedQueryInternalHidden          ProtectedQueryInternalOutcome = "hidden"
	ProtectedQueryInternalAbsent          ProtectedQueryInternalOutcome = "absent"
	ProtectedQueryInternalCrossTenant     ProtectedQueryInternalOutcome = "cross_tenant"
	ProtectedQueryInternalDenied          ProtectedQueryInternalOutcome = "denied"
	ProtectedQueryInternalProviderFailure ProtectedQueryInternalOutcome = "provider_failure"
)

const (
	ProtectedQueryNotFoundTimingFloor          = 50 * time.Millisecond
	ProtectedQueryNotFoundTimingVarianceBudget = 5 * time.Millisecond
)

var ErrProtectedQueryTimingBudgetExceeded = errors.New("protected query timing budget exceeded")

// ProtectedQueryProjectionInput is the trust boundary between query internals
// and the public protocol. Only Visible and the typed metadata fields can cross
// it. Cause, Diagnostics, and Sensitive are deliberately ignored.
type ProtectedQueryProjectionInput struct {
	Outcome               ProtectedQueryInternalOutcome
	Operation             protocol.ProtectedQueryOperation
	Visible               protocol.ProtectedQueryVisibleResult
	ProjectionVersion     string
	VisibilityFingerprint protocol.VisibilityFingerprint
	Plan                  *protocol.ProtectedTraversalPlanIdentity
	LatencyBucket         protocol.ProtectedQueryLatencyBucket
	Cause                 error
	Diagnostics           map[string]any
	Sensitive             any
}

func ProjectProtectedQuery(input ProtectedQueryProjectionInput) protocol.ProtectedQueryEnvelope {
	operation := normalizedProtectedQueryOperation(input.Operation)
	switch input.Outcome {
	case ProtectedQueryInternalAllowed:
		return projectAllowedProtectedQuery(operation, input)
	case ProtectedQueryInternalHidden, ProtectedQueryInternalAbsent, ProtectedQueryInternalCrossTenant:
		return protectedQueryErrorEnvelope(operation, protocol.ProtectedQueryOutcomeNotFound,
			protocol.NewProtectedQueryNotFoundError())
	case ProtectedQueryInternalDenied:
		return protectedQueryErrorEnvelope(operation, protocol.ProtectedQueryOutcomePermissionDenied,
			protocol.NewProtectedQueryPermissionDeniedError())
	case ProtectedQueryInternalProviderFailure:
		return protectedQueryErrorEnvelope(operation, protocol.ProtectedQueryOutcomeProviderUnavailable,
			protocol.NewProtectedQueryProviderUnavailableError())
	default:
		return protectedQueryErrorEnvelope(operation, protocol.ProtectedQueryOutcomeProviderUnavailable,
			protocol.NewProtectedQueryProviderUnavailableError())
	}
}

type ProtectedQueryTimingBudget struct {
	Floor       time.Duration
	MaxVariance time.Duration
}

func DefaultProtectedQueryTimingBudget() ProtectedQueryTimingBudget {
	return ProtectedQueryTimingBudget{
		Floor: ProtectedQueryNotFoundTimingFloor, MaxVariance: ProtectedQueryNotFoundTimingVarianceBudget,
	}
}

func (budget ProtectedQueryTimingBudget) Validate() error {
	if budget.Floor <= 0 || budget.MaxVariance < 0 || budget.MaxVariance > budget.Floor {
		return ErrProtectedQueryTimingBudgetExceeded
	}
	return nil
}

func (budget ProtectedQueryTimingBudget) ReleaseDelay(
	outcome ProtectedQueryInternalOutcome,
	elapsed time.Duration,
) (time.Duration, error) {
	if err := budget.Validate(); err != nil || elapsed < 0 {
		return 0, ErrProtectedQueryTimingBudgetExceeded
	}
	if !protectedQueryNotFoundTimingOutcome(outcome) {
		return 0, nil
	}
	if elapsed > budget.Floor+budget.MaxVariance {
		return 0, ErrProtectedQueryTimingBudgetExceeded
	}
	if elapsed >= budget.Floor {
		return 0, nil
	}
	return budget.Floor - elapsed, nil
}

type ProtectedQueryTimingWaiter func(context.Context, time.Duration) error

func EnforceProtectedQueryTiming(
	ctx context.Context,
	budget ProtectedQueryTimingBudget,
	outcome ProtectedQueryInternalOutcome,
	elapsed time.Duration,
	wait ProtectedQueryTimingWaiter,
) error {
	if ctx == nil {
		return ErrProtectedQueryTimingBudgetExceeded
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	delay, err := budget.ReleaseDelay(outcome, elapsed)
	if err != nil || delay == 0 {
		return err
	}
	if wait != nil {
		return wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func protectedQueryNotFoundTimingOutcome(outcome ProtectedQueryInternalOutcome) bool {
	switch outcome {
	case ProtectedQueryInternalHidden, ProtectedQueryInternalAbsent, ProtectedQueryInternalCrossTenant:
		return true
	default:
		return false
	}
}

func projectAllowedProtectedQuery(
	operation protocol.ProtectedQueryOperation,
	input ProtectedQueryProjectionInput,
) protocol.ProtectedQueryEnvelope {
	visible := protocol.CanonicalizeProtectedQueryVisibleResult(input.Visible)
	metadata := protectedQueryMetadata(operation, protocol.ProtectedQueryOutcomeOK)
	metadata.Debug = protocol.ProtectedQueryDebugMetadata{
		ProjectionVersion: input.ProjectionVersion, VisibilityFingerprint: input.VisibilityFingerprint,
		Plan: cloneProtectedTraversalPlanIdentity(input.Plan),
	}
	metadata.Metrics.LatencyBucket = input.LatencyBucket
	envelope := protocol.ProtectedQueryEnvelope{
		Version: protocol.ProtectedQueryContractVersion, Result: visible, Metadata: metadata,
	}
	if err := envelope.Validate(); err != nil {
		return protectedQueryErrorEnvelope(operation, protocol.ProtectedQueryOutcomeProviderUnavailable,
			protocol.NewProtectedQueryProviderUnavailableError())
	}
	return envelope
}

func protectedQueryErrorEnvelope(
	operation protocol.ProtectedQueryOperation,
	outcome protocol.ProtectedQueryPublicOutcome,
	publicError *protocol.ProtectedQueryPublicError,
) protocol.ProtectedQueryEnvelope {
	return protocol.ProtectedQueryEnvelope{
		Version:  protocol.ProtectedQueryContractVersion,
		Result:   protocol.EmptyProtectedQueryVisibleResult(),
		Error:    publicError,
		Metadata: protectedQueryMetadata(operation, outcome),
	}
}

func protectedQueryMetadata(
	operation protocol.ProtectedQueryOperation,
	outcome protocol.ProtectedQueryPublicOutcome,
) protocol.ProtectedQueryMetadata {
	return protocol.ProtectedQueryMetadata{
		Trace:   protocol.ProtectedQueryTraceMetadata{Operation: operation, Outcome: outcome},
		Metrics: protocol.ProtectedQueryMetricsMetadata{Operation: operation, Outcome: outcome},
		Audit:   protocol.ProtectedQueryAuditMetadata{Action: "protected_query", Decision: outcome},
	}
}

func normalizedProtectedQueryOperation(operation protocol.ProtectedQueryOperation) protocol.ProtectedQueryOperation {
	if operation.Validate() != nil {
		return protocol.ProtectedQueryOperationQuery
	}
	return operation
}

func cloneProtectedTraversalPlanIdentity(
	identity *protocol.ProtectedTraversalPlanIdentity,
) *protocol.ProtectedTraversalPlanIdentity {
	if identity == nil {
		return nil
	}
	cloned := *identity
	return &cloned
}

func ProtectedQueryLatencyBucketFor(elapsed time.Duration) protocol.ProtectedQueryLatencyBucket {
	switch {
	case elapsed < 10*time.Millisecond:
		return protocol.ProtectedQueryLatencyUnder10MS
	case elapsed < 50*time.Millisecond:
		return protocol.ProtectedQueryLatencyUnder50MS
	case elapsed < 250*time.Millisecond:
		return protocol.ProtectedQueryLatencyUnder250MS
	default:
		return protocol.ProtectedQueryLatencyOver250MS
	}
}
