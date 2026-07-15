package catalog

import (
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

type OperationOutcome string

const (
	OperationSucceeded OperationOutcome = "succeeded"
	OperationFailed    OperationOutcome = "failed"
)

type OperationResult struct {
	OperationID string           `json:"operation_id"`
	Outcome     OperationOutcome `json:"outcome"`
	ErrorCode   string           `json:"error_code,omitempty"`
}

func (r OperationResult) Validate() error {
	if err := validateToken("operation_id", r.OperationID); err != nil {
		return err
	}
	switch r.Outcome {
	case OperationSucceeded:
		if r.ErrorCode != "" {
			return fmt.Errorf("successful operation %s has an error code", r.OperationID)
		}
	case OperationFailed:
		if err := validateToken("error_code", r.ErrorCode); err != nil {
			return fmt.Errorf("failed operation %s: %w", r.OperationID, err)
		}
	default:
		return fmt.Errorf("unsupported operation outcome %q", r.Outcome)
	}
	return nil
}

type OperationReceipt struct {
	OperationID       string           `json:"operation_id"`
	RunID             string           `json:"run_id"`
	ProjectionVersion string           `json:"projection_version"`
	IdempotencyKey    string           `json:"idempotency_key"`
	Outcome           OperationOutcome `json:"outcome"`
	ErrorCode         string           `json:"error_code,omitempty"`
}

func (r OperationReceipt) Validate() error {
	if err := validateToken("operation_id", r.OperationID); err != nil {
		return err
	}
	if err := validateToken("run_id", r.RunID); err != nil {
		return err
	}
	if err := validateToken("projection_version", r.ProjectionVersion); err != nil {
		return err
	}
	if err := validateToken("idempotency_key", r.IdempotencyKey); err != nil {
		return err
	}
	return OperationResult{
		OperationID: r.OperationID, Outcome: r.Outcome, ErrorCode: r.ErrorCode,
	}.Validate()
}

type ReplayReport struct {
	PlanID              string   `json:"plan_id"`
	RunID               string   `json:"run_id"`
	RunState            RunState `json:"run_state"`
	IdempotentNoop      bool     `json:"idempotent_noop"`
	AppliedOperationIDs []string `json:"applied_operation_ids"`
}

// Replay reduces a complete result set into a new immutable projection value.
// It does not persist data or move a serving pointer.
func Replay(
	plan ProjectionPlan,
	current Projection,
	results []OperationResult,
) (Projection, ReplayReport, error) {
	if err := plan.Validate(); err != nil {
		return Projection{}, ReplayReport{}, err
	}
	if err := current.Validate(); err != nil {
		return Projection{}, ReplayReport{}, err
	}
	if containsSorted(current.AppliedPlanIDs, plan.PlanID) {
		runState, err := runStateForAppliedPlan(current, plan)
		if err != nil {
			return Projection{}, ReplayReport{}, err
		}
		return cloneProjection(current), ReplayReport{
			PlanID: plan.PlanID, RunID: plan.Run.RunID,
			RunState: runState, IdempotentNoop: true,
		}, nil
	}
	if current.State != StatePublished {
		return Projection{}, ReplayReport{}, fmt.Errorf("projection replay requires a published base projection")
	}
	if current.Scope != plan.Run.Scope || current.Version != plan.Run.BaseProjectionVersion {
		return Projection{}, ReplayReport{}, fmt.Errorf("projection plan does not apply to the current projection")
	}
	if err := validateReplayPlan(plan, current); err != nil {
		return Projection{}, ReplayReport{}, err
	}

	resultByID := make(map[string]OperationResult, len(results))
	for _, result := range results {
		if err := result.Validate(); err != nil {
			return Projection{}, ReplayReport{}, err
		}
		if _, duplicate := resultByID[result.OperationID]; duplicate {
			return Projection{}, ReplayReport{}, fmt.Errorf("duplicate result for operation %s", result.OperationID)
		}
		resultByID[result.OperationID] = result
	}
	if len(resultByID) != len(plan.Operations) {
		return Projection{}, ReplayReport{}, fmt.Errorf("projection replay requires one result for every operation")
	}

	targets := make(map[protocol.ResourceID]ResourceMetadata)
	terminalResources := make(map[protocol.ResourceID]ResourceMetadata)
	statuses := make(map[protocol.ResourceID]ProjectionStatus)
	receipts := make([]OperationReceipt, 0, len(plan.Operations))
	appliedIDs := make([]string, 0, len(plan.Operations))
	runFailed := false
	directFailure := make(map[protocol.ResourceID]bool)
	for _, operation := range plan.Operations {
		result, ok := resultByID[operation.OperationID]
		if !ok {
			return Projection{}, ReplayReport{}, fmt.Errorf("missing result for operation %s", operation.OperationID)
		}
		if operation.Kind == OperationStage {
			targets[operation.Resource.ResourceID] = operation.Resource
			statuses[operation.Resource.ResourceID] = PendingProjectionStatus()
		}
		if operation.Kind == OperationTombstone || operation.Kind == OperationRevoke {
			terminal := operation.Resource
			if result.Outcome == OperationFailed {
				terminal.ServingState = StateFailed
			}
			terminalResources[operation.Resource.ResourceID] = terminal
		}
		if result.Outcome == OperationFailed {
			runFailed = true
			directFailure[operation.Resource.ResourceID] = true
		}
		if status, ok := statuses[operation.Resource.ResourceID]; ok {
			status = applyComponentResult(status, operation.Kind, result.Outcome)
			statuses[operation.Resource.ResourceID] = status
		}
		receipts = append(receipts, OperationReceipt{
			OperationID: operation.OperationID, RunID: operation.RunID,
			ProjectionVersion: operation.ProjectionVersion,
			IdempotencyKey:    operation.IdempotencyKey, Outcome: result.Outcome,
			ErrorCode: result.ErrorCode,
		})
		appliedIDs = append(appliedIDs, operation.OperationID)
	}

	projectionState := StatePublished
	runState := RunSucceeded
	if runFailed {
		projectionState = StateFailed
		runState = RunFailed
	}
	resources := make([]ResourceMetadata, 0, len(targets)+len(terminalResources))
	for id, resource := range targets {
		resource.Versions.Projection = plan.Run.ProjectionVersion
		resource.ProjectionStatus = statuses[id]
		if runFailed {
			resource.ServingState = StateStaged
			if resource.ProjectionStatus.Failed() || directFailure[id] {
				resource.ServingState = StateFailed
			}
		} else {
			resource.ServingState = StatePublished
		}
		resources = append(resources, resource)
	}
	for _, resource := range terminalResources {
		resource.Versions.Projection = plan.Run.ProjectionVersion
		resources = append(resources, resource)
	}
	projection := Projection{
		Scope: plan.Run.Scope, Version: plan.Run.ProjectionVersion,
		SourceSnapshot: plan.Run.SourceSnapshot, State: projectionState,
		Resources:         resources,
		AppliedPlanIDs:    append(append([]string(nil), current.AppliedPlanIDs...), plan.PlanID),
		AppliedOperations: append(append([]OperationReceipt(nil), current.AppliedOperations...), receipts...),
	}
	projection.normalize()
	if err := projection.Validate(); err != nil {
		return Projection{}, ReplayReport{}, fmt.Errorf("replayed projection: %w", err)
	}
	sort.Strings(appliedIDs)
	return projection, ReplayReport{
		PlanID: plan.PlanID, RunID: plan.Run.RunID, RunState: runState,
		AppliedOperationIDs: appliedIDs,
	}, nil
}

type replayResourceOperations struct {
	byKind map[OperationKind]ProjectionOperation
	target *ResourceMetadata
}

func validateReplayPlan(plan ProjectionPlan, current Projection) error {
	currentByID := make(map[protocol.ResourceID]ResourceMetadata, len(current.Resources))
	for _, resource := range current.Resources {
		currentByID[resource.ResourceID] = resource
	}
	grouped := make(map[protocol.ResourceID]*replayResourceOperations)
	for _, operation := range plan.Operations {
		resourceID := operation.Resource.ResourceID
		group := grouped[resourceID]
		if group == nil {
			group = &replayResourceOperations{byKind: make(map[OperationKind]ProjectionOperation)}
			grouped[resourceID] = group
		}
		if _, duplicate := group.byKind[operation.Kind]; duplicate {
			return fmt.Errorf("projection plan repeats %s for resource %s", operation.Kind, resourceID)
		}
		group.byKind[operation.Kind] = operation
		if isTargetOperation(operation.Kind) {
			if group.target == nil {
				target := operation.Resource
				group.target = &target
			} else if !resourceMetadataEqual(*group.target, operation.Resource) {
				return fmt.Errorf("projection plan uses inconsistent target definitions for resource %s", resourceID)
			}
		}
	}

	targetKinds := []OperationKind{
		OperationStage, OperationProjectContent, OperationProjectACL, OperationProjectIndex,
		OperationProjectGraph, OperationProjectArtifact, OperationPublish,
	}
	for resourceID, group := range grouped {
		_, hasTombstone := group.byKind[OperationTombstone]
		_, hasRevoke := group.byKind[OperationRevoke]
		_, hasSupersede := group.byKind[OperationSupersede]
		if hasTombstone && hasRevoke {
			return fmt.Errorf("resource %s cannot be both tombstoned and revoked", resourceID)
		}
		previous, existed := currentByID[resourceID]
		if group.target == nil {
			if !hasTombstone && !hasRevoke {
				return fmt.Errorf("resource %s has no complete target or terminal operation", resourceID)
			}
			if !existed || previous.ServingState.IsTerminal() {
				return fmt.Errorf("terminal operation for resource %s does not match a live current resource", resourceID)
			}
			if hasSupersede {
				return fmt.Errorf("terminal resource %s cannot also be superseded", resourceID)
			}
			kind := OperationTombstone
			expectedState := StateTombstoned
			if hasRevoke {
				kind = OperationRevoke
				expectedState = StateRevoked
			}
			terminal := group.byKind[kind].Resource
			if terminal.ServingState != expectedState || !sameTerminalDefinition(previous, terminal) {
				return fmt.Errorf("terminal operation for resource %s does not match the current resource", resourceID)
			}
			continue
		}
		if hasTombstone || hasRevoke {
			return fmt.Errorf("target resource %s also has a terminal operation", resourceID)
		}
		for _, kind := range targetKinds {
			if _, ok := group.byKind[kind]; !ok {
				return fmt.Errorf("target resource %s is missing %s", resourceID, kind)
			}
		}
		changed := existed && !sameResourceDefinition(previous, *group.target)
		if changed != hasSupersede {
			return fmt.Errorf("resource %s has an invalid supersede transition", resourceID)
		}
		expectedSupersede := previous
		expectedSupersede.Versions.Source = plan.Run.SourceSnapshot.Version
		expectedSupersede.Versions.Projection = plan.Run.ProjectionVersion
		expectedSupersede.ServingState = StateSuperseded
		expectedSupersede.ClaimRecord = nil
		expectedSupersede.DerivedArtifactSecurity = nil
		if hasSupersede && !resourceMetadataEqual(group.byKind[OperationSupersede].Resource, expectedSupersede) {
			return fmt.Errorf("supersede operation for resource %s does not match the current resource", resourceID)
		}
	}
	for resourceID, resource := range currentByID {
		if resource.ServingState.IsTerminal() {
			continue
		}
		if _, ok := grouped[resourceID]; !ok {
			return fmt.Errorf("projection plan does not reconcile current resource %s", resourceID)
		}
	}
	return nil
}

func sameTerminalDefinition(previous, terminal ResourceMetadata) bool {
	previous.Versions.Source = terminal.Versions.Source
	previous.ClaimRecord = nil
	return sameResourceDefinition(previous, terminal)
}

func isTargetOperation(kind OperationKind) bool {
	switch kind {
	case OperationStage, OperationProjectContent, OperationProjectACL, OperationProjectIndex,
		OperationProjectGraph, OperationProjectArtifact, OperationPublish:
		return true
	default:
		return false
	}
}

func SuccessfulResults(plan ProjectionPlan) []OperationResult {
	results := make([]OperationResult, len(plan.Operations))
	for i, operation := range plan.Operations {
		results[i] = OperationResult{OperationID: operation.OperationID, Outcome: OperationSucceeded}
	}
	return results
}

func applyComponentResult(
	status ProjectionStatus,
	kind OperationKind,
	outcome OperationOutcome,
) ProjectionStatus {
	state := ComponentSucceeded
	if outcome == OperationFailed {
		state = ComponentFailed
	}
	switch kind {
	case OperationProjectContent:
		status.Content = state
	case OperationProjectACL:
		status.ACL = state
	case OperationProjectIndex:
		status.Index = state
	case OperationProjectGraph:
		status.Graph = state
	case OperationProjectArtifact:
		status.Artifacts = state
	}
	return status
}

func containsSorted(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func runStateForAppliedPlan(projection Projection, plan ProjectionPlan) (RunState, error) {
	runState := RunSucceeded
	for _, operation := range plan.Operations {
		index := sort.Search(len(projection.AppliedOperations), func(i int) bool {
			return projection.AppliedOperations[i].OperationID >= operation.OperationID
		})
		if index == len(projection.AppliedOperations) || projection.AppliedOperations[index].OperationID != operation.OperationID {
			return "", fmt.Errorf("applied plan %s is missing receipt for operation %s", plan.PlanID, operation.OperationID)
		}
		receipt := projection.AppliedOperations[index]
		if receipt.RunID != operation.RunID ||
			receipt.ProjectionVersion != operation.ProjectionVersion ||
			receipt.IdempotencyKey != operation.IdempotencyKey {
			return "", fmt.Errorf("applied plan %s has a mismatched receipt for operation %s", plan.PlanID, operation.OperationID)
		}
		if receipt.Outcome == OperationFailed {
			runState = RunFailed
		}
	}
	return runState, nil
}

func cloneProjection(projection Projection) Projection {
	clone := projection
	clone.Resources = append([]ResourceMetadata(nil), projection.Resources...)
	for i := range clone.Resources {
		clone.Resources[i].Dependencies = append([]protocol.ResourceID(nil), projection.Resources[i].Dependencies...)
	}
	clone.AppliedPlanIDs = append([]string(nil), projection.AppliedPlanIDs...)
	clone.AppliedOperations = append([]OperationReceipt(nil), projection.AppliedOperations...)
	return clone
}
