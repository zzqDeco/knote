package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

var (
	ErrIncompleteReceipts  = errors.New("projection operation receipts are incomplete")
	ErrJournalConflict     = errors.New("projection journal record conflicts with persisted state")
	ErrStaleServingPointer = errors.New("serving projection changed from the planned base")
)

// OperationExecutor performs one projection side effect. Implementations must
// honor ProjectionOperation.IdempotencyKey because a process can exit after a
// side effect succeeds but before its receipt reaches durable storage.
type OperationExecutor interface {
	Execute(context.Context, ProjectionOperation) (OperationResult, error)
}

type OperationExecutorFunc func(context.Context, ProjectionOperation) (OperationResult, error)

func (f OperationExecutorFunc) Execute(ctx context.Context, operation ProjectionOperation) (OperationResult, error) {
	return f(ctx, operation)
}

type ServingPointer struct {
	Scope                 Scope  `json:"scope"`
	ProjectionVersion     string `json:"projection_version"`
	SourceSnapshotVersion string `json:"source_snapshot_version"`
	RunID                 string `json:"run_id,omitempty"`
	PlanID                string `json:"plan_id,omitempty"`
}

func (p ServingPointer) Validate() error {
	if err := p.Scope.Validate(); err != nil {
		return err
	}
	if err := validateJournalToken("projection_version", p.ProjectionVersion); err != nil {
		return err
	}
	if err := validateToken("source_snapshot_version", p.SourceSnapshotVersion); err != nil {
		return err
	}
	if (p.RunID == "") != (p.PlanID == "") {
		return fmt.Errorf("serving pointer run and plan bindings must both be present or absent")
	}
	if p.RunID != "" {
		if err := validateJournalToken("run_id", p.RunID); err != nil {
			return err
		}
		if err := validateJournalToken("plan_id", p.PlanID); err != nil {
			return err
		}
	}
	return nil
}

type ProjectionExecution struct {
	Projection           Projection
	Report               ReplayReport
	Pointer              ServingPointer
	ExecutedOperationIDs []string
	PointerAdvanced      bool
	IdempotentNoop       bool
}

// ProjectionStore is a local durable control plane rooted at
// .knote/projections (or an equivalent caller-owned absolute path).
type ProjectionStore struct {
	root                    string
	syncDirectory           func(string) error
	afterCandidatePersisted func(ProjectionPlan) error
	afterPointerAdvanced    func(ServingPointer) error
}

func NewProjectionStore(root string) (*ProjectionStore, error) {
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("projection store root must be an absolute path")
	}
	root = filepath.Clean(root)
	if root == filepath.VolumeName(root)+string(filepath.Separator) {
		return nil, fmt.Errorf("projection store root cannot be a filesystem root")
	}
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("projection store root must be a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect projection store root: %w", err)
	} else if err := createDirectoriesDurably(root, syncDirectory); err != nil {
		return nil, fmt.Errorf("create projection store root: %w", err)
	}
	if err := secureProjectionDirectory(root); err != nil {
		return nil, fmt.Errorf("secure projection store root: %w", err)
	}
	store := &ProjectionStore{root: root, syncDirectory: syncDirectory}
	for _, path := range []string{store.runsDir(), store.projectionsDir()} {
		if err := store.ensureDir(path); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *ProjectionStore) Root() string { return s.root }

func (s *ProjectionStore) InitializeServing(projection Projection) error {
	if err := projection.Validate(); err != nil {
		return err
	}
	if projection.State != StatePublished {
		return fmt.Errorf("initial serving projection must be published")
	}
	if err := validateJournalToken("projection_version", projection.Version); err != nil {
		return err
	}
	return s.withLock(func() error {
		pointer, err := s.readServingPointerLocked()
		if err == nil {
			if pointer.Scope != projection.Scope || pointer.ProjectionVersion != projection.Version {
				return ErrJournalConflict
			}
			persisted, readErr := s.readProjectionFile(s.projectionPath(projection.Version))
			if readErr != nil {
				return readErr
			}
			equal, compareErr := projectionsEqual(persisted, projection)
			if compareErr != nil {
				return compareErr
			}
			if !equal {
				return ErrJournalConflict
			}
			if err := s.syncDirectory(filepath.Dir(s.pointerPath())); err != nil {
				return fmt.Errorf("sync serving pointer directory: %w", err)
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		pointer = ServingPointer{
			Scope: projection.Scope, ProjectionVersion: projection.Version,
			SourceSnapshotVersion: projection.SourceSnapshot.Version,
		}
		if err := pointer.Validate(); err != nil {
			return err
		}
		if err := s.writeJSONOnce(s.projectionPath(projection.Version), projection); err != nil {
			return err
		}
		return s.writeJSON(s.pointerPath(), pointer)
	})
}

func (s *ProjectionStore) ServingPointer() (ServingPointer, error) {
	var pointer ServingPointer
	err := s.withLock(func() error {
		var err error
		pointer, err = s.readServingPointerLocked()
		return err
	})
	return pointer, err
}

func (s *ProjectionStore) Stage(plan ProjectionPlan) error {
	return s.withLock(func() error { return s.stageLocked(plan) })
}

func (s *ProjectionStore) RecordResult(plan ProjectionPlan, result OperationResult) error {
	return s.withLock(func() error {
		if err := s.stageLocked(plan); err != nil {
			return err
		}
		return s.recordResultLocked(plan, result)
	})
}

func (s *ProjectionStore) Finalize(plan ProjectionPlan, current Projection) (ProjectionExecution, error) {
	var execution ProjectionExecution
	err := s.withLock(func() error {
		var err error
		execution, err = s.finalizeLocked(plan, current)
		return err
	})
	return execution, err
}

func (s *ProjectionStore) Execute(
	ctx context.Context,
	plan ProjectionPlan,
	current Projection,
	executor OperationExecutor,
) (ProjectionExecution, error) {
	if executor == nil {
		return ProjectionExecution{}, fmt.Errorf("projection operation executor is required")
	}
	var execution ProjectionExecution
	err := s.withLock(func() error {
		if err := s.stageLocked(plan); err != nil {
			return err
		}
		if err := current.Validate(); err != nil {
			return err
		}
		if current.Scope != plan.Run.Scope || current.Version != plan.Run.BaseProjectionVersion {
			return fmt.Errorf("projection plan does not match the supplied base projection")
		}
		journalRun, err := s.readRunLocked(plan.Run.RunID)
		if err != nil {
			return err
		}
		if journalRun.State == RunSucceeded || journalRun.State == RunFailed {
			execution, err = s.persistedExecutionLocked(plan, journalRun.State)
			return err
		}
		pointer, err := s.readServingPointerLocked()
		if err != nil {
			return err
		}
		if err := s.reconcilePointerOwnerLocked(pointer); err != nil {
			return err
		}
		journalRun, err = s.readRunLocked(plan.Run.RunID)
		if err != nil {
			return err
		}
		if journalRun.State == RunSucceeded || journalRun.State == RunFailed {
			execution, err = s.persistedExecutionLocked(plan, journalRun.State)
			return err
		}
		if !pointerMatchesBase(pointer, plan, current) {
			if pointer.ProjectionVersion == plan.Run.ProjectionVersion &&
				pointer.RunID == plan.Run.RunID && pointer.PlanID == plan.PlanID {
				execution, err = s.finalizeLocked(plan, current)
				return err
			}
			execution, err = s.persistStaleFailureLocked(plan, current, pointer)
			if err != nil {
				return err
			}
			return ErrStaleServingPointer
		}
		if err := s.verifyBaseProjectionLocked(current, plan); err != nil {
			return err
		}
		if err := validateReplayPlan(plan, current); err != nil {
			return fmt.Errorf("preflight projection plan: %w", err)
		}
		journalRun.State = RunRunning
		if err := s.writeJSON(s.runPath(plan.Run.RunID), journalRun); err != nil {
			return err
		}

		persistedResults := make(map[string]OperationResult, len(plan.Operations))
		operationFailed := false
		for _, operation := range plan.Operations {
			persisted, readErr := s.readResultLocked(plan.Run.RunID, operation.OperationID)
			if readErr == nil {
				persistedResults[operation.OperationID] = persisted
				operationFailed = operationFailed || persisted.Outcome == OperationFailed
				continue
			}
			if !errors.Is(readErr, os.ErrNotExist) {
				return readErr
			}
		}
		for _, operation := range plan.Operations {
			if _, persisted := persistedResults[operation.OperationID]; persisted {
				continue
			}
			result := OperationResult{
				OperationID: operation.OperationID, Outcome: OperationFailed,
				ErrorCode: "operation_execution_failed",
			}
			executorInvoked := false
			if operationFailed {
				result.ErrorCode = "operation_blocked"
			} else if ctx.Err() == nil {
				executorInvoked = true
				candidate, executeErr := executor.Execute(ctx, operation)
				if executeErr == nil && candidate.OperationID == operation.OperationID && candidate.Validate() == nil {
					result = candidate
				} else if executeErr == nil {
					result.ErrorCode = "invalid_operation_result"
				}
			} else {
				result.ErrorCode = "operation_context_cancelled"
			}
			if err := s.recordResultLocked(plan, result); err != nil {
				return err
			}
			if executorInvoked {
				execution.ExecutedOperationIDs = append(execution.ExecutedOperationIDs, operation.OperationID)
			}
			operationFailed = operationFailed || result.Outcome == OperationFailed
		}
		sort.Strings(execution.ExecutedOperationIDs)
		finalized, err := s.finalizeLocked(plan, current)
		finalized.ExecutedOperationIDs = execution.ExecutedOperationIDs
		execution = finalized
		return err
	})
	return execution, err
}

func (s *ProjectionStore) stageLocked(plan ProjectionPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := validateJournalToken("run_id", plan.Run.RunID); err != nil {
		return err
	}
	if err := validateJournalToken("plan_id", plan.PlanID); err != nil {
		return err
	}
	if err := validateJournalToken("base_projection_version", plan.Run.BaseProjectionVersion); err != nil {
		return err
	}
	if err := validateJournalToken("projection_version", plan.Run.ProjectionVersion); err != nil {
		return err
	}
	if err := validateToken("source_snapshot_version", plan.Run.SourceSnapshot.Version); err != nil {
		return err
	}
	for _, operation := range plan.Operations {
		if err := validateJournalToken("operation_id", operation.OperationID); err != nil {
			return err
		}
	}
	if err := s.ensureDir(s.runDir(plan.Run.RunID)); err != nil {
		return err
	}
	if err := s.ensureDir(s.resultsDir(plan.Run.RunID)); err != nil {
		return err
	}
	if err := s.writeJSONOnce(s.planPath(plan.Run.RunID), plan); err != nil {
		return err
	}
	if persisted, err := s.readRunLocked(plan.Run.RunID); err == nil {
		if !sameRunIdentity(persisted, plan.Run) {
			return ErrJournalConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.writeJSONOnce(s.runPath(plan.Run.RunID), plan.Run)
}

func (s *ProjectionStore) recordResultLocked(plan ProjectionPlan, result OperationResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	result = canonicalJournalResult(result)
	matched := false
	for _, operation := range plan.Operations {
		if operation.OperationID == result.OperationID {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("result operation %s is not in plan %s", result.OperationID, plan.PlanID)
	}
	if err := validateJournalToken("operation_id", result.OperationID); err != nil {
		return err
	}
	return s.writeJSONOnce(s.resultPath(plan.Run.RunID, result.OperationID), result)
}

func canonicalJournalResult(result OperationResult) OperationResult {
	if result.Outcome != OperationFailed {
		return result
	}
	switch result.ErrorCode {
	case "invalid_operation_result", "operation_blocked", "operation_context_cancelled", "operation_execution_failed",
		"stale_base_projection":
		return result
	default:
		result.ErrorCode = "operation_failed"
		return result
	}
}

func (s *ProjectionStore) finalizeLocked(plan ProjectionPlan, current Projection) (ProjectionExecution, error) {
	if err := s.stageLocked(plan); err != nil {
		return ProjectionExecution{}, err
	}
	if err := current.Validate(); err != nil {
		return ProjectionExecution{}, err
	}
	if current.Scope != plan.Run.Scope || current.Version != plan.Run.BaseProjectionVersion {
		return ProjectionExecution{}, fmt.Errorf("projection plan does not match the supplied base projection")
	}
	journalRun, err := s.readRunLocked(plan.Run.RunID)
	if err != nil {
		return ProjectionExecution{}, err
	}
	if journalRun.State == RunSucceeded || journalRun.State == RunFailed {
		return s.persistedExecutionLocked(plan, journalRun.State)
	}
	pointer, err := s.readServingPointerLocked()
	if err != nil {
		return ProjectionExecution{}, err
	}
	if err := s.reconcilePointerOwnerLocked(pointer); err != nil {
		return ProjectionExecution{}, err
	}
	journalRun, err = s.readRunLocked(plan.Run.RunID)
	if err != nil {
		return ProjectionExecution{}, err
	}
	if journalRun.State == RunSucceeded || journalRun.State == RunFailed {
		return s.persistedExecutionLocked(plan, journalRun.State)
	}
	if !pointerMatchesBase(pointer, plan, current) {
		if pointer.ProjectionVersion == plan.Run.ProjectionVersion &&
			pointer.RunID == plan.Run.RunID && pointer.PlanID == plan.PlanID {
			results, resultsErr := s.completeResultsLocked(plan)
			if resultsErr != nil {
				return ProjectionExecution{}, resultsErr
			}
			projection, report, replayErr := Replay(plan, current, results)
			if replayErr != nil {
				return ProjectionExecution{}, replayErr
			}
			if projection.State != StatePublished || report.RunState != RunSucceeded {
				return ProjectionExecution{}, ErrJournalConflict
			}
			if err := s.persistProjectionLocked(plan, projection); err != nil {
				return ProjectionExecution{}, err
			}
			journalRun.State = RunSucceeded
			if err := s.writeJSON(s.runPath(plan.Run.RunID), journalRun); err != nil {
				return ProjectionExecution{}, err
			}
			return ProjectionExecution{
				Projection: projection, Report: report, Pointer: pointer,
				IdempotentNoop: true,
			}, nil
		}
		execution, persistErr := s.persistStaleFailureLocked(plan, current, pointer)
		if persistErr != nil {
			return ProjectionExecution{}, persistErr
		}
		return execution, ErrStaleServingPointer
	}
	if err := s.verifyBaseProjectionLocked(current, plan); err != nil {
		return ProjectionExecution{}, err
	}
	results, err := s.completeResultsLocked(plan)
	if err != nil {
		return ProjectionExecution{}, err
	}
	projection, report, err := Replay(plan, current, results)
	if err != nil {
		return ProjectionExecution{}, err
	}
	journalRun.State = report.RunState
	if report.RunState == RunFailed {
		if err := s.persistProjectionLocked(plan, projection); err != nil {
			return ProjectionExecution{}, err
		}
		if err := s.writeJSON(s.runPath(plan.Run.RunID), journalRun); err != nil {
			return ProjectionExecution{}, err
		}
		return ProjectionExecution{Projection: projection, Report: report, Pointer: pointer}, nil
	}
	if projection.State != StatePublished {
		return ProjectionExecution{}, fmt.Errorf("successful replay did not produce a published projection")
	}
	if err := s.writeJSONOnce(s.projectionPath(projection.Version), projection); err != nil {
		return ProjectionExecution{}, err
	}
	if s.afterCandidatePersisted != nil {
		if err := s.afterCandidatePersisted(plan); err != nil {
			return ProjectionExecution{}, err
		}
	}
	next := ServingPointer{
		Scope: projection.Scope, ProjectionVersion: projection.Version,
		SourceSnapshotVersion: projection.SourceSnapshot.Version,
		RunID:                 plan.Run.RunID, PlanID: plan.PlanID,
	}
	if err := next.Validate(); err != nil {
		return ProjectionExecution{}, err
	}
	if err := s.writeJSON(s.pointerPath(), next); err != nil {
		return ProjectionExecution{}, err
	}
	if s.afterPointerAdvanced != nil {
		if err := s.afterPointerAdvanced(next); err != nil {
			return ProjectionExecution{}, err
		}
	}
	if err := s.persistProjectionLocked(plan, projection); err != nil {
		return ProjectionExecution{}, err
	}
	if err := s.writeJSON(s.runPath(plan.Run.RunID), journalRun); err != nil {
		return ProjectionExecution{}, err
	}
	return ProjectionExecution{
		Projection: projection, Report: report, Pointer: next, PointerAdvanced: true,
	}, nil
}

// reconcilePointerOwnerLocked closes the only success ambiguity in the journal:
// the serving pointer moved, but the owning run did not reach its terminal
// record before the process exited. A successor must reconcile this owner before
// it is allowed to replace the pointer.
func (s *ProjectionStore) reconcilePointerOwnerLocked(pointer ServingPointer) error {
	if pointer.RunID == "" {
		return nil
	}
	if err := s.syncDirectory(filepath.Dir(s.pointerPath())); err != nil {
		return fmt.Errorf("sync serving pointer directory: %w", err)
	}
	plan, err := s.readPlanLocked(pointer.RunID)
	if err != nil {
		return fmt.Errorf("read serving pointer owner plan: %w", err)
	}
	if plan.PlanID != pointer.PlanID || plan.Run.RunID != pointer.RunID ||
		plan.Run.ProjectionVersion != pointer.ProjectionVersion || plan.Run.Scope != pointer.Scope {
		return ErrJournalConflict
	}
	run, err := s.readRunLocked(pointer.RunID)
	if err != nil {
		return fmt.Errorf("read serving pointer owner run: %w", err)
	}
	if !sameRunIdentity(run, plan.Run) {
		return ErrJournalConflict
	}
	if run.State == RunFailed {
		return fmt.Errorf("failed run %s owns the serving pointer: %w", run.RunID, ErrJournalConflict)
	}
	if run.State == RunSucceeded {
		if err := s.syncDirectory(s.runDir(run.RunID)); err != nil {
			return fmt.Errorf("sync serving pointer owner run directory: %w", err)
		}
		persisted, readErr := s.readProjectionFile(s.runProjectionPath(run.RunID))
		if readErr != nil {
			return readErr
		}
		serving, readErr := s.readProjectionFile(s.projectionPath(pointer.ProjectionVersion))
		if readErr != nil {
			return readErr
		}
		equal, compareErr := projectionsEqual(persisted, serving)
		if compareErr != nil {
			return compareErr
		}
		if !equal {
			return ErrJournalConflict
		}
		return nil
	}
	results, err := s.completeResultsLocked(plan)
	if err != nil {
		return fmt.Errorf("serving pointer owner has incomplete receipts: %w", ErrJournalConflict)
	}
	for _, result := range results {
		if result.Outcome != OperationSucceeded {
			return fmt.Errorf("serving pointer owner has failed receipts: %w", ErrJournalConflict)
		}
	}
	base, err := s.readProjectionFile(s.projectionPath(plan.Run.BaseProjectionVersion))
	if err != nil {
		return fmt.Errorf("read serving pointer owner base: %w", err)
	}
	projection, report, err := Replay(plan, base, results)
	if err != nil {
		return fmt.Errorf("replay serving pointer owner: %w", err)
	}
	if projection.State != StatePublished || report.RunState != RunSucceeded ||
		projection.SourceSnapshot.Version != pointer.SourceSnapshotVersion {
		return ErrJournalConflict
	}
	serving, err := s.readProjectionFile(s.projectionPath(pointer.ProjectionVersion))
	if err != nil {
		return err
	}
	equal, compareErr := projectionsEqual(projection, serving)
	if compareErr != nil {
		return compareErr
	}
	if !equal {
		return ErrJournalConflict
	}
	if err := s.persistProjectionLocked(plan, projection); err != nil {
		return err
	}
	run.State = RunSucceeded
	return s.writeJSON(s.runPath(run.RunID), run)
}

func (s *ProjectionStore) persistStaleFailureLocked(
	plan ProjectionPlan,
	current Projection,
	pointer ServingPointer,
) (ProjectionExecution, error) {
	for _, operation := range plan.Operations {
		if _, err := s.readResultLocked(plan.Run.RunID, operation.OperationID); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return ProjectionExecution{}, err
		}
		result := OperationResult{
			OperationID: operation.OperationID, Outcome: OperationFailed,
			ErrorCode: "stale_base_projection",
		}
		if err := s.recordResultLocked(plan, result); err != nil {
			return ProjectionExecution{}, err
		}
	}
	results, err := s.completeResultsLocked(plan)
	if err != nil {
		return ProjectionExecution{}, err
	}
	projection, report, err := Replay(plan, current, results)
	if err != nil {
		return ProjectionExecution{}, err
	}
	if report.RunState == RunSucceeded {
		projection.State = StateFailed
		for index := range projection.Resources {
			if projection.Resources[index].IsServing() {
				projection.Resources[index].ServingState = StateStaged
			}
		}
		if err := projection.Validate(); err != nil {
			return ProjectionExecution{}, fmt.Errorf("stale non-serving projection: %w", err)
		}
		report.RunState = RunFailed
	}
	if projection.State != StateFailed || report.RunState != RunFailed {
		return ProjectionExecution{}, ErrJournalConflict
	}
	if err := s.persistProjectionLocked(plan, projection); err != nil {
		return ProjectionExecution{}, err
	}
	journalRun := plan.Run
	journalRun.State = RunFailed
	if err := s.writeJSON(s.runPath(plan.Run.RunID), journalRun); err != nil {
		return ProjectionExecution{}, err
	}
	return ProjectionExecution{Projection: projection, Report: report, Pointer: pointer}, nil
}

func (s *ProjectionStore) completeResultsLocked(plan ProjectionPlan) ([]OperationResult, error) {
	results := make([]OperationResult, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		result, err := s.readResultLocked(plan.Run.RunID, operation.OperationID)
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrIncompleteReceipts
		}
		if err != nil {
			return nil, err
		}
		if result.OperationID != operation.OperationID {
			return nil, ErrJournalConflict
		}
		results = append(results, result)
	}
	if err := s.syncDirectory(s.resultsDir(plan.Run.RunID)); err != nil {
		return nil, fmt.Errorf("sync projection result receipts: %w", err)
	}
	return results, nil
}

func (s *ProjectionStore) persistedExecutionLocked(plan ProjectionPlan, state RunState) (ProjectionExecution, error) {
	projection, err := s.readProjectionFile(s.runProjectionPath(plan.Run.RunID))
	if err != nil {
		return ProjectionExecution{}, err
	}
	pointer, err := s.readServingPointerLocked()
	if err != nil {
		return ProjectionExecution{}, err
	}
	return ProjectionExecution{
		Projection: projection,
		Report:     ReplayReport{PlanID: plan.PlanID, RunID: plan.Run.RunID, RunState: state, IdempotentNoop: true},
		Pointer:    pointer, IdempotentNoop: true,
	}, nil
}

func (s *ProjectionStore) persistProjectionLocked(plan ProjectionPlan, projection Projection) error {
	if projection.Version != plan.Run.ProjectionVersion || projection.Scope != plan.Run.Scope {
		return ErrJournalConflict
	}
	return s.writeJSONOnce(s.runProjectionPath(plan.Run.RunID), projection)
}

func (s *ProjectionStore) verifyBaseProjectionLocked(current Projection, plan ProjectionPlan) error {
	if current.Version != plan.Run.BaseProjectionVersion || current.Scope != plan.Run.Scope {
		return ErrJournalConflict
	}
	persisted, err := s.readProjectionFile(s.projectionPath(current.Version))
	if err != nil {
		return err
	}
	equal, compareErr := projectionsEqual(persisted, current)
	if compareErr != nil {
		return compareErr
	}
	if !equal {
		return ErrJournalConflict
	}
	return nil
}

func projectionsEqual(left, right Projection) (bool, error) {
	leftJSON, err := deterministicJSON(left)
	if err != nil {
		return false, err
	}
	rightJSON, err := deterministicJSON(right)
	if err != nil {
		return false, err
	}
	return string(leftJSON) == string(rightJSON), nil
}

func (s *ProjectionStore) readServingPointerLocked() (ServingPointer, error) {
	var pointer ServingPointer
	if err := s.readJSON(s.pointerPath(), &pointer); err != nil {
		return ServingPointer{}, err
	}
	if err := pointer.Validate(); err != nil {
		return ServingPointer{}, fmt.Errorf("serving pointer: %w", err)
	}
	return pointer, nil
}

func (s *ProjectionStore) readPlanLocked(runID string) (ProjectionPlan, error) {
	var plan ProjectionPlan
	if err := s.readJSON(s.planPath(runID), &plan); err != nil {
		return ProjectionPlan{}, err
	}
	if err := plan.Validate(); err != nil {
		return ProjectionPlan{}, fmt.Errorf("persisted projection plan: %w", err)
	}
	return plan, nil
}

func (s *ProjectionStore) readRunLocked(runID string) (SyncRun, error) {
	var run SyncRun
	if err := s.readJSON(s.runPath(runID), &run); err != nil {
		return SyncRun{}, err
	}
	if err := run.Validate(); err != nil {
		return SyncRun{}, fmt.Errorf("persisted sync run: %w", err)
	}
	return run, nil
}

func (s *ProjectionStore) readResultLocked(runID, operationID string) (OperationResult, error) {
	var result OperationResult
	if err := s.readJSON(s.resultPath(runID, operationID), &result); err != nil {
		return OperationResult{}, err
	}
	if err := result.Validate(); err != nil {
		return OperationResult{}, fmt.Errorf("persisted operation result: %w", err)
	}
	return result, nil
}

func (s *ProjectionStore) readProjectionFile(path string) (Projection, error) {
	var projection Projection
	if err := s.readJSON(path, &projection); err != nil {
		return Projection{}, err
	}
	if err := projection.Validate(); err != nil {
		return Projection{}, fmt.Errorf("persisted projection: %w", err)
	}
	return projection, nil
}

func sameRunIdentity(left, right SyncRun) bool {
	left.State, right.State = RunStaged, RunStaged
	return reflect.DeepEqual(left, right)
}

func pointerMatchesBase(pointer ServingPointer, plan ProjectionPlan, current Projection) bool {
	return pointer.Scope == plan.Run.Scope &&
		pointer.ProjectionVersion == plan.Run.BaseProjectionVersion &&
		pointer.SourceSnapshotVersion == current.SourceSnapshot.Version
}

func validateJournalToken(name, value string) error {
	if err := validateToken(name, value); err != nil {
		return err
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `<>:"/\\|?*`) {
		return fmt.Errorf("%s is not safe for journal paths", name)
	}
	if strings.HasSuffix(value, ".") || strings.HasSuffix(value, " ") {
		return fmt.Errorf("%s has a non-portable trailing character", name)
	}
	base := value
	if extension := strings.IndexByte(base, '.'); extension >= 0 {
		base = base[:extension]
	}
	upperBase := strings.ToUpper(base)
	reserved := upperBase == "CON" || upperBase == "PRN" || upperBase == "AUX" ||
		upperBase == "NUL" || upperBase == "CLOCK$"
	if len(upperBase) == 4 && (strings.HasPrefix(upperBase, "COM") || strings.HasPrefix(upperBase, "LPT")) &&
		upperBase[3] >= '1' && upperBase[3] <= '9' {
		reserved = true
	}
	if reserved {
		return fmt.Errorf("%s uses a reserved DOS device basename", name)
	}
	if len(value) > 200 {
		return fmt.Errorf("%s is too long for journal paths", name)
	}
	return nil
}

func (s *ProjectionStore) withLock(fn func() error) (err error) {
	lockPath := filepath.Join(s.root, ".lock")
	if info, err := os.Lstat(lockPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("projection store lock is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock, err := acquireProjectionFileLock(lockPath)
	if err != nil {
		return fmt.Errorf("open projection store lock: %w", err)
	}
	defer func() {
		err = errors.Join(err, lock.Close())
	}()
	return fn()
}

func (s *ProjectionStore) ensureDir(path string) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	if err := createDirectoriesDurably(path, s.syncDirectory); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("projection journal directory is not a real directory: %s", path)
	}
	return secureProjectionDirectory(path)
}

func createDirectoriesDurably(path string, syncDir func(string) error) error {
	path = filepath.Clean(path)
	missing := make([]string, 0, 2)
	current := path
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("projection journal directory is not a real directory: %s", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for projection journal directory %s", path)
		}
		current = parent
	}
	if parent := filepath.Dir(current); parent != current {
		if err := syncDir(parent); err != nil {
			return fmt.Errorf("sync parent of projection journal directory: %w", err)
		}
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := createProjectionDirectory(directory); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("projection journal directory is not a real directory: %s", directory)
		}
		if err := secureProjectionDirectory(directory); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(directory)); err != nil {
			return fmt.Errorf("sync parent of projection journal directory: %w", err)
		}
	}
	return nil
}

func (s *ProjectionStore) writeJSONOnce(path string, value any) error {
	data, err := deterministicJSON(value)
	if err != nil {
		return err
	}
	if existing, err := s.readFile(path); err == nil {
		if string(existing) == string(data) {
			return s.syncDirectory(filepath.Dir(path))
		}
		return ErrJournalConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.atomicWrite(path, data)
}

func (s *ProjectionStore) writeJSON(path string, value any) error {
	data, err := deterministicJSON(value)
	if err != nil {
		return err
	}
	return s.atomicWrite(path, data)
}

func deterministicJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (s *ProjectionStore) atomicWrite(path string, data []byte) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	if err := s.ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("projection journal target is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".projection-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := secureProjectionFile(temp); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return s.syncDirectory(filepath.Dir(path))
}

func (s *ProjectionStore) readJSON(path string, destination any) error {
	data, err := s.readFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode projection journal record: %w", err)
	}
	return nil
}

func (s *ProjectionStore) readFile(path string) ([]byte, error) {
	if err := s.requireWithinRoot(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("projection journal record is not a regular file")
	}
	return os.ReadFile(path)
}

func (s *ProjectionStore) requireWithinRoot(path string) error {
	relative, err := filepath.Rel(s.root, filepath.Clean(path))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("projection journal path escapes its root")
	}
	return nil
}

func (s *ProjectionStore) runsDir() string        { return filepath.Join(s.root, "runs") }
func (s *ProjectionStore) projectionsDir() string { return filepath.Join(s.root, "projections") }
func (s *ProjectionStore) pointerPath() string    { return filepath.Join(s.root, "serving.json") }
func (s *ProjectionStore) runDir(runID string) string {
	return filepath.Join(s.runsDir(), runID)
}
func (s *ProjectionStore) resultsDir(runID string) string {
	return filepath.Join(s.runDir(runID), "results")
}
func (s *ProjectionStore) runPath(runID string) string {
	return filepath.Join(s.runDir(runID), "run.json")
}
func (s *ProjectionStore) planPath(runID string) string {
	return filepath.Join(s.runDir(runID), "plan.json")
}
func (s *ProjectionStore) resultPath(runID, operationID string) string {
	return filepath.Join(s.resultsDir(runID), operationID+".json")
}
func (s *ProjectionStore) runProjectionPath(runID string) string {
	return filepath.Join(s.runDir(runID), "projection.json")
}
func (s *ProjectionStore) projectionPath(version string) string {
	return filepath.Join(s.projectionsDir(), version+".json")
}
