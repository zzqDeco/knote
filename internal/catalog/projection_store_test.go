package catalog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestProjectionStoreReceiptBarrierAndCrashRecovery(t *testing.T) {
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	results := SuccessfulResults(plan)
	for _, result := range results[:len(results)-1] {
		if err := store.RecordResult(plan, result); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Finalize(plan, current); !errors.Is(err, ErrIncompleteReceipts) {
		t.Fatalf("Finalize error = %v, want ErrIncompleteReceipts", err)
	}
	assertServingVersion(t, store, current.Version)

	reopened, err := NewProjectionStore(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordResult(plan, results[len(results)-1]); err != nil {
		t.Fatal(err)
	}
	first, err := reopened.Finalize(plan, current)
	if err != nil {
		t.Fatal(err)
	}
	if first.Projection.State != StatePublished || first.Report.RunState != RunSucceeded {
		t.Fatalf("successful finalize = %+v", first)
	}
	assertServingVersion(t, reopened, plan.Run.ProjectionVersion)

	second, err := reopened.Finalize(plan, current)
	if err != nil {
		t.Fatal(err)
	}
	if !second.IdempotentNoop || !reflect.DeepEqual(first.Projection, second.Projection) {
		t.Fatalf("duplicate finalize changed the outcome: first=%+v second=%+v", first, second)
	}
}

func TestProjectionStoreExecuteSkipsPersistedSuccessfulOperations(t *testing.T) {
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	first := SuccessfulResults(plan)[0]
	if err := store.RecordResult(plan, first); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewProjectionStore(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	executor := OperationExecutorFunc(func(_ context.Context, operation ProjectionOperation) (OperationResult, error) {
		calls.Add(1)
		return OperationResult{OperationID: operation.OperationID, Outcome: OperationSucceeded}, nil
	})
	firstExecution, err := reopened.Execute(context.Background(), plan, current, executor)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := calls.Load(), int64(len(plan.Operations)-1); got != want {
		t.Fatalf("executor calls = %d, want %d", got, want)
	}
	secondExecution, err := reopened.Execute(context.Background(), plan, current, executor)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := calls.Load(), int64(len(plan.Operations)-1); got != want {
		t.Fatalf("duplicate execute reran side effects: calls = %d, want %d", got, want)
	}
	if !secondExecution.IdempotentNoop || !reflect.DeepEqual(firstExecution.Projection, secondExecution.Projection) {
		t.Fatal("duplicate execute did not return the persisted outcome")
	}
}

func TestProjectionStoreFailedOperationNeverAdvancesServingPointer(t *testing.T) {
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	var calls atomic.Int64
	executor := OperationExecutorFunc(func(_ context.Context, operation ProjectionOperation) (OperationResult, error) {
		calls.Add(1)
		if operation.Kind == OperationProjectACL {
			return OperationResult{}, errors.New("secret upstream ACL response")
		}
		return OperationResult{OperationID: operation.OperationID, Outcome: OperationSucceeded}, nil
	})
	execution, err := store.Execute(context.Background(), plan, current, executor)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Projection.State != StateFailed || execution.Report.RunState != RunFailed {
		t.Fatalf("failed execution was not persisted as non-serving: %+v", execution)
	}
	if got, want := calls.Load(), int64(3); got != want {
		t.Fatalf("executor calls after ACL failure = %d, want %d", got, want)
	}
	assertServingVersion(t, store, current.Version)

	err = filepath.Walk(store.Root(), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), "secret upstream") {
			t.Fatalf("journal leaked executor error detail in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProjectionStorePersistedLaterFailureBlocksAllMissingOperations(t *testing.T) {
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	failed := plan.Operations[len(plan.Operations)-1]
	if err := store.RecordResult(plan, OperationResult{
		OperationID: failed.OperationID,
		Outcome:     OperationFailed,
		ErrorCode:   "projector_failed",
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	execution, err := store.Execute(
		context.Background(), plan, current, successfulCountingExecutor(&calls),
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("executor ran %d operations despite a persisted later failure", calls.Load())
	}
	if execution.Projection.State != StateFailed || execution.Report.RunState != RunFailed {
		t.Fatalf("persisted failure did not produce a failed run: %+v", execution)
	}
	for _, operation := range plan.Operations[:len(plan.Operations)-1] {
		result, readErr := store.readResultLocked(plan.Run.RunID, operation.OperationID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if result.Outcome != OperationFailed || result.ErrorCode != "operation_blocked" {
			t.Fatalf("missing operation was not deterministically blocked: %+v", result)
		}
	}
	assertServingVersion(t, store, current.Version)
}

func TestProjectionStoreLockSerializesIndependentInstances(t *testing.T) {
	root := t.TempDir()
	first, err := NewProjectionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProjectionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.withLock(func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered

	secondStarted := make(chan struct{})
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondDone <- second.withLock(func() error {
			close(secondEntered)
			return nil
		})
	}()
	<-secondStarted
	select {
	case <-secondEntered:
		t.Fatal("second store entered the exclusive lock before the first released it")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("second store did not acquire the lock after release")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestProjectionStoreRejectsStaleCASBeforeSideEffects(t *testing.T) {
	root := t.TempDir()
	store, current, firstPlan := testProjectionStorePlan(t, root, "projection-v2")
	secondPlan := testProjectionStorePlanFromCurrent(t, current, "projection-v3")
	executor := successfulCountingExecutor(nil)
	if _, err := store.Execute(context.Background(), firstPlan, current, executor); err != nil {
		t.Fatal(err)
	}

	var staleCalls atomic.Int64
	stale, err := store.Execute(context.Background(), secondPlan, current, successfulCountingExecutor(&staleCalls))
	if !errors.Is(err, ErrStaleServingPointer) {
		t.Fatalf("stale Execute error = %v, want ErrStaleServingPointer", err)
	}
	if staleCalls.Load() != 0 {
		t.Fatalf("stale execution ran %d side effects", staleCalls.Load())
	}
	if stale.Projection.State != StateFailed || stale.Report.RunState != RunFailed {
		t.Fatalf("stale execution was not journaled as failed: %+v", stale)
	}
	assertServingVersion(t, store, firstPlan.Run.ProjectionVersion)
}

func TestProjectionStorePersistsNonServingProjectionWhenCASTurnsStaleAfterReceipts(t *testing.T) {
	root := t.TempDir()
	store, current, winner := testProjectionStorePlan(t, root, "projection-v2")
	stale := testProjectionStorePlanFromCurrent(t, current, "projection-v3")
	if err := store.Stage(stale); err != nil {
		t.Fatal(err)
	}
	for _, result := range SuccessfulResults(stale) {
		if err := store.RecordResult(stale, result); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Execute(context.Background(), winner, current, successfulCountingExecutor(nil)); err != nil {
		t.Fatal(err)
	}

	execution, err := store.Finalize(stale, current)
	if !errors.Is(err, ErrStaleServingPointer) {
		t.Fatalf("Finalize error = %v, want ErrStaleServingPointer", err)
	}
	if execution.Projection.State != StateFailed || execution.Report.RunState != RunFailed {
		t.Fatalf("stale CAS outcome remained serving: %+v", execution)
	}
	for _, resource := range execution.Projection.Resources {
		if resource.IsServing() {
			t.Fatalf("stale CAS left resource serving: %+v", resource)
		}
	}
	assertServingVersion(t, store, winner.Run.ProjectionVersion)
}

func TestProjectionStoreSerializesConcurrentCASContenders(t *testing.T) {
	root := t.TempDir()
	store, current, firstPlan := testProjectionStorePlan(t, root, "projection-v2a")
	secondPlan := testProjectionStorePlanFromCurrent(t, current, "projection-v2b")
	secondStore, err := NewProjectionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type outcome struct {
		execution ProjectionExecution
		err       error
	}
	outcomes := make(chan outcome, 2)
	var calls atomic.Int64
	var wg sync.WaitGroup
	for index, contender := range []struct {
		store *ProjectionStore
		plan  ProjectionPlan
	}{{store, firstPlan}, {secondStore, secondPlan}} {
		wg.Add(1)
		go func(index int, contender struct {
			store *ProjectionStore
			plan  ProjectionPlan
		}) {
			defer wg.Done()
			<-start
			execution, executeErr := contender.store.Execute(
				context.Background(), contender.plan, current, successfulCountingExecutor(&calls),
			)
			outcomes <- outcome{execution: execution, err: executeErr}
		}(index, contender)
	}
	close(start)
	wg.Wait()
	close(outcomes)

	succeeded, stale := 0, 0
	for result := range outcomes {
		switch {
		case result.err == nil && result.execution.Report.RunState == RunSucceeded:
			succeeded++
		case errors.Is(result.err, ErrStaleServingPointer):
			stale++
		default:
			t.Fatalf("unexpected contender outcome: execution=%+v err=%v", result.execution, result.err)
		}
	}
	if succeeded != 1 || stale != 1 {
		t.Fatalf("concurrent outcomes: succeeded=%d stale=%d", succeeded, stale)
	}
	if calls.Load() != int64(len(firstPlan.Operations)) {
		t.Fatalf("side effect calls = %d, want one plan's %d operations", calls.Load(), len(firstPlan.Operations))
	}
	pointer, err := store.ServingPointer()
	if err != nil {
		t.Fatal(err)
	}
	if pointer.ProjectionVersion != firstPlan.Run.ProjectionVersion &&
		pointer.ProjectionVersion != secondPlan.Run.ProjectionVersion {
		t.Fatalf("serving pointer = %+v", pointer)
	}
}

func TestProjectionStoreResultConflictsAreRejected(t *testing.T) {
	store, _, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	result := SuccessfulResults(plan)[0]
	if err := store.RecordResult(plan, result); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordResult(plan, result); err != nil {
		t.Fatalf("identical result was not idempotent: %v", err)
	}
	result.Outcome = OperationFailed
	result.ErrorCode = "conflict"
	if err := store.RecordResult(plan, result); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("conflicting result error = %v, want ErrJournalConflict", err)
	}
}

func TestProjectionStoreWritesDeterministicPrivateJournalRecords(t *testing.T) {
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	planPath := store.planPath(plan.Run.RunID)
	before, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPlan, err := deterministicJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(wantPlan) {
		t.Fatalf("persisted plan is not canonical JSON:\ngot=%s\nwant=%s", before, wantPlan)
	}
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("idempotent stage changed the persisted plan bytes")
	}
	if _, err := store.Execute(context.Background(), plan, current, successfulCountingExecutor(nil)); err != nil {
		t.Fatal(err)
	}

	err = filepath.Walk(store.Root(), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if got := info.Mode().Perm(); got != 0o700 {
				t.Fatalf("directory %s permissions = %o, want 700", path, got)
			}
			return nil
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("file %s permissions = %o, want 600", path, got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProjectionStoreSyncsEveryNewJournalDirectoryEntry(t *testing.T) {
	store, _, plan := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	var synced []string
	store.syncDirectory = func(path string) error {
		synced = append(synced, path)
		return syncDirectory(path)
	}
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	wantParents := []string{store.runsDir(), store.runDir(plan.Run.RunID)}
	if len(synced) < len(wantParents) || !reflect.DeepEqual(synced[:len(wantParents)], wantParents) {
		t.Fatalf("directory creation sync order = %v, want prefix %v", synced, wantParents)
	}
	for _, want := range wantParents {
		found := false
		for _, path := range synced {
			if path == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("new child of %s was not followed by a parent directory sync: events=%v", want, synced)
		}
	}
}

func TestProjectionStoreCrashBeforePointerThenCompetitorWins(t *testing.T) {
	root := t.TempDir()
	store, current, interrupted := testProjectionStorePlan(t, root, "projection-v2")
	competitor := testProjectionStorePlanFromCurrent(t, current, "projection-v3")
	crash := errors.New("simulated crash before pointer CAS")
	store.afterCandidatePersisted = func(ProjectionPlan) error { return crash }
	if _, err := store.Execute(context.Background(), interrupted, current, successfulCountingExecutor(nil)); !errors.Is(err, crash) {
		t.Fatalf("interrupted Execute error = %v, want simulated crash", err)
	}
	if _, err := os.Stat(store.runProjectionPath(interrupted.Run.RunID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published run outcome existed before pointer CAS: %v", err)
	}
	assertServingVersion(t, store, current.Version)

	store.afterCandidatePersisted = nil
	if _, err := store.Execute(context.Background(), competitor, current, successfulCountingExecutor(nil)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewProjectionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := reopened.Execute(context.Background(), interrupted, current, successfulCountingExecutor(nil))
	if !errors.Is(err, ErrStaleServingPointer) {
		t.Fatalf("interrupted retry error = %v, want ErrStaleServingPointer", err)
	}
	if failed.Projection.State != StateFailed || failed.Report.RunState != RunFailed {
		t.Fatalf("pre-CAS crash was not durably failed: %+v", failed)
	}
	assertServingVersion(t, reopened, competitor.Run.ProjectionVersion)
}

func TestProjectionStoreCrashAfterPointerThenSuccessorReconcilesPredecessor(t *testing.T) {
	root := t.TempDir()
	store, current, interrupted := testProjectionStorePlan(t, root, "projection-v2")
	interruptedProjection, _, err := Replay(interrupted, current, SuccessfulResults(interrupted))
	if err != nil {
		t.Fatal(err)
	}
	successor := testProjectionStorePlanFromCurrent(t, interruptedProjection, "projection-v3")
	crash := errors.New("simulated crash after pointer CAS")
	store.afterPointerAdvanced = func(ServingPointer) error { return crash }
	if _, err := store.Execute(context.Background(), interrupted, current, successfulCountingExecutor(nil)); !errors.Is(err, crash) {
		t.Fatalf("interrupted Execute error = %v, want simulated crash", err)
	}
	assertServingVersion(t, store, interrupted.Run.ProjectionVersion)
	if _, err := os.Stat(store.runProjectionPath(interrupted.Run.RunID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run outcome was finalized despite simulated post-pointer crash: %v", err)
	}

	store.afterPointerAdvanced = nil
	if _, err := store.Execute(context.Background(), successor, interruptedProjection, successfulCountingExecutor(nil)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewProjectionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Execute(context.Background(), interrupted, current, successfulCountingExecutor(nil))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Projection.State != StatePublished || recovered.Report.RunState != RunSucceeded {
		t.Fatalf("pointer-bound predecessor was not reconciled as succeeded: %+v", recovered)
	}
	assertServingVersion(t, reopened, successor.Run.ProjectionVersion)
}

func TestProjectionStoreRejectsUnsafeRoot(t *testing.T) {
	if _, err := NewProjectionStore("relative/projections"); err == nil {
		t.Fatal("store accepted a relative root")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "projections")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewProjectionStore(link); err == nil {
		t.Fatal("store accepted a symlink root")
	}
}

func TestProjectionStoreRejectsPathLikeProjectionVersion(t *testing.T) {
	store, current, _ := testProjectionStorePlan(t, t.TempDir(), "projection-v2")
	plan := testProjectionStorePlanFromCurrent(t, current, "nested/projection-v2")
	if err := store.Stage(plan); err == nil {
		t.Fatal("store accepted a projection version containing a path separator")
	}
}

func testProjectionStorePlan(t *testing.T, root, projectionVersion string) (*ProjectionStore, Projection, ProjectionPlan) {
	t.Helper()
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	store, err := NewProjectionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InitializeServing(current); err != nil {
		t.Fatal(err)
	}
	return store, current, testProjectionStorePlanFromCurrent(t, current, projectionVersion)
}

func testProjectionStorePlanFromCurrent(t *testing.T, current Projection, projectionVersion string) ProjectionPlan {
	t.Helper()
	nextSnapshot := testSnapshot(t, current.Scope, "source-v2", "sources/a.md")
	run := testRun(current.Scope, current.Version, projectionVersion, nextSnapshot.Ref())
	run.RunID = "run-" + projectionVersion
	run.IdempotencyKey = "sync-" + projectionVersion
	desired := testMetadata(
		t, current.Scope, protocol.ResourceDocument, "sources/a.md", projectionVersion,
		"source-v2", "content-"+projectionVersion, projectionVersion, "", "doc:a",
	)
	plan, err := PlanResources(run, current, []ResourceMetadata{desired})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func successfulCountingExecutor(calls *atomic.Int64) OperationExecutor {
	return OperationExecutorFunc(func(_ context.Context, operation ProjectionOperation) (OperationResult, error) {
		if calls != nil {
			calls.Add(1)
		}
		return OperationResult{OperationID: operation.OperationID, Outcome: OperationSucceeded}, nil
	})
}

func assertServingVersion(t *testing.T, store *ProjectionStore, want string) {
	t.Helper()
	pointer, err := store.ServingPointer()
	if err != nil {
		t.Fatal(err)
	}
	if pointer.ProjectionVersion != want {
		t.Fatalf("serving version = %q, want %q", pointer.ProjectionVersion, want)
	}
}
