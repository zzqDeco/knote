package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

const reconciliationTestStoreID = "01GXSA8YR785C4FYS3C0RTG7B1"

func TestPlanCatalogTupleReconciliationHandlesAddRemoveAndChangeDeterministically(t *testing.T) {
	keepID := testClaimResourceID(t, "keep")
	staleID := testClaimResourceID(t, "stale")
	newID := testClaimResourceID(t, "new")
	current := testTupleProjection(t, "projection-v1", []testClaimTupleSpec{
		{resourceID: keepID, object: "claim:keep", source: "document:source", subject: "entity:keep-old", target: "entity:keep-object"},
		{resourceID: staleID, object: "claim:stale", source: "document:source", subject: "entity:stale-subject", target: "entity:stale-object"},
	})
	desired := testTupleProjection(t, "projection-v2", []testClaimTupleSpec{
		{resourceID: keepID, object: "claim:keep", source: "document:source", subject: "entity:keep-new", target: "entity:keep-object"},
		{resourceID: newID, object: "claim:new", source: "document:source", subject: "entity:new-subject", target: "entity:new-object"},
	})
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)

	first, err := PlanCatalogTupleReconciliation(current, desired, base, target)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanCatalogTupleReconciliation(current, desired, base, target)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("equal reconciliation inputs produced different bytes:\n%s\n%s", firstJSON, secondJSON)
	}
	if len(first.Writes) != 4 || len(first.Deletes) != 4 {
		t.Fatalf("write/delete counts = %d/%d, want 4/4", len(first.Writes), len(first.Deletes))
	}
	if !reflect.DeepEqual(first.RetiredResourceIDs, canonicalTestResourceIDs(keepID, staleID)) {
		t.Fatalf("retired resources = %#v", first.RetiredResourceIDs)
	}
	if !reflect.DeepEqual(first.GrantedResourceIDs, canonicalTestResourceIDs(keepID, newID)) {
		t.Fatalf("granted resources = %#v", first.GrantedResourceIDs)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("plan validation: %v", err)
	}
	tampered := first
	tampered.Writes = append([]CatalogTupleBinding(nil), first.Writes[1:]...)
	tampered.GrantedResourceIDs = resourceIDsFromBindings(tampered.Writes)
	if err := tampered.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("incomplete hand-built delta error = %v", err)
	}

	noop, err := PlanCatalogTupleReconciliation(desired, desired, target, target)
	if err != nil {
		t.Fatal(err)
	}
	if !noop.IsNoop() {
		t.Fatalf("equal tuple snapshots did not produce a no-op: %#v", noop)
	}
}

func TestPlanCatalogTupleReconciliationRequiresNewEpochAndACLWatermark(t *testing.T) {
	resourceID := testClaimResourceID(t, "claim")
	current := testTupleProjection(t, "projection-v1", nil)
	desired := testTupleProjection(t, "projection-v2", []testClaimTupleSpec{{
		resourceID: resourceID,
		object:     "claim:claim",
		source:     "document:source",
		subject:    "entity:subject",
		target:     "entity:object",
	}})
	base := testAuthorizationRevision(1)
	if _, err := PlanCatalogTupleReconciliation(current, desired, base, base); !errors.Is(err, ErrRegrantRevision) {
		t.Fatalf("same-revision tuple change error = %v", err)
	}
	target := testAuthorizationRevision(2)
	target.ACLWatermark = base.ACLWatermark
	if _, err := PlanCatalogTupleReconciliation(current, desired, base, target); !errors.Is(err, ErrRegrantRevision) {
		t.Fatalf("same-watermark tuple change error = %v", err)
	}
}

func TestTupleReconcilerPartialFailureDoesNotPublishAndRetryConverges(t *testing.T) {
	keepID := testClaimResourceID(t, "keep")
	staleID := testClaimResourceID(t, "stale")
	newID := testClaimResourceID(t, "new")
	current := testTupleProjection(t, "projection-v1", []testClaimTupleSpec{
		{resourceID: keepID, object: "claim:keep", source: "document:source", subject: "entity:keep-old", target: "entity:keep-object"},
		{resourceID: staleID, object: "claim:stale", source: "document:source", subject: "entity:stale-subject", target: "entity:stale-object"},
	})
	desired := testTupleProjection(t, "projection-v2", []testClaimTupleSpec{
		{resourceID: keepID, object: "claim:keep", source: "document:source", subject: "entity:keep-new", target: "entity:keep-object"},
		{resourceID: newID, object: "claim:new", source: "document:source", subject: "entity:new-subject", target: "entity:new-object"},
	})
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)
	plan, err := PlanCatalogTupleReconciliation(current, desired, base, target)
	if err != nil {
		t.Fatal(err)
	}

	events := &reconciliationEvents{}
	lifecycle, err := NewEpochRevocationLifecycle(ResourceInvalidatorFunc(func(_ context.Context, request InvalidationRequest) error {
		events.add("invalidate")
		return request.Validate()
	}))
	if err != nil {
		t.Fatal(err)
	}
	writer := newTestPartialTupleWriter(current.Tuples(), events)
	writer.failNext = true
	revisions, err := NewAtomicRevisionPublisher(base)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewTupleReconciler(writer, revisions, lifecycle)
	if err != nil {
		t.Fatal(err)
	}

	report, err := reconciler.Reconcile(context.Background(), plan)
	if !errors.Is(err, ErrReconciliation) {
		t.Fatalf("partial write error = %v", err)
	}
	if report.Outcome != ReconciliationFailed || report.RevisionPublished {
		t.Fatalf("failed report = %#v", report)
	}
	currentRevision, err := revisions.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if currentRevision != base {
		t.Fatalf("failed write published revision %#v", currentRevision)
	}
	allowed, err := lifecycle.Allows(base, keepID)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("changed resource remained readable after invalidation and failed write")
	}
	if got := events.snapshot(); len(got) < 2 || got[0] != "invalidate" || got[1] != "write" {
		t.Fatalf("failure ordering = %#v, want invalidation before write", got)
	}

	report, err = reconciler.Reconcile(context.Background(), plan)
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if report.Outcome != ReconciliationSucceeded || !report.RevisionPublished {
		t.Fatalf("successful report = %#v", report)
	}
	if report.InvalidatedResourceCount != 3 || report.GrantedResourceCount != 2 {
		t.Fatalf("content-free lifecycle counts = %#v", report)
	}
	currentRevision, err = revisions.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if currentRevision != target {
		t.Fatalf("published revision = %#v, want %#v", currentRevision, target)
	}
	if got := writer.tupleSnapshot(); !reflect.DeepEqual(got, desired.Tuples()) {
		t.Fatalf("reconciled tuples = %#v, want %#v", got, desired.Tuples())
	}
	for _, test := range []struct {
		resourceID protocol.ResourceID
		revision   AuthorizationRevision
		want       bool
	}{
		{resourceID: keepID, revision: base, want: false},
		{resourceID: keepID, revision: target, want: true},
		{resourceID: newID, revision: target, want: true},
		{resourceID: staleID, revision: target, want: false},
	} {
		allowed, err := lifecycle.Allows(test.revision, test.resourceID)
		if err != nil {
			t.Fatal(err)
		}
		if allowed != test.want {
			t.Fatalf("Allows(epoch=%d, resource=%s) = %t, want %t", test.revision.Epoch, test.resourceID, allowed, test.want)
		}
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(reportJSON, []byte("claim:")) || bytes.Contains(reportJSON, []byte("res_")) {
		t.Fatalf("reconciliation report leaked tuple or resource identifiers: %s", reportJSON)
	}
}

func TestTupleReconcilerRejectsRevisionSkewBeforeInvalidationOrWrite(t *testing.T) {
	resourceID := testClaimResourceID(t, "new")
	current := testTupleProjection(t, "projection-v1", nil)
	desired := testTupleProjection(t, "projection-v3", []testClaimTupleSpec{{
		resourceID: resourceID, object: "claim:new", source: "document:source",
		subject: "entity:new-subject", target: "entity:new-object",
	}})
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(3)
	plan, err := PlanCatalogTupleReconciliation(current, desired, base, target)
	if err != nil {
		t.Fatal(err)
	}
	actual := testAuthorizationRevision(2)
	revisions, err := NewAtomicRevisionPublisher(actual)
	if err != nil {
		t.Fatal(err)
	}
	var invalidations, writes int
	lifecycle, err := NewEpochRevocationLifecycle(ResourceInvalidatorFunc(func(context.Context, InvalidationRequest) error {
		invalidations++
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewTupleReconciler(
		TupleWriterFunc(func(context.Context, TupleWriteRequest) error {
			writes++
			return nil
		}),
		revisions,
		lifecycle,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), plan); !errors.Is(err, ErrRevisionSkew) {
		t.Fatalf("revision skew error = %v", err)
	}
	if invalidations != 0 || writes != 0 {
		t.Fatalf("skew performed invalidations/writes = %d/%d", invalidations, writes)
	}
}

type testClaimTupleSpec struct {
	resourceID protocol.ResourceID
	object     string
	source     string
	subject    string
	target     string
}

func testTupleProjection(
	t *testing.T,
	version string,
	specs []testClaimTupleSpec,
) CatalogTupleProjection {
	t.Helper()
	bindings := make([]CatalogTupleBinding, 0, len(specs)*3)
	for _, spec := range specs {
		for _, tuple := range []Tuple{
			{User: spec.source, Relation: RelationSourceDocument, Object: spec.object},
			{User: spec.subject, Relation: RelationSubject, Object: spec.object},
			{User: spec.target, Relation: RelationObject, Object: spec.object},
		} {
			bindings = append(bindings, CatalogTupleBinding{ResourceID: spec.resourceID, Tuple: tuple})
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return catalogTupleBindingLess(bindings[i], bindings[j]) })
	projection := CatalogTupleProjection{ProjectionVersion: version, Bindings: bindings}
	if err := projection.Validate(); err != nil {
		t.Fatal(err)
	}
	return projection
}

func testClaimResourceID(t *testing.T, sourceKey string) protocol.ResourceID {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID("tenant-authz", "kb-authz", protocol.ResourceClaim, sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	return resourceID
}

func testAuthorizationRevision(epoch uint64) AuthorizationRevision {
	return AuthorizationRevision{
		StoreID:              reconciliationTestStoreID,
		AuthorizationModelID: phase2ReconciliationModelID,
		IdentityWatermark:    "identity-v1",
		ACLWatermark:         "acl-v" + strconv.FormatUint(epoch, 10),
		Epoch:                epoch,
	}
}

type reconciliationEvents struct {
	mu     sync.Mutex
	events []string
}

func (e *reconciliationEvents) add(event string) {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()
}

func (e *reconciliationEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

type testPartialTupleWriter struct {
	mu       sync.Mutex
	tuples   map[Tuple]struct{}
	failNext bool
	events   *reconciliationEvents
}

func newTestPartialTupleWriter(tuples []Tuple, events *reconciliationEvents) *testPartialTupleWriter {
	set := make(map[Tuple]struct{}, len(tuples))
	for _, tuple := range tuples {
		set[tuple] = struct{}{}
	}
	return &testPartialTupleWriter{tuples: set, events: events}
}

func (w *testPartialTupleWriter) ApplyTupleChanges(_ context.Context, request TupleWriteRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	w.events.add("write")
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, tuple := range request.Deletes {
		delete(w.tuples, tuple)
	}
	for _, tuple := range request.Writes {
		w.tuples[tuple] = struct{}{}
	}
	if w.failNext {
		w.failNext = false
		return errors.New("injected partial write failure")
	}
	return nil
}

func (w *testPartialTupleWriter) tupleSnapshot() []Tuple {
	w.mu.Lock()
	defer w.mu.Unlock()
	tuples := make([]Tuple, 0, len(w.tuples))
	for tuple := range w.tuples {
		tuples = append(tuples, tuple)
	}
	sort.Slice(tuples, func(i, j int) bool { return tupleLess(tuples[i], tuples[j]) })
	return tuples
}
