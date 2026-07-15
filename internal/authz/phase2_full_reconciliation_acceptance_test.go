package authz

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const phase2ReconciliationModelID = "01J20000000000000000000000"

func TestPhase2FullReconciliationAcceptanceReplacesClaimTupleSnapshot(t *testing.T) {
	common := []Tuple{
		{User: "user:alice", Relation: RelationMember, Object: "organization:phase2"},
		{User: "organization:phase2", Relation: RelationOrganization, Object: "knowledge_base:phase2"},
		{User: "user:alice", Relation: RelationViewer, Object: "knowledge_base:phase2"},
	}
	keep := phase2AuthorizationPathTuples("keep")
	stale := phase2AuthorizationPathTuples("stale")
	currentTuples := append(append(append([]Tuple(nil), common...), keep...), stale...)
	if err := ValidateTuples(currentTuples); err != nil {
		t.Fatal(err)
	}
	current, err := NewLocalAuthorizer(phase2ReconciliationModelID, currentTuples)
	if err != nil {
		t.Fatal(err)
	}
	phase2AssertAuthorizationDecision(t, current, "claim:phase2-keep", true)
	phase2AssertAuthorizationDecision(t, current, "claim:phase2-stale", true)

	desired := append(append([]Tuple(nil), common...), keep...)
	if err := ValidateTuples(desired); err != nil {
		t.Fatal(err)
	}
	partialStaleClaim := append(append([]Tuple(nil), desired...),
		Tuple{User: "organization:phase2", Relation: RelationOrganization, Object: "claim:phase2-stale"},
		Tuple{User: "document:phase2-stale", Relation: RelationSourceDocument, Object: "claim:phase2-stale"},
		Tuple{User: "entity:phase2-stale-subject", Relation: RelationSubject, Object: "claim:phase2-stale"},
	)
	if err := ValidateTuples(partialStaleClaim); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("partial stale Claim binding error = %v, want ErrInvalidRequest", err)
	}

	reconciled, err := NewLocalAuthorizer(phase2ReconciliationModelID, desired)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := NewLocalAuthorizer(phase2ReconciliationModelID, desired)
	if err != nil {
		t.Fatal(err)
	}
	gotTuples := reconciled.Tuples()
	if !reflect.DeepEqual(gotTuples, repeated.Tuples()) ||
		!reflect.DeepEqual(gotTuples, phase2CanonicalTuples(desired)) {
		t.Fatalf("reconciled tuple snapshot is not deterministic: %+v", gotTuples)
	}

	staleObjects := map[string]struct{}{
		"document:phase2-stale":       {},
		"entity:phase2-stale-subject": {},
		"entity:phase2-stale-object":  {},
		"claim:phase2-stale":          {},
	}
	for _, tuple := range gotTuples {
		if _, staleObject := staleObjects[tuple.Object]; staleObject {
			t.Fatalf("stale tuple object remains after reconciliation: %+v", tuple)
		}
		if _, staleSubject := staleObjects[tuple.User]; staleSubject {
			t.Fatalf("stale tuple subject remains after reconciliation: %+v", tuple)
		}
	}

	checks := []BatchCheckItem{
		{CorrelationID: "keep-document", User: "user:alice", Relation: RelationCanView, Object: "document:phase2-keep"},
		{CorrelationID: "keep-subject", User: "user:alice", Relation: RelationCanView, Object: "entity:phase2-keep-subject"},
		{CorrelationID: "keep-object", User: "user:alice", Relation: RelationCanView, Object: "entity:phase2-keep-object"},
		{CorrelationID: "keep-claim", User: "user:alice", Relation: RelationCanView, Object: "claim:phase2-keep"},
		{CorrelationID: "stale-document", User: "user:alice", Relation: RelationCanView, Object: "document:phase2-stale"},
		{CorrelationID: "stale-subject", User: "user:alice", Relation: RelationCanView, Object: "entity:phase2-stale-subject"},
		{CorrelationID: "stale-object", User: "user:alice", Relation: RelationCanView, Object: "entity:phase2-stale-object"},
		{CorrelationID: "stale-claim", User: "user:alice", Relation: RelationCanView, Object: "claim:phase2-stale"},
	}
	decisions, err := reconciled.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: phase2ReconciliationModelID,
		Consistency:          ConsistencyHigherConsistency,
		Checks:               checks,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != len(checks) {
		t.Fatalf("decision count = %d, want %d", len(decisions), len(checks))
	}
	for index, decision := range decisions {
		wantAllowed := strings.HasPrefix(checks[index].CorrelationID, "keep-")
		if decision.CorrelationID != checks[index].CorrelationID || decision.Allowed != wantAllowed ||
			decision.AuthorizationModelID != phase2ReconciliationModelID {
			t.Fatalf("decision %d = %+v, want correlation=%q allowed=%t", index, decision, checks[index].CorrelationID, wantAllowed)
		}
	}
}

func phase2AuthorizationPathTuples(suffix string) []Tuple {
	document := "document:phase2-" + suffix
	subject := "entity:phase2-" + suffix + "-subject"
	object := "entity:phase2-" + suffix + "-object"
	claim := "claim:phase2-" + suffix
	return []Tuple{
		{User: "organization:phase2", Relation: RelationOrganization, Object: document},
		{User: "knowledge_base:phase2", Relation: RelationParent, Object: document},
		{User: "organization:phase2", Relation: RelationOrganization, Object: subject},
		{User: document, Relation: RelationSourceDocument, Object: subject},
		{User: "organization:phase2", Relation: RelationOrganization, Object: object},
		{User: document, Relation: RelationSourceDocument, Object: object},
		{User: "organization:phase2", Relation: RelationOrganization, Object: claim},
		{User: document, Relation: RelationSourceDocument, Object: claim},
		{User: subject, Relation: RelationSubject, Object: claim},
		{User: object, Relation: RelationObject, Object: claim},
	}
}

func phase2AssertAuthorizationDecision(
	t *testing.T,
	authorizer *LocalAuthorizer,
	object string,
	want bool,
) {
	t.Helper()
	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User: "user:alice", Relation: RelationCanView, Object: object,
		AuthorizationModelID: phase2ReconciliationModelID,
		Consistency:          ConsistencyHigherConsistency,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed != want {
		t.Fatalf("decision for %s = %t, want %t", object, decision.Allowed, want)
	}
}

func phase2CanonicalTuples(tuples []Tuple) []Tuple {
	canonical := append([]Tuple(nil), tuples...)
	sort.Slice(canonical, func(i, j int) bool {
		left := strings.Join([]string{canonical[i].Object, canonical[i].Relation, canonical[i].User}, "\x00")
		right := strings.Join([]string{canonical[j].Object, canonical[j].Relation, canonical[j].User}, "\x00")
		return left < right
	})
	return canonical
}
