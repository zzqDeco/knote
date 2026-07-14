package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestEntityAndClaimAuthorizationTruthTable(t *testing.T) {
	authorizer := newEntityClaimTestAuthorizer(t)
	tests := []struct {
		name     string
		user     string
		relation string
		object   string
		allowed  bool
	}{
		{name: "entity inherits source view", user: "user:alice", relation: RelationCanView, object: "entity:visible-subject", allowed: true},
		{name: "entity inherits source edit", user: "user:erin", relation: RelationCanEdit, object: "entity:visible-subject", allowed: true},
		{name: "restricted entity blocks inheritance", user: "user:alice", relation: RelationCanView, object: "entity:hidden-subject", allowed: false},
		{name: "direct entity share overrides restricted inheritance", user: "user:bob", relation: RelationCanView, object: "entity:hidden-subject", allowed: true},
		{name: "direct entity editor grants view", user: "user:bob", relation: RelationCanView, object: "entity:direct-edit", allowed: true},
		{name: "direct entity editor grants edit", user: "user:bob", relation: RelationCanEdit, object: "entity:direct-edit", allowed: true},
		{name: "claim inherits source and entity visibility", user: "user:alice", relation: RelationCanView, object: "claim:visible", allowed: true},
		{name: "claim inherits source and entity edit", user: "user:erin", relation: RelationCanEdit, object: "claim:visible", allowed: true},
		{name: "visible entities do not expose restricted claim", user: "user:alice", relation: RelationCanView, object: "claim:hidden", allowed: false},
		{name: "direct claim share overrides restricted inheritance", user: "user:bob", relation: RelationCanView, object: "claim:hidden", allowed: true},
		{name: "direct claim editor grants view", user: "user:bob", relation: RelationCanView, object: "claim:direct-edit", allowed: true},
		{name: "direct claim editor grants edit", user: "user:bob", relation: RelationCanEdit, object: "claim:direct-edit", allowed: true},
		{name: "source denial blocks claim", user: "user:alice", relation: RelationCanView, object: "claim:source-denied", allowed: false},
		{name: "subject denial blocks claim", user: "user:alice", relation: RelationCanView, object: "claim:subject-denied", allowed: false},
		{name: "object denial blocks claim", user: "user:alice", relation: RelationCanView, object: "claim:object-denied", allowed: false},
		{name: "cross tenant direct entity share denied", user: "user:mallory", relation: RelationCanView, object: "entity:cross-tenant", allowed: false},
		{name: "cross tenant direct claim share denied", user: "user:mallory", relation: RelationCanView, object: "claim:cross-tenant", allowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertLocalDecision(t, authorizer, test.user, test.relation, test.object, test.allowed)
		})
	}
}

func TestEntityAndClaimTupleValidationIsStrict(t *testing.T) {
	valid := []Tuple{
		{User: "organization:acme", Relation: RelationOrganization, Object: "entity:subject"},
		{User: "document:source", Relation: RelationSourceDocument, Object: "entity:subject"},
		{User: "group:engineering#member", Relation: RelationViewer, Object: "entity:subject"},
		{User: "user:*", Relation: RelationRestricted, Object: "entity:subject"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "claim:edge"},
		{User: "document:source", Relation: RelationSourceDocument, Object: "claim:edge"},
		{User: "entity:subject", Relation: RelationSubject, Object: "claim:edge"},
		{User: "entity:object", Relation: RelationObject, Object: "claim:edge"},
		{User: "user:alice", Relation: RelationEditor, Object: "claim:edge"},
		{User: "user:*", Relation: RelationRestricted, Object: "claim:edge"},
	}
	for _, tuple := range valid {
		if err := tuple.Validate(); err != nil {
			t.Errorf("valid tuple %+v: %v", tuple, err)
		}
	}

	invalid := []Tuple{
		{User: "user:alice", Relation: RelationOrganization, Object: "entity:subject"},
		{User: "claim:edge", Relation: RelationSourceDocument, Object: "entity:subject"},
		{User: "document:source#viewer", Relation: RelationSourceDocument, Object: "entity:subject"},
		{User: "entity:object", Relation: RelationViewer, Object: "entity:subject"},
		{User: "user:alice", Relation: RelationRestricted, Object: "entity:subject"},
		{User: "entity:subject", Relation: RelationSourceDocument, Object: "claim:edge"},
		{User: "document:source", Relation: RelationSubject, Object: "claim:edge"},
		{User: "claim:other", Relation: RelationObject, Object: "claim:edge"},
		{User: "entity:*", Relation: RelationSubject, Object: "claim:edge"},
		{User: "user:*", Relation: RelationViewer, Object: "claim:edge"},
		{User: "entity:*", Relation: RelationRestricted, Object: "claim:edge"},
		{User: "entity:subject", Relation: RelationSubject, Object: "claim:*"},
	}
	for _, tuple := range invalid {
		if err := tuple.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("invalid tuple %+v error = %v", tuple, err)
		}
	}
}

func TestClaimBindingSnapshotRequiresExactlyOneBoundary(t *testing.T) {
	complete := []Tuple{
		{User: "organization:acme", Relation: RelationOrganization, Object: "claim:edge"},
		{User: "document:current", Relation: RelationSourceDocument, Object: "claim:edge"},
		{User: "entity:subject", Relation: RelationSubject, Object: "claim:edge"},
		{User: "entity:object", Relation: RelationObject, Object: "claim:edge"},
	}
	if err := ValidateTuples(append(append([]Tuple(nil), complete...), complete[1])); err != nil {
		t.Fatalf("identical tuple is one binding: %v", err)
	}

	tests := []struct {
		name   string
		tuples []Tuple
	}{
		{
			name: "duplicate source",
			tuples: append(append([]Tuple(nil), complete...),
				Tuple{User: "document:stale", Relation: RelationSourceDocument, Object: "claim:edge"}),
		},
		{
			name: "duplicate subject",
			tuples: append(append([]Tuple(nil), complete...),
				Tuple{User: "entity:stale-subject", Relation: RelationSubject, Object: "claim:edge"}),
		},
		{
			name: "duplicate object",
			tuples: append(append([]Tuple(nil), complete...),
				Tuple{User: "entity:stale-object", Relation: RelationObject, Object: "claim:edge"}),
		},
		{name: "missing source", tuples: []Tuple{complete[0], complete[2], complete[3]}},
		{name: "missing subject", tuples: []Tuple{complete[0], complete[1], complete[3]}},
		{name: "missing object", tuples: []Tuple{complete[0], complete[1], complete[2]}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateTuples(test.tuples); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ValidateTuples error = %v, want %v", err, ErrInvalidRequest)
			}
			if _, err := NewLocalAuthorizer(localTestModelID, test.tuples); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewLocalAuthorizer error = %v, want %v", err, ErrInvalidRequest)
			}
		})
	}
}

func TestClaimBindingMutationRejectsStaleAlternatesAndFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		claim    string
		relation string
		stale    string
		current  string
	}{
		{
			name: "source", claim: "claim:source-denied", relation: RelationSourceDocument,
			stale: "document:source", current: "document:source-denied",
		},
		{
			name: "subject", claim: "claim:subject-denied", relation: RelationSubject,
			stale: "entity:visible-subject", current: "entity:hidden-subject",
		},
		{
			name: "object", claim: "claim:object-denied", relation: RelationObject,
			stale: "entity:visible-object", current: "entity:hidden-object",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := newEntityClaimTestAuthorizer(t)
			stale := Tuple{User: test.stale, Relation: test.relation, Object: test.claim}
			if err := authorizer.AddTuple(stale); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("add stale binding error = %v, want %v", err, ErrInvalidRequest)
			}
			assertLocalDecision(t, authorizer, "user:alice", RelationCanView, test.claim, false)

			current := Tuple{User: test.current, Relation: test.relation, Object: test.claim}
			if err := authorizer.RemoveTuple(current); err != nil {
				t.Fatalf("remove current binding: %v", err)
			}
			decision, err := authorizer.Check(context.Background(), CheckRequest{
				User: "user:alice", Relation: RelationCanView, Object: test.claim,
				AuthorizationModelID: localTestModelID,
			})
			if !errors.Is(err, ErrInvalidRequest) || decision.Allowed {
				t.Fatalf("incomplete binding decision=%#v error=%v", decision, err)
			}
		})
	}
}

func TestEntityAndClaimBatchIsOrderedAndFailsClosed(t *testing.T) {
	authorizer := newEntityClaimTestAuthorizer(t)
	request := BatchCheckRequest{
		AuthorizationModelID: localTestModelID,
		Checks: []BatchCheckItem{
			{CorrelationID: "hidden-claim", User: "user:alice", Relation: RelationCanView, Object: "claim:hidden"},
			{CorrelationID: "visible-entity", User: "user:alice", Relation: RelationCanView, Object: "entity:visible-subject"},
			{CorrelationID: "visible-claim", User: "user:alice", Relation: RelationCanView, Object: "claim:visible"},
		},
	}
	decisions, err := authorizer.BatchCheck(context.Background(), request)
	if err != nil {
		t.Fatalf("batch check: %v", err)
	}
	want := []Decision{
		{CorrelationID: "hidden-claim", Allowed: false, AuthorizationModelID: localTestModelID},
		{CorrelationID: "visible-entity", Allowed: true, AuthorizationModelID: localTestModelID},
		{CorrelationID: "visible-claim", Allowed: true, AuthorizationModelID: localTestModelID},
	}
	if !reflect.DeepEqual(decisions, want) {
		t.Fatalf("decisions = %#v, want %#v", decisions, want)
	}

	request.Checks[1].Object = "unsupported:object"
	decisions, err = authorizer.BatchCheck(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unsupported object error = %v", err)
	}
	if len(decisions) != len(request.Checks) {
		t.Fatalf("failed batch decision count = %d, want %d", len(decisions), len(request.Checks))
	}
	for _, decision := range decisions {
		if decision.Allowed {
			t.Fatalf("failed batch returned partial allow: %#v", decisions)
		}
	}
}

func newEntityClaimTestAuthorizer(t *testing.T) *LocalAuthorizer {
	t.Helper()
	tuple := func(user, relation, object string) Tuple {
		return Tuple{User: user, Relation: relation, Object: object}
	}
	tupleFor := func(object string, relations ...Tuple) []Tuple {
		result := make([]Tuple, len(relations))
		for index, relation := range relations {
			relation.Object = object
			result[index] = relation
		}
		return result
	}
	relation := func(user, name string) Tuple {
		return Tuple{User: user, Relation: name}
	}

	tuples := []Tuple{
		tuple("user:alice", RelationMember, "organization:acme"),
		tuple("user:bob", RelationMember, "organization:acme"),
		tuple("user:erin", RelationMember, "organization:acme"),
		tuple("user:mallory", RelationMember, "organization:other"),
		tuple("organization:acme", RelationOrganization, "knowledge_base:graph"),
		tuple("user:alice", RelationViewer, "knowledge_base:graph"),
		tuple("user:erin", RelationEditor, "knowledge_base:graph"),
		tuple("organization:acme", RelationOrganization, "document:source"),
		tuple("knowledge_base:graph", RelationParent, "document:source"),
		tuple("organization:acme", RelationOrganization, "document:source-denied"),
	}

	tuples = append(tuples, tupleFor("entity:visible-subject",
		relation("organization:acme", RelationOrganization),
		relation("document:source", RelationSourceDocument),
	)...)
	tuples = append(tuples, tupleFor("entity:visible-object",
		relation("organization:acme", RelationOrganization),
		relation("document:source", RelationSourceDocument),
	)...)
	tuples = append(tuples, tupleFor("entity:hidden-subject",
		relation("organization:acme", RelationOrganization),
		relation("document:source", RelationSourceDocument),
		relation("user:*", RelationRestricted),
		relation("user:bob", RelationViewer),
	)...)
	tuples = append(tuples, tupleFor("entity:hidden-object",
		relation("organization:acme", RelationOrganization),
		relation("document:source", RelationSourceDocument),
		relation("user:*", RelationRestricted),
	)...)
	tuples = append(tuples, tupleFor("entity:direct-edit",
		relation("organization:acme", RelationOrganization),
		relation("document:source-denied", RelationSourceDocument),
		relation("user:bob", RelationEditor),
	)...)
	tuples = append(tuples, tupleFor("entity:cross-tenant",
		relation("organization:acme", RelationOrganization),
		relation("user:mallory", RelationViewer),
	)...)

	claimRelations := func(source, subject, object string) []Tuple {
		return []Tuple{
			relation("organization:acme", RelationOrganization),
			relation(source, RelationSourceDocument),
			relation(subject, RelationSubject),
			relation(object, RelationObject),
		}
	}
	tuples = append(tuples, tupleFor("claim:visible", claimRelations(
		"document:source", "entity:visible-subject", "entity:visible-object",
	)...)...)
	tuples = append(tuples, tupleFor("claim:hidden", append(claimRelations(
		"document:source", "entity:visible-subject", "entity:visible-object",
	), relation("user:*", RelationRestricted), relation("user:bob", RelationViewer))...)...)
	tuples = append(tuples, tupleFor("claim:direct-edit", append(claimRelations(
		"document:source-denied", "entity:hidden-subject", "entity:hidden-object",
	), relation("user:bob", RelationEditor))...)...)
	tuples = append(tuples, tupleFor("claim:source-denied", claimRelations(
		"document:source-denied", "entity:visible-subject", "entity:visible-object",
	)...)...)
	tuples = append(tuples, tupleFor("claim:subject-denied", claimRelations(
		"document:source", "entity:hidden-subject", "entity:visible-object",
	)...)...)
	tuples = append(tuples, tupleFor("claim:object-denied", claimRelations(
		"document:source", "entity:visible-subject", "entity:hidden-object",
	)...)...)
	tuples = append(tuples, tupleFor("claim:cross-tenant", append(claimRelations(
		"document:source", "entity:visible-subject", "entity:visible-object",
	), relation("user:mallory", RelationViewer))...)...)

	authorizer, err := NewLocalAuthorizer(localTestModelID, tuples)
	if err != nil {
		t.Fatalf("new entity/claim authorizer: %v", err)
	}
	return authorizer
}
