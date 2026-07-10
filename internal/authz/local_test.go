package authz

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

const localTestModelID = "01GAHCE4YVKPQEKZQHT2R89MQV"

func TestLocalAuthorizerTruthTable(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	tests := []struct {
		name     string
		user     string
		relation string
		object   string
		allowed  bool
	}{
		{name: "inherited group read", user: "user:alice", relation: RelationCanRead, object: "document:welcome", allowed: true},
		{name: "computed inherited reader", user: "user:alice", relation: relationInheritedReader, object: "document:welcome", allowed: true},
		{name: "computed unscoped reader", user: "user:alice", relation: relationUnscopedReader, object: "document:welcome", allowed: true},
		{name: "inherited group edit denied", user: "user:alice", relation: RelationCanEdit, object: "document:welcome", allowed: false},
		{name: "inherited editor", user: "user:erin", relation: RelationCanEdit, object: "document:welcome", allowed: true},
		{name: "computed inherited editor", user: "user:erin", relation: relationInheritedEditor, object: "document:welcome", allowed: true},
		{name: "cross tenant share", user: "user:mallory", relation: RelationCanRead, object: "document:cross-tenant", allowed: false},
		{name: "restricted inherited read", user: "user:alice", relation: RelationCanRead, object: "document:restricted", allowed: false},
		{name: "restricted computed inherited read", user: "user:alice", relation: relationInheritedReader, object: "document:restricted", allowed: false},
		{name: "restricted direct share", user: "user:bob", relation: RelationCanRead, object: "document:restricted", allowed: true},
		{name: "direct share", user: "user:bob", relation: RelationCanRead, object: "document:direct", allowed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := authorizer.Check(context.Background(), CheckRequest{
				User:                 test.user,
				Relation:             test.relation,
				Object:               test.object,
				AuthorizationModelID: localTestModelID,
			})
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t", decision.Allowed, test.allowed)
			}
		})
	}
}

func TestLocalAuthorizerGroupAddRemoveAndDirectRevoke(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	membership := Tuple{User: "user:alice", Relation: RelationMember, Object: "group:engineering"}
	if err := authorizer.RemoveTuple(membership); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	assertLocalDecision(t, authorizer, "user:alice", RelationCanRead, "document:welcome", false)
	if err := authorizer.AddTuple(membership); err != nil {
		t.Fatalf("add membership: %v", err)
	}
	assertLocalDecision(t, authorizer, "user:alice", RelationCanRead, "document:welcome", true)

	share := Tuple{User: "user:bob", Relation: RelationViewer, Object: "document:direct"}
	if err := authorizer.RemoveTuple(share); err != nil {
		t.Fatalf("revoke direct share: %v", err)
	}
	assertLocalDecision(t, authorizer, "user:bob", RelationCanRead, "document:direct", false)
	if err := authorizer.RemoveTuple(share); err != nil {
		t.Fatalf("idempotent stale tuple cleanup: %v", err)
	}
}

func TestLocalAuthorizerBatchIsOrderedAndFailsClosed(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	request := BatchCheckRequest{
		AuthorizationModelID: localTestModelID,
		Checks: []BatchCheckItem{
			{CorrelationID: "second", User: "user:mallory", Relation: RelationCanRead, Object: "document:cross-tenant"},
			{CorrelationID: "first", User: "user:alice", Relation: RelationCanRead, Object: "document:welcome"},
		},
	}
	decisions, err := authorizer.BatchCheck(context.Background(), request)
	if err != nil {
		t.Fatalf("batch check: %v", err)
	}
	want := []Decision{
		{CorrelationID: "second", Allowed: false, AuthorizationModelID: localTestModelID},
		{CorrelationID: "first", Allowed: true, AuthorizationModelID: localTestModelID},
	}
	if !reflect.DeepEqual(decisions, want) {
		t.Fatalf("decisions = %#v, want %#v", decisions, want)
	}

	request.Checks[1].CorrelationID = "second"
	decisions, err = authorizer.BatchCheck(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate correlation error = %v", err)
	}
	for _, decision := range decisions {
		if decision.Allowed {
			t.Fatalf("invalid batch returned allow: %#v", decisions)
		}
	}
}

func TestBatchCheckRequestRejectsOversizedBatch(t *testing.T) {
	checks := make([]BatchCheckItem, MaxBatchChecks+1)
	for i := range checks {
		checks[i] = BatchCheckItem{
			CorrelationID: fmt.Sprintf("check-%d", i), User: "user:alice",
			Relation: RelationCanRead, Object: "document:welcome",
		}
	}
	request := BatchCheckRequest{AuthorizationModelID: localTestModelID, Checks: checks}
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized batch error = %v", err)
	}
}

func TestLocalAuthorizerModelMismatchAndCancellationDeny(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	request := CheckRequest{
		User:                 "user:alice",
		Relation:             RelationCanRead,
		Object:               "document:welcome",
		AuthorizationModelID: "01GXSB9YR785C4FYS3C0RTG7B2",
	}
	decision, err := authorizer.Check(context.Background(), request)
	if !errors.Is(err, ErrModelMismatch) || decision.Allowed {
		t.Fatalf("model mismatch decision=%#v error=%v", decision, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request.AuthorizationModelID = localTestModelID
	decision, err = authorizer.Check(ctx, request)
	if !errors.Is(err, ErrUnavailable) || decision.Allowed {
		t.Fatalf("canceled decision=%#v error=%v", decision, err)
	}
}

func TestLocalAuthorizerTuplesAreSorted(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	tuples := authorizer.Tuples()
	for index := 1; index < len(tuples); index++ {
		previous := tuples[index-1].Object + "\x00" + tuples[index-1].Relation + "\x00" + tuples[index-1].User
		current := tuples[index].Object + "\x00" + tuples[index].Relation + "\x00" + tuples[index].User
		if previous >= current {
			t.Fatalf("tuples are not strictly sorted at %d: %#v", index, tuples)
		}
	}
}

func TestAuthorizationConfigDefaultsToStrictLocalMode(t *testing.T) {
	authorizer, err := New(Config{AuthorizationModelID: localTestModelID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := authorizer.(*LocalAuthorizer); !ok {
		t.Fatalf("default authorizer type = %T, want strict local", authorizer)
	}
	if _, err := New(Config{Mode: "disabled", AuthorizationModelID: localTestModelID}, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid mode error = %v", err)
	}
}

func newLocalTestAuthorizer(t *testing.T) *LocalAuthorizer {
	t.Helper()
	tuples := []Tuple{
		{User: "user:alice", Relation: RelationMember, Object: "group:engineering"},
		{User: "group:engineering#member", Relation: RelationMember, Object: "organization:acme"},
		{User: "user:bob", Relation: RelationMember, Object: "organization:acme"},
		{User: "user:erin", Relation: RelationMember, Object: "organization:acme"},
		{User: "user:mallory", Relation: RelationMember, Object: "organization:other"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "knowledge_base:handbook"},
		{User: "group:engineering#member", Relation: RelationViewer, Object: "knowledge_base:handbook"},
		{User: "user:erin", Relation: RelationEditor, Object: "knowledge_base:handbook"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "document:welcome"},
		{User: "knowledge_base:handbook", Relation: RelationParent, Object: "document:welcome"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "document:cross-tenant"},
		{User: "user:mallory", Relation: RelationViewer, Object: "document:cross-tenant"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "document:restricted"},
		{User: "knowledge_base:handbook", Relation: RelationParent, Object: "document:restricted"},
		{User: "user:*", Relation: RelationRestricted, Object: "document:restricted"},
		{User: "user:bob", Relation: RelationViewer, Object: "document:restricted"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "document:direct"},
		{User: "user:bob", Relation: RelationViewer, Object: "document:direct"},
	}
	authorizer, err := NewLocalAuthorizer(localTestModelID, tuples)
	if err != nil {
		t.Fatalf("new local authorizer: %v", err)
	}
	return authorizer
}

func assertLocalDecision(t *testing.T, authorizer *LocalAuthorizer, user, relation, object string, allowed bool) {
	t.Helper()
	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User:                 user,
		Relation:             relation,
		Object:               object,
		AuthorizationModelID: localTestModelID,
	})
	if err != nil {
		t.Fatalf("check %s %s %s: %v", user, relation, object, err)
	}
	if decision.Allowed != allowed {
		t.Fatalf("check %s %s %s allowed=%t, want %t", user, relation, object, decision.Allowed, allowed)
	}
}
