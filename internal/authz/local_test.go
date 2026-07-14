package authz

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
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
		{name: "inherited group read", user: "user:alice", relation: RelationCanView, object: "document:welcome", allowed: true},
		{name: "computed inherited reader", user: "user:alice", relation: relationInheritedReader, object: "document:welcome", allowed: true},
		{name: "computed unscoped reader", user: "user:alice", relation: relationUnscopedReader, object: "document:welcome", allowed: true},
		{name: "inherited group edit denied", user: "user:alice", relation: RelationCanEdit, object: "document:welcome", allowed: false},
		{name: "inherited editor", user: "user:erin", relation: RelationCanEdit, object: "document:welcome", allowed: true},
		{name: "computed inherited editor", user: "user:erin", relation: relationInheritedEditor, object: "document:welcome", allowed: true},
		{name: "cross tenant share", user: "user:mallory", relation: RelationCanView, object: "document:cross-tenant", allowed: false},
		{name: "restricted inherited read", user: "user:alice", relation: RelationCanView, object: "document:restricted", allowed: false},
		{name: "restricted computed inherited read", user: "user:alice", relation: relationInheritedReader, object: "document:restricted", allowed: false},
		{name: "restricted direct share", user: "user:bob", relation: RelationCanView, object: "document:restricted", allowed: true},
		{name: "direct share", user: "user:bob", relation: RelationCanView, object: "document:direct", allowed: true},
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
	assertLocalDecision(t, authorizer, "user:alice", RelationCanView, "document:welcome", false)
	if err := authorizer.AddTuple(membership); err != nil {
		t.Fatalf("add membership: %v", err)
	}
	assertLocalDecision(t, authorizer, "user:alice", RelationCanView, "document:welcome", true)

	share := Tuple{User: "user:bob", Relation: RelationViewer, Object: "document:direct"}
	if err := authorizer.RemoveTuple(share); err != nil {
		t.Fatalf("revoke direct share: %v", err)
	}
	assertLocalDecision(t, authorizer, "user:bob", RelationCanView, "document:direct", false)
	if err := authorizer.RemoveTuple(share); err != nil {
		t.Fatalf("idempotent stale tuple cleanup: %v", err)
	}
}

func TestLocalAuthorizerBatchIsOrderedAndFailsClosed(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	request := BatchCheckRequest{
		AuthorizationModelID: localTestModelID,
		Checks: []BatchCheckItem{
			{CorrelationID: "second", User: "user:mallory", Relation: RelationCanView, Object: "document:cross-tenant"},
			{CorrelationID: "first", User: "user:alice", Relation: RelationCanView, Object: "document:welcome"},
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
	authorizer := newLocalTestAuthorizer(t)
	checks := make([]BatchCheckItem, MaxBatchChecks+1)
	for i := range checks {
		checks[i] = BatchCheckItem{
			CorrelationID: fmt.Sprintf("check-%d", i), User: "user:alice",
			Relation: RelationCanView, Object: "document:welcome",
		}
	}
	request := BatchCheckRequest{AuthorizationModelID: localTestModelID, Checks: checks}
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized batch error = %v", err)
	}
	decisions, err := authorizer.BatchCheck(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized batch check error = %v", err)
	}
	if decisions != nil {
		t.Fatalf("oversized batch allocated decisions: %#v", decisions)
	}
}

func TestCheckRequestsRejectUsersetPrincipals(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	request := CheckRequest{
		User:                 "group:engineering#member",
		Relation:             RelationCanView,
		Object:               "document:restricted",
		AuthorizationModelID: localTestModelID,
	}
	decision, err := authorizer.Check(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) || decision.Allowed {
		t.Fatalf("userset check decision=%#v error=%v", decision, err)
	}

	decisions, err := authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: localTestModelID,
		Checks: []BatchCheckItem{{
			CorrelationID: "userset", User: request.User,
			Relation: request.Relation, Object: request.Object,
		}},
	})
	if !errors.Is(err, ErrInvalidRequest) || len(decisions) != 1 || decisions[0].Allowed {
		t.Fatalf("userset batch decisions=%#v error=%v", decisions, err)
	}
}

func TestBatchCheckRequestRejectsInvalidCorrelationIDs(t *testing.T) {
	for _, correlationID := range []string{"foo_bar", strings.Repeat("a", 37)} {
		request := BatchCheckRequest{
			AuthorizationModelID: localTestModelID,
			Checks: []BatchCheckItem{{
				CorrelationID: correlationID, User: "user:alice",
				Relation: RelationCanView, Object: "document:welcome",
			}},
		}
		if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("correlation_id %q error = %v", correlationID, err)
		}
	}
}

func TestLocalAuthorizerModelMismatchAndCancellationDeny(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	request := CheckRequest{
		User:                 "user:alice",
		Relation:             RelationCanView,
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

func TestLocalBatchCheckCancellationDuringEvaluationDenies(t *testing.T) {
	tests := []struct {
		name    string
		failure error
		wantErr error
	}{
		{name: "canceled", failure: context.Canceled, wantErr: ErrUnavailable},
		{name: "deadline", failure: context.DeadlineExceeded, wantErr: ErrTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := newLocalTestAuthorizer(t)
			ctx := newFailOnNthErrContext(test.failure, 3)
			decisions, err := authorizer.BatchCheck(ctx, BatchCheckRequest{
				AuthorizationModelID: localTestModelID,
				Checks: []BatchCheckItem{{
					CorrelationID: "would-allow", User: "user:alice",
					Relation: RelationCanView, Object: "document:welcome",
				}},
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if len(decisions) != 1 || decisions[0].Allowed {
				t.Fatalf("decisions = %#v, want one fail-closed deny", decisions)
			}
			if !errors.Is(ctx.Err(), test.failure) {
				t.Fatalf("context error = %v, want %v", ctx.Err(), test.failure)
			}
		})
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

type failOnNthErrContext struct {
	failure error
	failAt  int
	calls   int
	done    chan struct{}
}

func newFailOnNthErrContext(failure error, failAt int) *failOnNthErrContext {
	return &failOnNthErrContext{failure: failure, failAt: failAt, done: make(chan struct{})}
}

func (c *failOnNthErrContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (c *failOnNthErrContext) Done() <-chan struct{} {
	return c.done
}

func (c *failOnNthErrContext) Err() error {
	c.calls++
	if c.calls < c.failAt {
		return nil
	}
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return c.failure
}

func (c *failOnNthErrContext) Value(any) any {
	return nil
}
