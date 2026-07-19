package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLocalAgentTaskIntersectionTruthTable(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	tests := []struct {
		name    string
		user    string
		object  string
		tuples  []Tuple
		allowed bool
	}{
		{
			name: "group permission intersects complete scope", user: "user:alice", object: "document:welcome",
			tuples: agentTaskEvidence("user:alice", "agent:research", "task:answer"), allowed: true,
		},
		{
			name: "direct share intersects complete scope", user: "user:bob", object: "document:direct",
			tuples: agentTaskEvidence("user:bob", "agent:research", "task:answer"), allowed: true,
		},
		{
			name: "scope cannot replace user permission", user: "user:mallory", object: "document:welcome",
			tuples: agentTaskEvidence("user:mallory", "agent:research", "task:answer"), allowed: false,
		},
		{
			name: "user assignment alone denies", user: "user:alice", object: "document:welcome",
			tuples: []Tuple{{User: "user:alice", Relation: RelationAssignee, Object: "task:answer"}}, allowed: false,
		},
		{
			name: "agent delegation alone denies", user: "user:alice", object: "document:welcome",
			tuples: []Tuple{{User: "user:alice", Relation: RelationDelegate, Object: "agent:research"}}, allowed: false,
		},
		{
			name: "task agent binding alone denies", user: "user:alice", object: "document:welcome",
			tuples: []Tuple{{User: "agent:research", Relation: RelationAgent, Object: "task:answer"}}, allowed: false,
		},
		{
			name: "revoked delegation denies", user: "user:alice", object: "document:welcome",
			tuples: withoutAgentTaskRelation(agentTaskEvidence("user:alice", "agent:research", "task:answer"), RelationDelegate), allowed: false,
		},
		{
			name: "expired assignment denies", user: "user:alice", object: "document:welcome",
			tuples: withoutAgentTaskRelation(agentTaskEvidence("user:alice", "agent:research", "task:answer"), RelationAssignee), allowed: false,
		},
		{
			name: "revoked task agent binding denies", user: "user:alice", object: "document:welcome",
			tuples: withoutAgentTaskRelation(agentTaskEvidence("user:alice", "agent:research", "task:answer"), RelationAgent), allowed: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := authorizer.Check(context.Background(), CheckRequest{
				User:                 test.user,
				Relation:             RelationCanView,
				Object:               test.object,
				AuthorizationModelID: localTestModelID,
				AgentTaskScope: &AgentTaskScope{
					User:                 test.user,
					Agent:                "agent:research",
					Task:                 "task:answer",
					AuthorizationModelID: localTestModelID,
					ContextualTuples:     test.tuples,
				},
			})
			if err != nil {
				t.Fatalf("scoped check: %v", err)
			}
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t", decision.Allowed, test.allowed)
			}
		})
	}

	assertLocalDecision(t, authorizer, "user:alice", RelationCanView, "document:welcome", true)
}

func TestLocalAgentTaskIntersectionCoversEveryProtectedType(t *testing.T) {
	authorizer := newEntityClaimTestAuthorizer(t)
	for _, object := range []string{
		"knowledge_base:graph",
		"document:source",
		"entity:visible-subject",
		"claim:visible",
	} {
		object := object
		t.Run(object, func(t *testing.T) {
			decision, err := authorizer.Check(context.Background(), CheckRequest{
				User:                 "user:alice",
				Relation:             RelationCanView,
				Object:               object,
				AuthorizationModelID: localTestModelID,
				AgentTaskScope:       completeAgentTaskScope("user:alice", localTestModelID),
			})
			if err != nil {
				t.Fatalf("scoped check: %v", err)
			}
			if !decision.Allowed {
				t.Fatal("complete user/agent/task intersection denied")
			}
		})
	}
}

func TestLocalAgentTaskIntersectionAuthorizesEditWithoutDowngrade(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User:                 "user:erin",
		Relation:             RelationCanEdit,
		Object:               "document:welcome",
		AuthorizationModelID: localTestModelID,
		AgentTaskScope:       completeAgentTaskScope("user:erin", localTestModelID),
	})
	if err != nil {
		t.Fatalf("scoped edit check: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("complete edit permission and user/agent/task intersection denied")
	}

	decision, err = authorizer.Check(context.Background(), CheckRequest{
		User:                 "user:alice",
		Relation:             RelationCanEdit,
		Object:               "document:welcome",
		AuthorizationModelID: localTestModelID,
		AgentTaskScope:       completeAgentTaskScope("user:alice", localTestModelID),
	})
	if err != nil {
		t.Fatalf("scoped denied edit check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("agent/task scope upgraded read-only user to editor")
	}
}

func TestAgentTaskScopeRejectsMismatchAndMalformedContext(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CheckRequest)
		wantErr error
	}{
		{
			name:    "scope user mismatch",
			mutate:  func(request *CheckRequest) { request.AgentTaskScope.User = "user:bob" },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "agent type mismatch",
			mutate:  func(request *CheckRequest) { request.AgentTaskScope.Agent = "user:research" },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "missing task",
			mutate:  func(request *CheckRequest) { request.AgentTaskScope.Task = "" },
			wantErr: ErrInvalidRequest,
		},
		{
			name: "scope model mismatch",
			mutate: func(request *CheckRequest) {
				request.AgentTaskScope.AuthorizationModelID = "01GXSB9YR785C4FYS3C0RTG7B2"
			},
			wantErr: ErrModelMismatch,
		},
		{
			name: "request model differs from authorizer",
			mutate: func(request *CheckRequest) {
				request.AuthorizationModelID = "01GXSB9YR785C4FYS3C0RTG7B2"
				request.AgentTaskScope.AuthorizationModelID = request.AuthorizationModelID
			},
			wantErr: ErrModelMismatch,
		},
		{
			name:    "relation mismatch",
			mutate:  func(request *CheckRequest) { request.Relation = RelationViewer },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "unprotected object",
			mutate:  func(request *CheckRequest) { request.Object = "organization:acme" },
			wantErr: ErrInvalidRequest,
		},
		{
			name: "context user mismatch",
			mutate: func(request *CheckRequest) {
				request.AgentTaskScope.ContextualTuples[0].User = "user:bob"
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "context agent mismatch",
			mutate: func(request *CheckRequest) {
				request.AgentTaskScope.ContextualTuples[1].User = "agent:other"
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "context task mismatch",
			mutate: func(request *CheckRequest) {
				request.AgentTaskScope.ContextualTuples[2].Object = "task:other"
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "duplicate contextual tuple",
			mutate: func(request *CheckRequest) {
				request.AgentTaskScope.ContextualTuples[1] = request.AgentTaskScope.ContextualTuples[0]
			},
			wantErr: ErrInvalidRequest,
		},
	}
	authorizer := newLocalTestAuthorizer(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := CheckRequest{
				User:                 "user:alice",
				Relation:             RelationCanView,
				Object:               "document:welcome",
				AuthorizationModelID: localTestModelID,
				AgentTaskScope:       completeAgentTaskScope("user:alice", localTestModelID),
			}
			test.mutate(&request)
			decision, err := authorizer.Check(context.Background(), request)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if decision.Allowed {
				t.Fatalf("malformed scope returned allow: %#v", decision)
			}
		})
	}

	for _, relation := range []string{RelationCanViewInTask, RelationCanEditInTask} {
		decision, err := authorizer.Check(context.Background(), CheckRequest{
			User:                 "user:alice",
			Relation:             relation,
			Object:               "document:welcome",
			AuthorizationModelID: localTestModelID,
		})
		if !errors.Is(err, ErrInvalidRequest) || decision.Allowed {
			t.Fatalf("direct internal relation %s decision=%#v error=%v", relation, decision, err)
		}
	}
}

func TestLocalAgentTaskBatchParity(t *testing.T) {
	authorizer := newLocalTestAuthorizer(t)
	complete := completeAgentTaskScope("user:alice", localTestModelID)
	missingDelegation := completeAgentTaskScope("user:alice", localTestModelID)
	missingDelegation.ContextualTuples = withoutAgentTaskRelation(missingDelegation.ContextualTuples, RelationDelegate)
	decisions, err := authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: localTestModelID,
		Checks: []BatchCheckItem{
			{
				CorrelationID: "complete", User: "user:alice", Relation: RelationCanView,
				Object: "document:welcome", AgentTaskScope: complete,
			},
			{
				CorrelationID: "revoked", User: "user:alice", Relation: RelationCanView,
				Object: "document:welcome", AgentTaskScope: missingDelegation,
			},
		},
	})
	if err != nil {
		t.Fatalf("batch check: %v", err)
	}
	want := []Decision{
		{CorrelationID: "complete", Allowed: true, AuthorizationModelID: localTestModelID},
		{CorrelationID: "revoked", Allowed: false, AuthorizationModelID: localTestModelID},
	}
	if !reflect.DeepEqual(decisions, want) {
		t.Fatalf("decisions = %#v, want %#v", decisions, want)
	}

	invalid := completeAgentTaskScope("user:alice", localTestModelID)
	invalid.Agent = "agent:other"
	decisions, err = authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: localTestModelID,
		Checks: []BatchCheckItem{{
			CorrelationID: "mismatch", User: "user:alice", Relation: RelationCanView,
			Object: "document:welcome", AgentTaskScope: invalid,
		}},
	})
	if !errors.Is(err, ErrInvalidRequest) || len(decisions) != 1 || decisions[0].Allowed {
		t.Fatalf("malformed batch decisions=%#v error=%v", decisions, err)
	}
}

func TestAgentTaskContextualTuplesCannotBePersisted(t *testing.T) {
	tuples := append(agentTaskEvidence("user:alice", "agent:research", "task:answer"), Tuple{
		User: "task:answer", Relation: RelationActiveTask, Object: "document:welcome",
	})
	for _, tuple := range tuples {
		if err := tuple.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("persistent tuple %+v error = %v, want %v", tuple, err, ErrInvalidRequest)
		}
	}
	if _, err := NewLocalAuthorizer(localTestModelID, tuples); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("persist contextual tuples error = %v, want %v", err, ErrInvalidRequest)
	}
	if err := (TupleWriteRequest{
		StoreID: openFGATestStoreID, AuthorizationModelID: localTestModelID, Writes: []Tuple{tuples[0]},
	}).Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("OpenFGA write preflight error = %v, want %v", err, ErrInvalidRequest)
	}
}

func completeAgentTaskScope(user, modelID string) *AgentTaskScope {
	return &AgentTaskScope{
		User:                 user,
		Agent:                "agent:research",
		Task:                 "task:answer",
		AuthorizationModelID: modelID,
		ContextualTuples:     agentTaskEvidence(user, "agent:research", "task:answer"),
	}
}

func agentTaskEvidence(user, agent, task string) []Tuple {
	return []Tuple{
		{User: user, Relation: RelationDelegate, Object: agent},
		{User: agent, Relation: RelationAgent, Object: task},
		{User: user, Relation: RelationAssignee, Object: task},
	}
}

func withoutAgentTaskRelation(tuples []Tuple, relation string) []Tuple {
	result := make([]Tuple, 0, len(tuples))
	for _, tuple := range tuples {
		if tuple.Relation != relation {
			result = append(result, tuple)
		}
	}
	return result
}
