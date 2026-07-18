package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestOpenFGAScopedCheckUsesPinnedModelAndContextualTuples(t *testing.T) {
	wantContext := []Tuple{
		{User: "user:alice", Relation: RelationDelegate, Object: "agent:research"},
		{User: "task:answer", Relation: RelationActiveTask, Object: "document:welcome"},
		{User: "agent:research", Relation: RelationAgent, Object: "task:answer"},
		{User: "user:alice", Relation: RelationAssignee, Object: "task:answer"},
	}
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			AuthorizationModelID string `json:"authorization_model_id"`
			Consistency          string `json:"consistency"`
			TupleKey             struct {
				User     string `json:"user"`
				Relation string `json:"relation"`
				Object   string `json:"object"`
			} `json:"tuple_key"`
			ContextualTuples struct {
				TupleKeys []Tuple `json:"tuple_keys"`
			} `json:"contextual_tuples"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body.AuthorizationModelID != openFGATestModelID {
			t.Errorf("authorization_model_id = %q", body.AuthorizationModelID)
		}
		if body.Consistency != "HIGHER_CONSISTENCY" {
			t.Errorf("consistency = %q", body.Consistency)
		}
		if body.TupleKey.User != "user:alice" || body.TupleKey.Relation != RelationCanViewInTask || body.TupleKey.Object != "document:welcome" {
			t.Errorf("tuple_key = %#v", body.TupleKey)
		}
		if !reflect.DeepEqual(body.ContextualTuples.TupleKeys, wantContext) {
			t.Errorf("contextual_tuples = %#v, want %#v", body.ContextualTuples.TupleKeys, wantContext)
		}
		writeJSON(t, writer, `{"allowed":true}`)
	}))

	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User:                 "user:alice",
		Relation:             RelationCanView,
		Object:               "document:welcome",
		AuthorizationModelID: openFGATestModelID,
		AgentTaskScope:       completeAgentTaskScope("user:alice", openFGATestModelID),
	})
	if err != nil {
		t.Fatalf("scoped check: %v", err)
	}
	if !decision.Allowed || decision.AuthorizationModelID != openFGATestModelID {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestOpenFGAScopedBatchUsesPerItemContextWithoutDowngrade(t *testing.T) {
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			AuthorizationModelID string `json:"authorization_model_id"`
			Consistency          string `json:"consistency"`
			Checks               []struct {
				TupleKey struct {
					User     string `json:"user"`
					Relation string `json:"relation"`
					Object   string `json:"object"`
				} `json:"tuple_key"`
				CorrelationID    string `json:"correlation_id"`
				ContextualTuples struct {
					TupleKeys []Tuple `json:"tuple_keys"`
				} `json:"contextual_tuples"`
			} `json:"checks"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(body.Checks) != 2 {
			t.Fatalf("checks = %d, want 2", len(body.Checks))
		}
		if body.AuthorizationModelID != openFGATestModelID || body.Consistency != "HIGHER_CONSISTENCY" {
			t.Errorf("batch pinning: authorization_model_id=%q consistency=%q", body.AuthorizationModelID, body.Consistency)
		}
		if body.Checks[0].TupleKey.Relation != RelationCanViewInTask || len(body.Checks[0].ContextualTuples.TupleKeys) != 4 {
			t.Errorf("scoped item = %#v", body.Checks[0])
		}
		if body.Checks[1].TupleKey.Relation != RelationCanView || len(body.Checks[1].ContextualTuples.TupleKeys) != 0 {
			t.Errorf("ordinary item = %#v", body.Checks[1])
		}
		writeJSON(t, writer, `{"result":{"scoped":{"allowed":true},"ordinary":{"allowed":true}}}`)
	}))

	decisions, err := authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: openFGATestModelID,
		Checks: []BatchCheckItem{
			{
				CorrelationID: "scoped", User: "user:alice", Relation: RelationCanView,
				Object: "document:welcome", AgentTaskScope: completeAgentTaskScope("user:alice", openFGATestModelID),
			},
			{
				CorrelationID: "ordinary", User: "user:alice", Relation: RelationCanView,
				Object: "document:welcome",
			},
		},
	})
	if err != nil {
		t.Fatalf("batch check: %v", err)
	}
	if len(decisions) != 2 || !decisions[0].Allowed || !decisions[1].Allowed {
		t.Fatalf("decisions = %#v", decisions)
	}
}

func TestOpenFGAScopedCheckRejectsMalformedContextBeforeRPC(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	tests := []struct {
		name    string
		mutate  func(*AgentTaskScope)
		wantErr error
	}{
		{
			name: "mismatched tuple",
			mutate: func(scope *AgentTaskScope) {
				scope.ContextualTuples[0].Object = "agent:other"
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "model mismatch",
			mutate: func(scope *AgentTaskScope) {
				scope.AuthorizationModelID = "01GXSB9YR785C4FYS3C0RTG7B2"
			},
			wantErr: ErrModelMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scope := completeAgentTaskScope("user:alice", openFGATestModelID)
			test.mutate(scope)
			decision, err := authorizer.Check(context.Background(), CheckRequest{
				User:                 "user:alice",
				Relation:             RelationCanView,
				Object:               "document:welcome",
				AuthorizationModelID: openFGATestModelID,
				AgentTaskScope:       scope,
			})
			if !errors.Is(err, test.wantErr) || decision.Allowed {
				t.Fatalf("decision=%#v error=%v, want %v", decision, err, test.wantErr)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("service calls = %d, want 0", calls.Load())
	}
}
