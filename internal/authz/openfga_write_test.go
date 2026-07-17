package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync/atomic"
	"testing"
)

func TestOpenFGAApplyTupleChangesPinsRevisionAndIgnoresRetryConflicts(t *testing.T) {
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stores/"+openFGATestStoreID+"/write" {
			t.Errorf("path = %q", request.URL.Path)
		}
		var body struct {
			AuthorizationModelID string `json:"authorization_model_id"`
			Writes               struct {
				OnDuplicate string  `json:"on_duplicate"`
				TupleKeys   []Tuple `json:"tuple_keys"`
			} `json:"writes"`
			Deletes struct {
				OnMissing string  `json:"on_missing"`
				TupleKeys []Tuple `json:"tuple_keys"`
			} `json:"deletes"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body.AuthorizationModelID != openFGATestModelID {
			t.Errorf("authorization_model_id = %q", body.AuthorizationModelID)
		}
		if body.Writes.OnDuplicate != "ignore" || body.Deletes.OnMissing != "ignore" {
			t.Errorf("conflict behavior = duplicate:%q missing:%q", body.Writes.OnDuplicate, body.Deletes.OnMissing)
		}
		if len(body.Writes.TupleKeys) != 1 || len(body.Deletes.TupleKeys) != 1 {
			t.Errorf("write/delete tuple counts = %d/%d", len(body.Writes.TupleKeys), len(body.Deletes.TupleKeys))
		}
		writeJSON(t, writer, `{}`)
	}))
	request := TupleWriteRequest{
		StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID,
		Writes:  []Tuple{{User: "entity:new", Relation: RelationSubject, Object: "claim:changed"}},
		Deletes: []Tuple{{User: "entity:old", Relation: RelationSubject, Object: "claim:changed"}},
	}
	if err := authorizer.ApplyTupleChanges(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFGAApplyTupleChangesUsesBoundedSequentialTransactions(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		var body struct {
			Writes struct {
				TupleKeys []Tuple `json:"tuple_keys"`
			} `json:"writes"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(body.Writes.TupleKeys) > MaxTupleOperationsPerWrite {
			t.Errorf("batch %d has %d operations", call, len(body.Writes.TupleKeys))
		}
		if call == 2 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"code":"unavailable","message":"injected"}`))
			return
		}
		writeJSON(t, writer, `{}`)
	}))
	writes := make([]Tuple, MaxTupleOperationsPerWrite+1)
	for index := range writes {
		writes[index] = Tuple{
			User: "entity:subject", Relation: RelationSubject,
			Object: fmt.Sprintf("claim:item-%03d", index),
		}
	}
	sort.Slice(writes, func(i, j int) bool { return tupleLess(writes[i], writes[j]) })
	err := authorizer.ApplyTupleChanges(context.Background(), TupleWriteRequest{
		StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID,
		Writes: writes,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second transaction error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("transaction calls = %d, want 2", calls.Load())
	}
}

func TestOpenFGAApplyTupleChangesRejectsRevisionMismatchWithoutWrite(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	err := authorizer.ApplyTupleChanges(context.Background(), TupleWriteRequest{
		StoreID: openFGATestStoreID, AuthorizationModelID: "01GXSB9YR785C4FYS3C0RTG7B2",
		Writes: []Tuple{{User: "entity:subject", Relation: RelationSubject, Object: "claim:item"}},
	})
	if !errors.Is(err, ErrModelMismatch) {
		t.Fatalf("model mismatch error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("mismatched revision issued %d writes", calls.Load())
	}
}

func TestOpenFGAApplyTupleChangesRejectsIdentityControlTuplesWithoutWrite(t *testing.T) {
	tests := []struct {
		name   string
		tuple  Tuple
		delete bool
	}{
		{
			name:  "write claim lock",
			tuple: Tuple{User: identityClaimUser, Relation: identityClaimRelation, Object: identityControlObject},
		},
		{
			name:   "delete tenant binding",
			tuple:  Tuple{User: identityTenantType + ":tenant-acme", Relation: identityTenantRelation, Object: identityControlObject},
			delete: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			authorizer := newTestOpenFGA(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				calls.Add(1)
			}))
			request := TupleWriteRequest{
				StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID,
			}
			if test.delete {
				request.Deletes = []Tuple{test.tuple}
			} else {
				request.Writes = []Tuple{test.tuple}
			}
			err := authorizer.ApplyTupleChanges(context.Background(), request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ApplyTupleChanges error = %v, want %v", err, ErrInvalidRequest)
			}
			if calls.Load() != 0 {
				t.Fatalf("rejected control tuple issued %d HTTP writes", calls.Load())
			}
		})
	}
}
