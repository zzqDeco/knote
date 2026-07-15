package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

const (
	openFGATestStoreID = "01GXSA8YR785C4FYS3C0RTG7B1"
	openFGATestModelID = "01GAHCE4YVKPQEKZQHT2R89MQV"
)

func TestOpenFGACheckUsesPinnedModelTokenAndConsistency(t *testing.T) {
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stores/"+openFGATestStoreID+"/check" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer knote-test-token" {
			t.Errorf("authorization header = %q", got)
		}
		var body struct {
			AuthorizationModelID string `json:"authorization_model_id"`
			Consistency          string `json:"consistency"`
			TupleKey             struct {
				Relation string `json:"relation"`
			} `json:"tuple_key"`
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
		if body.TupleKey.Relation != RelationCanView {
			t.Errorf("relation = %q, want %q", body.TupleKey.Relation, RelationCanView)
		}
		writeJSON(t, writer, `{"allowed":true}`)
	}))

	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User:                 "user:alice",
		Relation:             RelationCanView,
		Object:               "document:welcome",
		AuthorizationModelID: openFGATestModelID,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !decision.Allowed || decision.AuthorizationModelID != openFGATestModelID {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestOpenFGABatchPreservesInputOrderAndOrdinaryDeny(t *testing.T) {
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stores/"+openFGATestStoreID+"/batch-check" {
			t.Errorf("path = %q", request.URL.Path)
		}
		writeJSON(t, writer, `{"result":{"allow-item":{"allowed":true},"deny-item":{"allowed":false}}}`)
	}))
	request := testBatchRequest()
	decisions, err := authorizer.BatchCheck(context.Background(), request)
	if err != nil {
		t.Fatalf("batch check: %v", err)
	}
	want := []Decision{
		{CorrelationID: "deny-item", Allowed: false, AuthorizationModelID: openFGATestModelID},
		{CorrelationID: "allow-item", Allowed: true, AuthorizationModelID: openFGATestModelID},
	}
	if !reflect.DeepEqual(decisions, want) {
		t.Fatalf("decisions = %#v, want %#v", decisions, want)
	}
}

func TestOpenFGABatchAtPhysicalLimitUsesOneRequest(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/stores/"+openFGATestStoreID+"/batch-check" {
			t.Errorf("path = %q", request.URL.Path)
		}
		var body struct {
			Checks []struct {
				CorrelationID string `json:"correlation_id"`
			} `json:"checks"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(body.Checks) != MaxBatchChecks {
			t.Errorf("physical batch size = %d, want %d", len(body.Checks), MaxBatchChecks)
		}
		results := make(map[string]map[string]bool, len(body.Checks))
		for _, check := range body.Checks {
			results[check.CorrelationID] = map[string]bool{"allowed": true}
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]any{"result": results}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))

	request := BatchCheckRequest{
		AuthorizationModelID: openFGATestModelID,
		Checks:               make([]BatchCheckItem, MaxBatchChecks),
	}
	for index := range request.Checks {
		request.Checks[index] = BatchCheckItem{
			CorrelationID: fmt.Sprintf("check-%d", index), User: "user:alice",
			Relation: RelationCanView, Object: "document:welcome",
		}
	}
	decisions, err := authorizer.BatchCheck(context.Background(), request)
	if err != nil {
		t.Fatalf("batch check: %v", err)
	}
	if len(decisions) != MaxBatchChecks {
		t.Fatalf("decision count = %d, want %d", len(decisions), MaxBatchChecks)
	}
	for _, decision := range decisions {
		if !decision.Allowed {
			t.Fatalf("physical-limit batch returned deny: %#v", decision)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("physical RPCs = %d, want 1", calls.Load())
	}
}

func TestOpenFGABatchRejectsFiftyOneChecksWithoutCallingService(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	checks := make([]BatchCheckItem, MaxBatchChecks+1)
	for index := range checks {
		checks[index] = BatchCheckItem{
			CorrelationID: fmt.Sprintf("check-%d", index), User: "user:alice",
			Relation: RelationCanView, Object: "document:welcome",
		}
	}
	if len(checks) != 51 {
		t.Fatalf("regression requires 51 checks, got %d", len(checks))
	}
	decisions, err := authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: openFGATestModelID,
		Checks:               checks,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized batch error = %v", err)
	}
	if decisions != nil {
		t.Fatalf("oversized batch allocated decisions: %#v", decisions)
	}
	if calls.Load() != 0 {
		t.Fatalf("service calls = %d, want 0", calls.Load())
	}
}

func TestOpenFGABatchRejectsPartialExtraErrorAndMalformedResults(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  error
	}{
		{
			name:     "partial",
			response: `{"result":{"deny-item":{"allowed":false}}}`,
			wantErr:  ErrIncompleteResponse,
		},
		{
			name:     "extra correlation id",
			response: `{"result":{"deny-item":{"allowed":false},"unexpected":{"allowed":true}}}`,
			wantErr:  ErrIncompleteResponse,
		},
		{
			name:     "per-item error is not ordinary deny",
			response: `{"result":{"deny-item":{"allowed":false,"error":{"input_error":"validation_error","message":"invalid check"}},"allow-item":{"allowed":true}}}`,
			wantErr:  ErrIncompleteResponse,
		},
		{
			name:     "missing allowed",
			response: `{"result":{"deny-item":{},"allow-item":{"allowed":true}}}`,
			wantErr:  ErrMalformedResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writeJSON(t, writer, test.response)
			}))
			decisions, err := authorizer.BatchCheck(context.Background(), testBatchRequest())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			assertAllDenied(t, decisions)
		})
	}
}

func TestOpenFGATimeoutAndServiceFailureDeny(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		authorizer := newTestOpenFGAWithTimeout(t, 20*time.Millisecond, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			select {
			case <-request.Context().Done():
			case <-time.After(200 * time.Millisecond):
			}
		}))
		decision, err := authorizer.Check(context.Background(), CheckRequest{
			User:                 "user:alice",
			Relation:             RelationCanView,
			Object:               "document:welcome",
			AuthorizationModelID: openFGATestModelID,
		})
		if !errors.Is(err, ErrTimeout) || decision.Allowed {
			t.Fatalf("decision=%#v error=%v", decision, err)
		}
	})

	t.Run("service failure", func(t *testing.T) {
		authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"code":"unavailable","message":"temporarily unavailable"}`))
		}))
		decisions, err := authorizer.BatchCheck(context.Background(), testBatchRequest())
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
		assertAllDenied(t, decisions)
	})
}

func TestOpenFGAModelMismatchDeniesWithoutCallingService(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User:                 "user:alice",
		Relation:             RelationCanView,
		Object:               "document:welcome",
		AuthorizationModelID: "01GXSB9YR785C4FYS3C0RTG7B2",
	})
	if !errors.Is(err, ErrModelMismatch) || decision.Allowed {
		t.Fatalf("decision=%#v error=%v", decision, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("service calls = %d, want 0", calls.Load())
	}
}

func TestOpenFGAConfigIsExplicitAndTokenOnly(t *testing.T) {
	t.Setenv(APITokenEnv, "")
	_, err := NewOpenFGA(testOpenFGAConfig("http://127.0.0.1"))
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing token error = %v", err)
	}

	t.Setenv(APITokenEnv, "token")
	tests := []OpenFGAConfig{
		{Endpoint: "", StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID, Timeout: time.Second},
		{Endpoint: "http://openfga.example.com", StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID, Timeout: time.Second},
		{Endpoint: "http://127.0.0.1", StoreID: "latest", AuthorizationModelID: openFGATestModelID, Timeout: time.Second},
		{Endpoint: "http://127.0.0.1", StoreID: openFGATestStoreID, AuthorizationModelID: "latest", Timeout: time.Second},
		{Endpoint: "http://127.0.0.1", StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID, Timeout: 0},
	}
	for index, config := range tests {
		if _, err := NewOpenFGA(config); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("config %d error = %v", index, err)
		}
	}
}

func newTestOpenFGA(t *testing.T, handler http.Handler) *OpenFGAAuthorizer {
	t.Helper()
	return newTestOpenFGAWithTimeout(t, time.Second, handler)
}

func newTestOpenFGAWithTimeout(t *testing.T, timeout time.Duration, handler http.Handler) *OpenFGAAuthorizer {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv(APITokenEnv, "knote-test-token")
	t.Setenv("OPENFGA_API_TOKEN", "must-not-be-used")
	config := testOpenFGAConfig(server.URL)
	config.Timeout = timeout
	authorizer, err := NewOpenFGA(config)
	if err != nil {
		t.Fatalf("new OpenFGA authorizer: %v", err)
	}
	return authorizer
}

func testOpenFGAConfig(endpoint string) OpenFGAConfig {
	return OpenFGAConfig{
		Endpoint:             endpoint,
		StoreID:              openFGATestStoreID,
		AuthorizationModelID: openFGATestModelID,
		Timeout:              time.Second,
		Consistency:          ConsistencyHigherConsistency,
	}
}

func testBatchRequest() BatchCheckRequest {
	return BatchCheckRequest{
		AuthorizationModelID: openFGATestModelID,
		Checks: []BatchCheckItem{
			{CorrelationID: "deny-item", User: "user:mallory", Relation: RelationCanView, Object: "document:welcome"},
			{CorrelationID: "allow-item", User: "user:alice", Relation: RelationCanView, Object: "document:welcome"},
		},
	}
}

func assertAllDenied(t *testing.T, decisions []Decision) {
	t.Helper()
	if len(decisions) != 2 {
		t.Fatalf("decision count = %d, want 2", len(decisions))
	}
	for _, decision := range decisions {
		if decision.Allowed {
			t.Fatalf("failure returned allow decision: %#v", decisions)
		}
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, body string) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if _, err := fmt.Fprint(writer, body); err != nil {
		t.Errorf("write response: %v", err)
	}
}
