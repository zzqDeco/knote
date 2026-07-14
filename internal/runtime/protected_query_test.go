package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const protectedQueryRuntimeCanary = "HIDDEN_BODY_LABEL_PATH_CARDINALITY_CANARY"

func TestProjectProtectedQueryMakesHiddenAndAbsentExactlyEqual(t *testing.T) {
	hidden := ProjectProtectedQuery(ProtectedQueryProjectionInput{
		Outcome:   ProtectedQueryInternalHidden,
		Operation: protocol.ProtectedQueryOperationPage,
		Visible: protocol.ProtectedQueryVisibleResult{
			Count: 41, Exists: true,
			Autocomplete: []string{protectedQueryRuntimeCanary},
			Facets: []protocol.ProtectedQueryFacet{{
				Name:   protectedQueryRuntimeCanary,
				Values: []protocol.ProtectedQueryFacetValue{{Value: protectedQueryRuntimeCanary, Count: 41}},
			}},
			Page: protocol.ProtectedQueryPage{
				Items:         []protocol.ProtectedQueryPageItem{{Value: protectedQueryRuntimeCanary}},
				NextPageToken: protectedQueryRuntimeCanary,
			},
		},
		Cause:       errors.New("hidden provider failure: " + protectedQueryRuntimeCanary),
		Diagnostics: map[string]any{"resource_id": protectedQueryRuntimeCanary, "cardinality": 41},
		Sensitive:   struct{ Path string }{Path: "/secret/" + protectedQueryRuntimeCanary},
	})
	absent := ProjectProtectedQuery(ProtectedQueryProjectionInput{
		Outcome:     ProtectedQueryInternalAbsent,
		Operation:   protocol.ProtectedQueryOperationPage,
		Cause:       errors.New("ordinary miss"),
		Diagnostics: map[string]any{"provider": "different"},
	})
	crossTenant := ProjectProtectedQuery(ProtectedQueryProjectionInput{
		Outcome: ProtectedQueryInternalCrossTenant, Operation: protocol.ProtectedQueryOperationPage,
		Cause: errors.New("cross-tenant canary: " + protectedQueryRuntimeCanary),
	})

	if !reflect.DeepEqual(hidden, absent) {
		t.Fatalf("hidden and absent public shapes differ:\nhidden=%+v\nabsent=%+v", hidden, absent)
	}
	hiddenJSON := protectedQueryRuntimeJSON(t, hidden)
	absentJSON := protectedQueryRuntimeJSON(t, absent)
	if !bytes.Equal(hiddenJSON, absentJSON) {
		t.Fatalf("hidden and absent JSON differ:\n%s\n%s", hiddenJSON, absentJSON)
	}
	if !reflect.DeepEqual(hidden, crossTenant) || !bytes.Equal(hiddenJSON, protectedQueryRuntimeJSON(t, crossTenant)) {
		t.Fatalf("cross-tenant and hidden public shapes differ:\nhidden=%+v\ncross-tenant=%+v", hidden, crossTenant)
	}
	assertProtectedQueryRuntimeNoCanary(t, hidden)
	if err := hidden.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProjectProtectedQueryUsesFixedErrorsAndDropsInternalDetails(t *testing.T) {
	tests := []struct {
		name    string
		outcome ProtectedQueryInternalOutcome
		code    protocol.ProtectedQueryErrorCode
	}{
		{name: "hidden", outcome: ProtectedQueryInternalHidden, code: protocol.ProtectedQueryErrorNotFound},
		{name: "absent", outcome: ProtectedQueryInternalAbsent, code: protocol.ProtectedQueryErrorNotFound},
		{name: "cross tenant", outcome: ProtectedQueryInternalCrossTenant, code: protocol.ProtectedQueryErrorNotFound},
		{name: "denied", outcome: ProtectedQueryInternalDenied, code: protocol.ProtectedQueryErrorPermissionDenied},
		{name: "provider", outcome: ProtectedQueryInternalProviderFailure, code: protocol.ProtectedQueryErrorProviderUnavailable},
		{name: "unknown", outcome: "unknown_" + protectedQueryRuntimeCanary, code: protocol.ProtectedQueryErrorProviderUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := ProjectProtectedQuery(ProtectedQueryProjectionInput{
				Outcome: test.outcome, Operation: protocol.ProtectedQueryOperationAutocomplete,
				Cause: errors.New("provider: " + protectedQueryRuntimeCanary),
				Diagnostics: map[string]any{
					"trace": protectedQueryRuntimeCanary, "resource_ids": []string{protectedQueryRuntimeCanary},
				},
				Sensitive: protectedQueryRuntimeCanary,
			})
			if envelope.Error == nil || envelope.Error.Code != test.code {
				t.Fatalf("public error = %+v, want %s", envelope.Error, test.code)
			}
			if err := envelope.Validate(); err != nil {
				t.Fatal(err)
			}
			assertProtectedQueryRuntimeNoCanary(t, envelope)
		})
	}
}

func TestProjectProtectedQueryAllowsOnlyTypedMetadataAndVisibleResult(t *testing.T) {
	plan := protectedQueryRuntimePlan(t)
	planIdentity, err := protocol.NewProtectedTraversalPlanIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	authorization := testAuthorizationContext("sess_protected_query")
	fingerprint, err := protocol.NewVisibilityFingerprint(authorization, plan.ProjectionVersion)
	if err != nil {
		t.Fatal(err)
	}
	input := ProtectedQueryProjectionInput{
		Outcome:   ProtectedQueryInternalAllowed,
		Operation: protocol.ProtectedQueryOperationQuery,
		Visible: protocol.ProtectedQueryVisibleResult{
			Count: 2, Exists: true,
			Autocomplete: []string{"zeta", "alpha"},
			Facets: []protocol.ProtectedQueryFacet{
				{Name: "kind", Values: []protocol.ProtectedQueryFacetValue{{Value: "summary", Count: 1}, {Value: "outline", Count: 1}}},
				{Name: "author", Values: []protocol.ProtectedQueryFacetValue{{Value: "alice", Count: 2}}},
			},
			Page: protocol.ProtectedQueryPage{
				Items:         []protocol.ProtectedQueryPageItem{{Value: "first"}, {Value: "second"}},
				NextPageToken: "pqt1.a2lk.b2Zmc2V0.c2lnbmF0dXJl",
			},
		},
		ProjectionVersion: plan.ProjectionVersion, VisibilityFingerprint: fingerprint,
		Plan: &planIdentity, LatencyBucket: ProtectedQueryLatencyBucketFor(12 * time.Millisecond),
		Cause: errors.New(protectedQueryRuntimeCanary),
		Diagnostics: map[string]any{
			"body": protectedQueryRuntimeCanary, "path": "/secret/path", "hidden_count": 99,
		},
		Sensitive: map[string]string{"label": protectedQueryRuntimeCanary},
	}

	envelope := ProjectProtectedQuery(input)
	if envelope.Error != nil {
		t.Fatalf("allowed projection failed closed: %+v", envelope.Error)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(envelope.Result.Autocomplete, []string{"alpha", "zeta"}) {
		t.Fatalf("autocomplete is not canonical: %+v", envelope.Result.Autocomplete)
	}
	if envelope.Result.Facets[0].Name != "author" || envelope.Result.Facets[1].Values[0].Value != "outline" {
		t.Fatalf("facets are not canonical: %+v", envelope.Result.Facets)
	}
	if envelope.Metadata.Debug.Plan == input.Plan {
		t.Fatal("public metadata retained caller-owned plan identity pointer")
	}
	if envelope.Metadata.Metrics.LatencyBucket != protocol.ProtectedQueryLatencyUnder50MS {
		t.Fatalf("latency bucket = %s", envelope.Metadata.Metrics.LatencyBucket)
	}
	assertProtectedQueryRuntimeNoCanary(t, envelope)
	assertProtectedQueryRuntimeMetadataKeys(t, envelope)
}

func TestProjectProtectedQueryFailsClosedOnMalformedAllowedSurface(t *testing.T) {
	input := ProtectedQueryProjectionInput{
		Outcome:   ProtectedQueryInternalAllowed,
		Operation: protocol.ProtectedQueryOperationPage,
		Visible: protocol.ProtectedQueryVisibleResult{
			Count: 1, Exists: true,
			Autocomplete: []string{protectedQueryRuntimeCanary},
			Facets:       []protocol.ProtectedQueryFacet{},
			Page:         protocol.ProtectedQueryPage{Items: []protocol.ProtectedQueryPageItem{}},
		},
		ProjectionVersion: protectedQueryRuntimeCanary,
		Diagnostics:       map[string]any{"provider_error": protectedQueryRuntimeCanary},
	}
	envelope := ProjectProtectedQuery(input)
	if envelope.Error == nil || envelope.Error.Code != protocol.ProtectedQueryErrorProviderUnavailable {
		t.Fatalf("malformed allowed result did not fail closed: %+v", envelope)
	}
	assertProtectedQueryRuntimeNoCanary(t, envelope)
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedQueryLatencyBucketsAreFixed(t *testing.T) {
	tests := map[time.Duration]protocol.ProtectedQueryLatencyBucket{
		0:                      protocol.ProtectedQueryLatencyUnder10MS,
		10 * time.Millisecond:  protocol.ProtectedQueryLatencyUnder50MS,
		50 * time.Millisecond:  protocol.ProtectedQueryLatencyUnder250MS,
		250 * time.Millisecond: protocol.ProtectedQueryLatencyOver250MS,
	}
	for elapsed, want := range tests {
		if got := ProtectedQueryLatencyBucketFor(elapsed); got != want {
			t.Fatalf("bucket(%s) = %s, want %s", elapsed, got, want)
		}
	}
}

func TestProtectedQueryTimingGateBoundsHiddenAbsentAndCrossTenantCohorts(t *testing.T) {
	budget := DefaultProtectedQueryTimingBudget()
	tests := []struct {
		outcome ProtectedQueryInternalOutcome
		elapsed time.Duration
	}{
		{outcome: ProtectedQueryInternalHidden, elapsed: 7 * time.Millisecond},
		{outcome: ProtectedQueryInternalAbsent, elapsed: 31 * time.Millisecond},
		{outcome: ProtectedQueryInternalCrossTenant, elapsed: 49 * time.Millisecond},
	}
	completed := make([]time.Duration, len(tests))
	for index, test := range tests {
		waited := time.Duration(0)
		err := EnforceProtectedQueryTiming(
			context.Background(), budget, test.outcome, test.elapsed,
			func(_ context.Context, delay time.Duration) error {
				waited = delay
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		completed[index] = test.elapsed + waited
	}
	for index, duration := range completed {
		if duration < budget.Floor || duration > budget.Floor+budget.MaxVariance {
			t.Fatalf("cohort %d completed at %s outside [%s,%s]", index, duration, budget.Floor, budget.Floor+budget.MaxVariance)
		}
		if index > 0 && absDuration(duration-completed[0]) > budget.MaxVariance {
			t.Fatalf("cohort variance = %s, budget = %s", absDuration(duration-completed[0]), budget.MaxVariance)
		}
	}
	if err := EnforceProtectedQueryTiming(
		context.Background(), budget, ProtectedQueryInternalHidden,
		budget.Floor+budget.MaxVariance+time.Nanosecond,
		func(context.Context, time.Duration) error { return nil },
	); !errors.Is(err, ErrProtectedQueryTimingBudgetExceeded) {
		t.Fatalf("over-budget hidden query error = %v", err)
	}
	if delay, err := budget.ReleaseDelay(ProtectedQueryInternalAllowed, time.Millisecond); err != nil || delay != 0 {
		t.Fatalf("allowed query timing gate = %s, %v", delay, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := EnforceProtectedQueryTiming(
		canceled, budget, ProtectedQueryInternalHidden, 0,
		func(context.Context, time.Duration) error { return nil },
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled timing gate error = %v", err)
	}
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func protectedQueryRuntimePlan(t *testing.T) protocol.TraversalPlan {
	t.Helper()
	descriptor, err := protocol.CompileGraphQuery(protocol.GraphQuery{
		Version: protocol.GraphQueryContractVersion, Operation: protocol.GraphOperationTraverseClaims,
		ProjectionVersion: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IdentityVersion: protocol.GraphBindingContractVersion,
		StartResourceIDs: []protocol.ResourceID{"res_88888888888888888888888888888888"},
		PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateDerivedFrom},
		ResourceKinds:    []protocol.GraphResourceKind{protocol.GraphResourceDerivedArtifact},
		Direction:        protocol.TraversalOutbound,
		Limits: protocol.TraversalLimits{
			MaxDepth: 2, MaxFrontierWidth: 32, MaxCandidatesPerHop: 64,
			MaxTotalResources: 128, MaxBatchChecks: 16, MaxWallClockMillis: 5_000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.Parameters
}

func assertProtectedQueryRuntimeNoCanary(t *testing.T, value any) {
	t.Helper()
	encoded := protectedQueryRuntimeJSON(t, value)
	for _, canary := range []string{
		protectedQueryRuntimeCanary,
		"/secret/path",
		"res_ffffffffffffffffffffffffffffffff",
		"hidden_count",
		"resource_ids",
	} {
		if bytes.Contains(encoded, []byte(canary)) {
			t.Fatalf("public protected query envelope exposed %q: %s", canary, encoded)
		}
	}
}

func assertProtectedQueryRuntimeMetadataKeys(t *testing.T, envelope protocol.ProtectedQueryEnvelope) {
	t.Helper()
	encoded := protectedQueryRuntimeJSON(t, envelope.Metadata)
	var raw map[string]map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"trace":   {"operation", "outcome"},
		"debug":   {"plan", "projection_version", "visibility_fingerprint"},
		"metrics": {"latency_bucket", "operation", "outcome"},
		"audit":   {"action", "decision"},
	}
	for surface, keys := range want {
		if len(raw[surface]) != len(keys) {
			t.Fatalf("%s metadata keys = %+v, want %v", surface, raw[surface], keys)
		}
		for _, key := range keys {
			if _, ok := raw[surface][key]; !ok {
				t.Fatalf("%s metadata omitted allowlisted key %q: %s", surface, key, encoded)
			}
		}
	}
	for _, forbidden := range []string{"body", "label", "path", "resource_id", "cardinality", "cause", "stack"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("metadata exposed forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func protectedQueryRuntimeJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
