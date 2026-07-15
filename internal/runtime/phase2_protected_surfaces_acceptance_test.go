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

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	phase2ProtectedCanary  = "PHASE2_HIDDEN_BODY_PATH_LABEL_CARDINALITY_CANARY"
	phase2ProtectedModelID = "01J00000000000000000000000"
	phase2ProtectedVersion = "prj_22222222222222222222222222222222"
)

func TestPhase2ProtectedSurfacesAcceptanceAreTypedAndCanaryFree(t *testing.T) {
	authorization := phase2ProtectedAuthorization("tenant-phase2", "sess-phase2-surfaces", "request-phase2-surfaces")
	plan := phase2ProtectedTraversalPlan(t)
	planIdentity, err := protocol.NewProtectedTraversalPlanIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := protocol.NewVisibilityFingerprint(authorization, plan.ProjectionVersion)
	if err != nil {
		t.Fatal(err)
	}

	codec, err := protocol.NewProtectedPageTokenCodec("phase2-key", []protocol.ProtectedPageTokenKey{{
		ID: "phase2-key", Secret: bytes.Repeat([]byte{0x42}, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, time.July, 15, 8, 0, 0, 0, time.UTC)
	tokenContext := protocol.ProtectedPageTokenContext{
		Authorization: authorization, VisibilityFingerprint: fingerprint,
		ProjectionVersion: plan.ProjectionVersion, TraversalPlan: plan,
		RevocationWatermark: "revocation-phase2-v1",
	}
	pageToken, err := codec.Encode(protocol.ProtectedPageTokenRequest{
		Context: tokenContext, Position: 2, Limit: 2,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	position, err := codec.Decode(pageToken, tokenContext, issuedAt.Add(time.Minute))
	if err != nil || position != (protocol.ProtectedPagePosition{Position: 2, Limit: 2}) {
		t.Fatalf("page token round trip = %+v, %v", position, err)
	}

	crossTenant := tokenContext
	crossTenant.Authorization.TenantID = "tenant-other"
	crossTenant.Authorization.RequestID = "request-phase2-cross-tenant"
	crossTenant.VisibilityFingerprint, err = protocol.NewVisibilityFingerprint(
		crossTenant.Authorization, crossTenant.ProjectionVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(pageToken, crossTenant, issuedAt.Add(time.Minute)); !errors.Is(err, protocol.ErrInvalidProtectedPageToken) {
		t.Fatalf("cross-tenant page token error = %v", err)
	}
	revoked := tokenContext
	revoked.RevocationWatermark = "revocation-phase2-v2"
	if _, err := codec.Decode(pageToken, revoked, issuedAt.Add(time.Minute)); !errors.Is(err, protocol.ErrInvalidProtectedPageToken) {
		t.Fatalf("revoked page token error = %v", err)
	}

	empty := protocol.EmptyProtectedQueryVisibleResult()
	tests := []struct {
		name      string
		operation protocol.ProtectedQueryOperation
		visible   protocol.ProtectedQueryVisibleResult
	}{
		{name: "count", operation: protocol.ProtectedQueryOperationCount, visible: phase2VisibleResult(empty, 3)},
		{name: "exists", operation: protocol.ProtectedQueryOperationExists, visible: phase2VisibleResult(empty, 1)},
		{
			name: "autocomplete", operation: protocol.ProtectedQueryOperationAutocomplete,
			visible: func() protocol.ProtectedQueryVisibleResult {
				result := phase2VisibleResult(empty, 2)
				result.Autocomplete = []string{"zeta", "alpha"}
				return result
			}(),
		},
		{
			name: "pagination", operation: protocol.ProtectedQueryOperationPage,
			visible: func() protocol.ProtectedQueryVisibleResult {
				result := phase2VisibleResult(empty, 3)
				result.Page = protocol.ProtectedQueryPage{
					Items:         []protocol.ProtectedQueryPageItem{{Value: "first"}, {Value: "second"}},
					NextPageToken: pageToken,
				}
				return result
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := ProjectProtectedQuery(ProtectedQueryProjectionInput{
				Outcome: ProtectedQueryInternalAllowed, Operation: test.operation, Visible: test.visible,
				ProjectionVersion: plan.ProjectionVersion, VisibilityFingerprint: fingerprint,
				Plan: &planIdentity, LatencyBucket: protocol.ProtectedQueryLatencyUnder50MS,
				Cause: errors.New("provider cause: " + phase2ProtectedCanary),
				Diagnostics: map[string]any{
					"path":         "/private/" + phase2ProtectedCanary,
					"hidden_count": 97,
					"resource_ids": []string{"res_ffffffffffffffffffffffffffffffff"},
				},
				Sensitive: map[string]string{"label": phase2ProtectedCanary},
			})
			if err := envelope.Validate(); err != nil {
				t.Fatal(err)
			}
			if envelope.Error != nil || envelope.Metadata.Trace.Operation != test.operation ||
				envelope.Metadata.Trace.Outcome != protocol.ProtectedQueryOutcomeOK ||
				envelope.Metadata.Metrics.Operation != test.operation ||
				envelope.Metadata.Metrics.Outcome != protocol.ProtectedQueryOutcomeOK ||
				envelope.Metadata.Metrics.LatencyBucket != protocol.ProtectedQueryLatencyUnder50MS ||
				envelope.Metadata.Audit.Action != "protected_query" ||
				envelope.Metadata.Audit.Decision != protocol.ProtectedQueryOutcomeOK {
				t.Fatalf("typed trace/metrics/audit metadata = %+v", envelope.Metadata)
			}
			if envelope.Metadata.Debug.ProjectionVersion != plan.ProjectionVersion ||
				envelope.Metadata.Debug.VisibilityFingerprint != fingerprint ||
				envelope.Metadata.Debug.Plan == nil ||
				!reflect.DeepEqual(*envelope.Metadata.Debug.Plan, planIdentity) {
				t.Fatalf("typed debug metadata = %+v", envelope.Metadata.Debug)
			}
			if test.operation == protocol.ProtectedQueryOperationAutocomplete &&
				!reflect.DeepEqual(envelope.Result.Autocomplete, []string{"alpha", "zeta"}) {
				t.Fatalf("canonical autocomplete = %+v", envelope.Result.Autocomplete)
			}
			phase2AssertProtectedSurfaceCanaryFree(t, envelope)
		})
	}

	errorInputs := []struct {
		name    string
		outcome ProtectedQueryInternalOutcome
		code    protocol.ProtectedQueryErrorCode
	}{
		{name: "hidden", outcome: ProtectedQueryInternalHidden, code: protocol.ProtectedQueryErrorNotFound},
		{name: "absent", outcome: ProtectedQueryInternalAbsent, code: protocol.ProtectedQueryErrorNotFound},
		{name: "cross tenant", outcome: ProtectedQueryInternalCrossTenant, code: protocol.ProtectedQueryErrorNotFound},
		{name: "denied", outcome: ProtectedQueryInternalDenied, code: protocol.ProtectedQueryErrorPermissionDenied},
		{name: "provider", outcome: ProtectedQueryInternalProviderFailure, code: protocol.ProtectedQueryErrorProviderUnavailable},
	}
	var indistinguishable [][]byte
	for _, test := range errorInputs {
		t.Run("error "+test.name, func(t *testing.T) {
			envelope := ProjectProtectedQuery(ProtectedQueryProjectionInput{
				Outcome: test.outcome, Operation: protocol.ProtectedQueryOperationPage,
				Visible: protocol.ProtectedQueryVisibleResult{
					Count: 97, Exists: true, Autocomplete: []string{phase2ProtectedCanary},
					Facets: []protocol.ProtectedQueryFacet{{Name: phase2ProtectedCanary}},
					Page: protocol.ProtectedQueryPage{
						Items:         []protocol.ProtectedQueryPageItem{{Value: phase2ProtectedCanary}},
						NextPageToken: phase2ProtectedCanary,
					},
				},
				ProjectionVersion: phase2ProtectedCanary, Plan: &planIdentity,
				Cause:       errors.New(phase2ProtectedCanary),
				Diagnostics: map[string]any{"body": phase2ProtectedCanary, "count": 97},
				Sensitive:   phase2ProtectedCanary,
			})
			if err := envelope.Validate(); err != nil {
				t.Fatal(err)
			}
			if envelope.Error == nil || envelope.Error.Code != test.code ||
				!reflect.DeepEqual(envelope.Result, protocol.EmptyProtectedQueryVisibleResult()) {
				t.Fatalf("fixed public error envelope = %+v", envelope)
			}
			if envelope.Metadata.Debug != (protocol.ProtectedQueryDebugMetadata{}) ||
				envelope.Metadata.Audit.Action != "protected_query" ||
				envelope.Metadata.Audit.Decision != envelope.Metadata.Trace.Outcome {
				t.Fatalf("error metadata = %+v", envelope.Metadata)
			}
			phase2AssertProtectedSurfaceCanaryFree(t, envelope)
			if test.outcome == ProtectedQueryInternalHidden || test.outcome == ProtectedQueryInternalAbsent ||
				test.outcome == ProtectedQueryInternalCrossTenant {
				indistinguishable = append(indistinguishable, phase2ProtectedJSON(t, envelope))
			}
		})
	}
	if len(indistinguishable) != 3 || !bytes.Equal(indistinguishable[0], indistinguishable[1]) ||
		!bytes.Equal(indistinguishable[0], indistinguishable[2]) {
		t.Fatalf("hidden, absent, and cross-tenant errors differ: %q", indistinguishable)
	}
	phase2AssertProtectedTimingCohorts(t)
}

func TestPhase2ProtectedSurfacesAcceptanceCrossTenantStopsBeforeSearchGraphAndGenerate(t *testing.T) {
	authorization := phase2ProtectedAuthorization("tenant-phase2", "sess-phase2-boundary", "request-phase2-boundary")
	foreign := phase2ProtectedResource(
		"res_99999999999999999999999999999999", protocol.ResourceEntity, "tenant-other", "foreign content",
	)
	backend := &phase2CrossTenantBoundaryProbe{foreign: foreign}
	authorizer := &phase2BoundaryAuthorizer{}
	loader := &phase2BoundaryLoader{}
	service, err := authorized.New(authorized.Options{
		KAG: backend, Authorizer: authorizer, Loader: loader,
		RetrieveLimit: 4, EvidenceLimit: 4,
		Traversal: authorized.TraversalConfig{
			Enabled: true, PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateLocatedIn},
			ResourceKinds: []protocol.GraphResourceKind{protocol.GraphResourceEntity},
			Direction:     protocol.TraversalOutbound,
			Limits: protocol.TraversalLimits{
				MaxDepth: 1, MaxFrontierWidth: 8, MaxCandidatesPerHop: 8,
				MaxTotalResources: 16, MaxBatchChecks: 8, MaxWallClockMillis: 1_000,
			},
		},
		Now: func() time.Time { return time.Date(2026, time.July, 15, 9, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Query(context.Background(), protocol.QueryRequest{
		Question: "foreign tenant canary", Authorization: authorization,
	})
	if err == nil {
		t.Fatal("cross-tenant discovery unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "foreign content") || strings.Contains(err.Error(), phase2ProtectedCanary) {
		t.Fatalf("cross-tenant boundary exposed protected content: %v", err)
	}
	if backend.discoverCalls != 1 || backend.retrieveCalls != 0 || backend.expandCalls != 0 ||
		backend.generateCalls != 0 || authorizer.calls != 0 || loader.calls != 0 {
		t.Fatalf(
			"cross-tenant boundary calls discover=%d retrieve=%d expand=%d generate=%d authorize=%d load=%d",
			backend.discoverCalls, backend.retrieveCalls, backend.expandCalls, backend.generateCalls,
			authorizer.calls, loader.calls,
		)
	}
}

func phase2VisibleResult(empty protocol.ProtectedQueryVisibleResult, count int) protocol.ProtectedQueryVisibleResult {
	result := empty
	result.Count = count
	result.Exists = count > 0
	return result
}

func phase2AssertProtectedTimingCohorts(t *testing.T) {
	t.Helper()
	budget := DefaultProtectedQueryTimingBudget()
	cohorts := []struct {
		outcome ProtectedQueryInternalOutcome
		elapsed time.Duration
	}{
		{outcome: ProtectedQueryInternalHidden, elapsed: 7 * time.Millisecond},
		{outcome: ProtectedQueryInternalAbsent, elapsed: 31 * time.Millisecond},
		{outcome: ProtectedQueryInternalCrossTenant, elapsed: 49 * time.Millisecond},
	}
	completed := make([]time.Duration, len(cohorts))
	for index, cohort := range cohorts {
		waited := time.Duration(0)
		if err := EnforceProtectedQueryTiming(
			context.Background(), budget, cohort.outcome, cohort.elapsed,
			func(_ context.Context, delay time.Duration) error {
				waited = delay
				return nil
			},
		); err != nil {
			t.Fatal(err)
		}
		completed[index] = cohort.elapsed + waited
		if completed[index] < budget.Floor || completed[index] > budget.Floor+budget.MaxVariance {
			t.Fatalf("cohort %s completed at %s outside budget %+v", cohort.outcome, completed[index], budget)
		}
		if index > 0 {
			variance := completed[index] - completed[0]
			if variance < 0 {
				variance = -variance
			}
			if variance > budget.MaxVariance {
				t.Fatalf("cohort %s timing variance=%s exceeds %s", cohort.outcome, variance, budget.MaxVariance)
			}
		}
	}
}

func phase2ProtectedAuthorization(tenantID, sessionID, requestID string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version: protocol.SecurityContractVersion, TenantID: tenantID, KnowledgeBaseID: "kb-phase2",
		PrincipalID: "alice", SessionID: sessionID, RequestID: requestID,
		AuthorizationModelID: phase2ProtectedModelID, IdentityWatermark: "identity-phase2-v1",
		ACLWatermark: "acl-phase2-v1", Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func phase2ProtectedTraversalPlan(t *testing.T) protocol.TraversalPlan {
	t.Helper()
	descriptor, err := protocol.CompileGraphQuery(protocol.GraphQuery{
		Version: protocol.GraphQueryContractVersion, Operation: protocol.GraphOperationTraverseClaims,
		ProjectionVersion: phase2ProtectedVersion, IdentityVersion: protocol.GraphBindingContractVersion,
		StartResourceIDs: []protocol.ResourceID{"res_22222222222222222222222222222222"},
		PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicateLocatedIn},
		ResourceKinds:    []protocol.GraphResourceKind{protocol.GraphResourceEntity},
		Direction:        protocol.TraversalOutbound,
		Limits: protocol.TraversalLimits{
			MaxDepth: 2, MaxFrontierWidth: 16, MaxCandidatesPerHop: 32,
			MaxTotalResources: 64, MaxBatchChecks: 8, MaxWallClockMillis: 2_000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.Parameters
}

func phase2AssertProtectedSurfaceCanaryFree(t *testing.T, value any) {
	t.Helper()
	encoded := phase2ProtectedJSON(t, value)
	for _, canary := range []string{
		phase2ProtectedCanary, "/private/", "hidden_count", "resource_ids",
		"res_ffffffffffffffffffffffffffffffff", "provider cause",
	} {
		if bytes.Contains(encoded, []byte(canary)) {
			t.Fatalf("protected surface exposed %q: %s", canary, encoded)
		}
	}
}

func phase2ProtectedJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func phase2ProtectedResource(
	resourceID protocol.ResourceID,
	resourceType protocol.ResourceType,
	tenantID string,
	content string,
) protocol.ResourceHandle {
	return protocol.ResourceHandle{
		ResourceID: resourceID, Type: resourceType, TenantID: tenantID, KnowledgeBaseID: "kb-phase2",
		AuthorizationID:         string(resourceType) + ":" + string(resourceID),
		AuthorizationResourceID: resourceID, ContentDigest: protocol.NewContentDigest(content),
		Versions: protocol.ResourceVersions{
			Source: "source-phase2-v1", Content: "content-phase2-v1", ACL: "acl-phase2-v1",
			Index: "index-phase2-v1", Graph: "graph-phase2-v1", Projection: phase2ProtectedVersion,
		},
		ServingState: protocol.ServingActive,
	}
}

type phase2CrossTenantBoundaryProbe struct {
	foreign protocol.ResourceHandle

	discoverCalls int
	retrieveCalls int
	expandCalls   int
	generateCalls int
}

func (p *phase2CrossTenantBoundaryProbe) Discover(
	_ context.Context,
	_ kag.DiscoverRequest,
) (kag.DiscoverResult, error) {
	p.discoverCalls++
	return kag.DiscoverResult{Mode: "fake", Resources: []protocol.ResourceHandle{p.foreign}, Complete: true}, nil
}

func (p *phase2CrossTenantBoundaryProbe) Retrieve(
	_ context.Context,
	_ kag.RetrieveRequest,
) (kag.RetrieveResult, error) {
	p.retrieveCalls++
	return kag.RetrieveResult{Mode: "fake"}, nil
}

func (p *phase2CrossTenantBoundaryProbe) Expand(
	_ context.Context,
	_ kag.ExpandRequest,
) (kag.ExpandResult, error) {
	p.expandCalls++
	return kag.ExpandResult{Mode: "fake"}, nil
}

func (p *phase2CrossTenantBoundaryProbe) Generate(
	_ context.Context,
	_ kag.GenerateRequest,
) (kag.GenerateResult, error) {
	p.generateCalls++
	return kag.GenerateResult{Mode: "fake"}, nil
}

type phase2BoundaryAuthorizer struct{ calls int }

func (a *phase2BoundaryAuthorizer) BatchCheck(
	_ context.Context,
	request authz.BatchCheckRequest,
) ([]authz.Decision, error) {
	a.calls++
	decisions := make([]authz.Decision, len(request.Checks))
	for index, check := range request.Checks {
		decisions[index] = authz.Decision{
			CorrelationID: check.CorrelationID, Allowed: true,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions, nil
}

type phase2BoundaryLoader struct{ calls int }

func (l *phase2BoundaryLoader) Load(
	_ context.Context,
	_ []protocol.ResourceHandle,
) ([]protocol.EvidenceItem, error) {
	l.calls++
	return nil, errors.New("phase2 boundary loader must not be called")
}
