package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestToolAuthorizationGateFailsClosedAndAuthorizesRegisteredActions(t *testing.T) {
	registry := toolTestRegistry(t)
	authorizer := toolTestAuthorizer(t)
	var denied []string
	gate, err := NewToolAuthorizationGate(ToolAuthorizationGateOptions{
		Authorizer: authorizer, Registry: registry,
		ResultGate: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			return nil
		},
		InvocationDenied: func(_ context.Context, manifest protocol.ToolAuthorizationManifest) {
			denied = append(denied, manifest.ToolName)
		},
		Now:              func() time.Time { return time.Unix(10, 0).UTC() },
		NewCorrelationID: func() (string, error) { return "tool-test-1", nil },
	})
	if err != nil {
		t.Fatalf("NewToolAuthorizationGate: %v", err)
	}
	authorization := toolTestAuthorization("alice")

	query, err := gate.AuthorizeInvocation(context.Background(), authorization, "knote_query")
	if err != nil {
		t.Fatalf("authorize query: %v", err)
	}
	if query.Relation != RelationCanView || query.SideEffect || query.ReturnObligation != protocol.ToolReturnEvidence {
		t.Fatalf("query authorization = %+v", query)
	}
	build, err := gate.AuthorizeInvocation(context.Background(), authorization, "knote_build")
	if err != nil {
		t.Fatalf("authorize build: %v", err)
	}
	if build.Relation != RelationCanEdit || !build.SideEffect || build.ReturnObligation != protocol.ToolReturnNone {
		t.Fatalf("build authorization = %+v", build)
	}
	if _, err := gate.AuthorizeInvocation(context.Background(), authorization, "knote_unknown"); !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("unknown tool error = %v", err)
	}
	malformedAuthorization := authorization
	malformedAuthorization.RequestID = ""
	if _, err := gate.AuthorizeInvocation(context.Background(), malformedAuthorization, "knote_query"); !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("malformed authorization error = %v", err)
	}
	if _, err := gate.AuthorizeInvocation(context.Background(), toolTestAuthorization("mallory"), "knote_query"); !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("unauthorized principal error = %v", err)
	}
	if got := strings.Join(denied, ","); got != "knote_query" {
		t.Fatalf("reported invocation denials = %q, want %q", got, "knote_query")
	}

	malformed := protocol.ToolAuthorizationManifest{
		Version: protocol.EnterpriseContractVersion, ToolName: "knote_bad", Action: "build",
		Relation: RelationCanView, SideEffect: true, ReturnObligation: protocol.ToolReturnNone,
	}
	badRegistry, err := protocol.NewToolManifestRegistry([]protocol.ToolAuthorizationManifest{malformed})
	if err != nil {
		t.Fatalf("protocol registry should accept structurally valid manifest: %v", err)
	}
	if _, err := NewToolAuthorizationGate(ToolAuthorizationGateOptions{
		Authorizer: authorizer, Registry: badRegistry,
		ResultGate: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			return nil
		},
	}); err == nil {
		t.Fatal("side-effecting read manifest was accepted")
	}
}

func TestToolAuthorizationGateDoesNotReportBackendFailureAsExplicitDenial(t *testing.T) {
	reported := 0
	gate, err := NewToolAuthorizationGate(ToolAuthorizationGateOptions{
		Authorizer: toolFailingAuthorizer{}, Registry: toolTestRegistry(t),
		ResultGate: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			return nil
		},
		InvocationDenied: func(context.Context, protocol.ToolAuthorizationManifest) {
			reported++
		},
	})
	if err != nil {
		t.Fatalf("NewToolAuthorizationGate: %v", err)
	}
	if _, err := gate.AuthorizeInvocation(
		context.Background(), toolTestAuthorization("alice"), "knote_query",
	); !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("backend failure error = %v", err)
	}
	if reported != 0 {
		t.Fatalf("backend failure reported as %d explicit denials", reported)
	}
}

func TestToolAuthorizationGateAuthorizesReturnedResourcesAtomically(t *testing.T) {
	registry := toolTestRegistry(t)
	authorizer := toolTestAuthorizer(t)
	resultCalls := 0
	denyResults := false
	gate, err := NewToolAuthorizationGate(ToolAuthorizationGateOptions{
		Authorizer: authorizer, Registry: registry,
		ResultGate: func(_ context.Context, _ protocol.AuthorizationContext, binding protocol.ProtectedContentBinding) error {
			resultCalls++
			if denyResults {
				return errors.New("mixed protected result contains res_private_canary")
			}
			if len(binding.Resources) != 2 {
				t.Fatalf("result binding resource count = %d", len(binding.Resources))
			}
			return nil
		},
		Now:              func() time.Time { return time.Unix(20, 0).UTC() },
		NewCorrelationID: func() (string, error) { return "tool-test-2", nil },
	})
	if err != nil {
		t.Fatalf("NewToolAuthorizationGate: %v", err)
	}
	authorization := toolTestAuthorization("alice")
	invocation, err := gate.AuthorizeInvocation(context.Background(), authorization, "knote_resources")
	if err != nil {
		t.Fatalf("authorize resource tool: %v", err)
	}
	first := toolTestResource(t, authorization, "first")
	second := toolTestResource(t, authorization, "second")
	envelope, err := gate.AuthorizeResourceResult(context.Background(), authorization, invocation, []protocol.ProtectedResourceBinding{
		{Resource: second, AuthorizationResource: second},
		{Resource: first, AuthorizationResource: first},
	})
	if err != nil {
		t.Fatalf("authorize resource result: %v", err)
	}
	if resultCalls != 1 || len(envelope.Result.Resources) != 2 ||
		envelope.Result.Resources[0].ResourceID > envelope.Result.Resources[1].ResourceID {
		t.Fatalf("canonical result envelope = %+v", envelope)
	}
	if err := registry.ValidateEnvelope(authorization, envelope); err != nil {
		t.Fatalf("validate result envelope: %v", err)
	}

	denyResults = true
	_, err = gate.AuthorizeResourceResult(context.Background(), authorization, invocation, []protocol.ProtectedResourceBinding{
		{Resource: first, AuthorizationResource: first},
		{Resource: second, AuthorizationResource: second},
	})
	if !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("mixed result error = %v", err)
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "2") || strings.Contains(err.Error(), string(first.ResourceID)) {
		t.Fatalf("mixed result error leaked protected existence metadata: %v", err)
	}
}

func TestToolAuthorizationGateRevalidatesDelegationForInvocationAndReturn(t *testing.T) {
	registry := toolTestRegistry(t)
	authorizer := toolTestAuthorizer(t)
	revoked := false
	gate, err := NewToolAuthorizationGate(ToolAuthorizationGateOptions{
		Authorizer: authorizer, Registry: registry,
		FinalAuthorizationGate: func(context.Context, protocol.AuthorizationContext) error {
			if revoked {
				return errors.New("delegation revoked")
			}
			return nil
		},
		ResultGate: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			if revoked {
				return errors.New("delegation revoked")
			}
			return nil
		},
		Now:              func() time.Time { return time.Unix(30, 0).UTC() },
		NewCorrelationID: func() (string, error) { return "tool-test-3", nil },
	})
	if err != nil {
		t.Fatalf("NewToolAuthorizationGate: %v", err)
	}
	authorization := toolTestAuthorization("alice")
	authorization.AgentID = "research"
	authorization.TaskID = "answer"
	authorization.DelegationWatermark = "delegation-v1"
	authorization.AgentTaskScopeFingerprint = "scope_00000000000000000000000000000001"
	invocation, err := gate.AuthorizeInvocation(context.Background(), authorization, "knote_resources")
	if err != nil {
		t.Fatalf("authorize delegated invocation: %v", err)
	}
	revoked = true
	if _, err := gate.AuthorizeInvocation(context.Background(), authorization, "knote_resources"); !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("revoked future invocation error = %v", err)
	}
	resource := toolTestResource(t, authorization, "delegated")
	if _, err := gate.AuthorizeResourceResult(context.Background(), authorization, invocation, []protocol.ProtectedResourceBinding{{
		Resource: resource, AuthorizationResource: resource,
	}}); !errors.Is(err, ErrToolAuthorizationDenied) {
		t.Fatalf("revoked result reuse error = %v", err)
	}
}

func toolTestRegistry(t *testing.T) *protocol.ToolManifestRegistry {
	t.Helper()
	registry, err := protocol.NewToolManifestRegistry([]protocol.ToolAuthorizationManifest{
		{
			Version: protocol.EnterpriseContractVersion, ToolName: "knote_query", Action: "query",
			Relation: RelationCanView, ReturnObligation: protocol.ToolReturnEvidence,
		},
		{
			Version: protocol.EnterpriseContractVersion, ToolName: "knote_resources", Action: "read",
			Relation: RelationCanView, ReturnObligation: protocol.ToolReturnResources,
		},
		{
			Version: protocol.EnterpriseContractVersion, ToolName: "knote_build", Action: "build",
			Relation: RelationCanEdit, SideEffect: true, ReturnObligation: protocol.ToolReturnNone,
		},
	})
	if err != nil {
		t.Fatalf("NewToolManifestRegistry: %v", err)
	}
	return registry
}

func toolTestAuthorizer(t *testing.T) *LocalAuthorizer {
	t.Helper()
	authorizer, err := NewLocalAuthorizer(localTestModelID, []Tuple{
		{User: "user:alice", Relation: RelationMember, Object: "organization:acme"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "knowledge_base:kb-a"},
		{User: "user:alice", Relation: RelationEditor, Object: "knowledge_base:kb-a"},
	})
	if err != nil {
		t.Fatalf("NewLocalAuthorizer: %v", err)
	}
	return authorizer
}

func toolTestAuthorization(principal string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version: protocol.SecurityContractVersion, TenantID: "tenant-a", KnowledgeBaseID: "kb-a",
		PrincipalID: principal, SessionID: "session-1", RequestID: "request-1",
		AuthorizationModelID: localTestModelID,
		IdentityWatermark:    "identity-v1", ACLWatermark: "acl-v1",
		Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func toolTestResource(t *testing.T, authorization protocol.AuthorizationContext, source string) protocol.ResourceHandle {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(
		authorization.TenantID, authorization.KnowledgeBaseID, protocol.ResourceDocument, source,
	)
	if err != nil {
		t.Fatalf("NewStableResourceID: %v", err)
	}
	return protocol.ResourceHandle{
		ResourceID: resourceID, Type: protocol.ResourceDocument,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		AuthorizationID: "document:" + string(resourceID), AuthorizationResourceID: resourceID,
		ContentDigest: protocol.NewContentDigest("content-" + source),
		Versions: protocol.ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: authorization.ACLWatermark,
			Index: "index-v1", Graph: "graph-v1", Projection: "projection-v1",
		},
		ServingState: protocol.ServingActive,
	}
}

type toolFailingAuthorizer struct{}

func (toolFailingAuthorizer) Check(context.Context, CheckRequest) (Decision, error) {
	return Decision{}, errors.New("authorization backend unavailable")
}

func (toolFailingAuthorizer) BatchCheck(context.Context, BatchCheckRequest) ([]Decision, error) {
	return nil, errors.New("authorization backend unavailable")
}
