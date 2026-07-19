package eino

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
)

func testEinoAuthorization(sessionID string) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:  protocol.SecurityContractVersion,
		TenantID: "local", KnowledgeBaseID: "default", PrincipalID: "alice",
		SessionID: sessionID, RequestID: "request-1", AgentID: "agent-1", TaskID: "task-1",
		DelegationWatermark:       "delegation-v1",
		AgentTaskScopeFingerprint: "scope_00000000000000000000000000000001",
		AuthorizationModelID:      "model-v1", IdentityWatermark: "identity-v1", ACLWatermark: "acl-v1",
		Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func testEinoEvidencePackage(t *testing.T, authorization protocol.AuthorizationContext, source, content string) protocol.EvidencePackage {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(authorization.TenantID, authorization.KnowledgeBaseID, protocol.ResourceDocument, source)
	if err != nil {
		t.Fatal(err)
	}
	resource := protocol.ResourceHandle{
		ResourceID: resourceID, Type: protocol.ResourceDocument,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		AuthorizationID: "document:" + string(resourceID), AuthorizationResourceID: resourceID,
		ContentDigest: protocol.NewContentDigest(content),
		Versions: protocol.ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
			Index: "index-v1", Graph: "graph-v1", Projection: "projection-v1",
		},
		ServingState: protocol.ServingActive,
	}
	fingerprint, err := protocol.NewVisibilityFingerprint(authorization, resource.Versions.Projection)
	if err != nil {
		t.Fatal(err)
	}
	decision := protocol.AuthorizationDecision{
		CorrelationID: "decision-1", RequestID: authorization.RequestID, SessionID: authorization.SessionID,
		PrincipalID: authorization.PrincipalID, AgentID: authorization.AgentID, TaskID: authorization.TaskID,
		DelegationWatermark:       authorization.DelegationWatermark,
		AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
		Relation:                  protocol.EvidenceReadRelation, Resource: resource, AuthorizationResource: resource,
		Outcome: protocol.DecisionAllow, AuthorizationModelID: authorization.AuthorizationModelID,
		IdentityWatermark: authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		Consistency: authorization.Consistency, CheckedAt: time.Unix(1, 0).UTC(),
	}
	item := protocol.EvidenceItem{
		Resource: resource, Content: content, Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{SupportID: "support-1", Resource: resource, Evidence: []protocol.ResourceHandle{resource}, Complete: true}},
		Citation: protocol.Citation{Handle: "citation-1", Resource: resource},
	}
	result := protocol.EvidencePackage{
		Version:  protocol.SecurityContractVersion,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID: authorization.PrincipalID, SessionID: authorization.SessionID, RequestID: authorization.RequestID,
		AgentID: authorization.AgentID, TaskID: authorization.TaskID,
		DelegationWatermark:       authorization.DelegationWatermark,
		AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
		AuthorizationModelID:      authorization.AuthorizationModelID,
		IdentityWatermark:         authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		Consistency: authorization.Consistency, ProjectionVersion: resource.Versions.Projection,
		VisibilityFingerprint: fingerprint, Items: []protocol.EvidenceItem{item}, Decisions: []protocol.AuthorizationDecision{decision},
	}
	if err := result.ValidateFor(authorization); err != nil {
		t.Fatalf("test evidence package is invalid: %v", err)
	}
	return result
}

func testPermissionedToolOutput(
	t *testing.T,
	evidencePackage protocol.EvidencePackage,
	answer string,
	toolNames ...string,
) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"answer": answer, "evidence_package": evidencePackage})
	if err != nil {
		t.Fatal(err)
	}
	toolName := einotools.NameQuery
	if len(toolNames) != 0 {
		toolName = toolNames[0]
	}
	return testToolOutputWithAuthorization(
		t, testEinoAuthorizationFromEvidence(evidencePackage), toolName, string(encoded), evidencePackage,
	)
}

func testPermissionedToolFailureOutput(t *testing.T, evidencePackage protocol.EvidencePackage, failure string) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"adapter_error": failure, "answer": "FAILURE_ANSWER_CANARY", "evidence_package": evidencePackage,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testToolOutputWithAuthorization(
		t, testEinoAuthorizationFromEvidence(evidencePackage), einotools.NameQuery, string(encoded), evidencePackage,
	)
}

func testPermissionedToolOutputWithoutAuthorization(
	t *testing.T,
	evidencePackage protocol.EvidencePackage,
	answer string,
) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"answer": answer, "evidence_package": evidencePackage})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func testPermissionedToolOutputWithAuthorizationEvidence(
	t *testing.T,
	evidencePackage protocol.EvidencePackage,
	authorizationEvidence protocol.EvidencePackage,
	answer string,
) string {
	t.Helper()
	raw := testPermissionedToolOutputWithoutAuthorization(t, evidencePackage, answer)
	return testToolOutputWithAuthorization(
		t,
		testEinoAuthorizationFromEvidence(evidencePackage),
		einotools.NameQuery,
		raw,
		authorizationEvidence,
	)
}

func testEinoAuthorizationFromEvidence(evidence protocol.EvidencePackage) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:                   protocol.SecurityContractVersion,
		TenantID:                  evidence.TenantID,
		KnowledgeBaseID:           evidence.KnowledgeBaseID,
		PrincipalID:               evidence.PrincipalID,
		AgentID:                   evidence.AgentID,
		TaskID:                    evidence.TaskID,
		SessionID:                 evidence.SessionID,
		RequestID:                 evidence.RequestID,
		AuthorizationModelID:      evidence.AuthorizationModelID,
		IdentityWatermark:         evidence.IdentityWatermark,
		ACLWatermark:              evidence.ACLWatermark,
		DelegationWatermark:       evidence.DelegationWatermark,
		AgentTaskScopeFingerprint: evidence.AgentTaskScopeFingerprint,
		Consistency:               evidence.Consistency,
	}
}

func testEinoToolAuthorizationValidator(t *testing.T) *authz.ToolAuthorizationGate {
	t.Helper()
	registry, err := einotools.NewPermissionedAuthorizationManifestRegistry()
	if err != nil {
		t.Fatal(err)
	}
	gate, err := authz.NewToolAuthorizationGate(authz.ToolAuthorizationGateOptions{
		Authorizer: testEinoAllowAuthorizer{},
		Registry:   registry,
		FinalAuthorizationGate: func(context.Context, protocol.AuthorizationContext) error {
			return nil
		},
		ResultGate: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
			return nil
		},
		Now:              func() time.Time { return time.Unix(2, 0).UTC() },
		NewCorrelationID: func() (string, error) { return "tool-model-current", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

type testEinoAllowAuthorizer struct{}

func (testEinoAllowAuthorizer) Check(
	_ context.Context,
	request authz.CheckRequest,
) (authz.Decision, error) {
	return authz.Decision{
		CorrelationID:        "model-check",
		Allowed:              true,
		AuthorizationModelID: request.AuthorizationModelID,
	}, nil
}

func (testEinoAllowAuthorizer) BatchCheck(
	_ context.Context,
	request authz.BatchCheckRequest,
) ([]authz.Decision, error) {
	decisions := make([]authz.Decision, len(request.Checks))
	for index, check := range request.Checks {
		decisions[index] = authz.Decision{
			CorrelationID:        check.CorrelationID,
			Allowed:              true,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions, nil
}
