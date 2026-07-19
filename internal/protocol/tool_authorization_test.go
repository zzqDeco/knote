package protocol

import (
	"slices"
	"testing"
)

func TestToolManifestRegistryIsDeterministicAndFailClosed(t *testing.T) {
	query := ToolAuthorizationManifest{
		Version: EnterpriseContractVersion, ToolName: "knote_query", Action: "query",
		Relation: EvidenceReadRelation, ReturnObligation: ToolReturnEvidence,
	}
	build := ToolAuthorizationManifest{
		Version: EnterpriseContractVersion, ToolName: "knote_build", Action: "build",
		Relation: "can_edit", SideEffect: true, ReturnObligation: ToolReturnNone,
	}
	first, err := NewToolManifestRegistry([]ToolAuthorizationManifest{query, build})
	if err != nil {
		t.Fatalf("NewToolManifestRegistry: %v", err)
	}
	second, err := NewToolManifestRegistry([]ToolAuthorizationManifest{build, query})
	if err != nil {
		t.Fatalf("NewToolManifestRegistry reversed: %v", err)
	}
	if first.Digest() == "" || first.Digest() != second.Digest() {
		t.Fatalf("registry digest is not deterministic: %q != %q", first.Digest(), second.Digest())
	}
	got := first.Manifests()
	if !slices.Equal(got, []ToolAuthorizationManifest{build, query}) {
		t.Fatalf("manifests = %#v, want sorted manifests", got)
	}
	if _, ok := first.Lookup("knote_unknown"); ok {
		t.Fatal("unregistered tool was found")
	}

	malformed := query
	malformed.ReturnObligation = "optional"
	if _, err := NewToolManifestRegistry([]ToolAuthorizationManifest{malformed}); err == nil {
		t.Fatal("malformed return obligation was accepted")
	}
	if _, err := NewToolManifestRegistry([]ToolAuthorizationManifest{query, query}); err == nil {
		t.Fatal("duplicate tool manifest was accepted")
	}
}

func TestToolResultAuthorizationAllowsOnlyEmptyContentFreeResult(t *testing.T) {
	auth := enterpriseTestAuthorization()
	manifest := ToolAuthorizationManifest{
		Version: EnterpriseContractVersion, ToolName: "knote_build", Action: "build",
		Relation: "can_edit", SideEffect: true, ReturnObligation: ToolReturnNone,
	}
	request, err := manifest.InvocationRequest()
	if err != nil {
		t.Fatalf("InvocationRequest: %v", err)
	}
	invocation := ToolInvocationAuthorization{
		Version: EnterpriseContractVersion, CorrelationID: "tool-build-1",
		TenantID: auth.TenantID, KnowledgeBaseID: auth.KnowledgeBaseID,
		PrincipalID: auth.PrincipalID, AgentID: auth.AgentID, TaskID: auth.TaskID,
		SessionID: auth.SessionID, RequestID: auth.RequestID,
		ToolName: manifest.ToolName, Action: manifest.Action, Relation: manifest.Relation,
		AuthorizationModelID: auth.AuthorizationModelID,
		IdentityWatermark:    auth.IdentityWatermark, ACLWatermark: auth.ACLWatermark,
		DelegationWatermark:       auth.DelegationWatermark,
		AgentTaskScopeFingerprint: auth.AgentTaskScopeFingerprint,
		SideEffect:                true, ReturnObligation: ToolReturnNone,
		Outcome: DecisionAllow, Consistency: auth.Consistency, CheckedAt: enterpriseTestTime(),
	}
	result := ToolResultAuthorization{
		Version: EnterpriseContractVersion, CorrelationID: invocation.CorrelationID,
		TenantID: auth.TenantID, KnowledgeBaseID: auth.KnowledgeBaseID,
		PrincipalID: auth.PrincipalID, AgentID: auth.AgentID, TaskID: auth.TaskID,
		SessionID: auth.SessionID, RequestID: auth.RequestID,
		ToolName: manifest.ToolName, Action: manifest.Action, Relation: manifest.Relation,
		SideEffect: true, ReturnObligation: ToolReturnNone,
		AuthorizationModelID: auth.AuthorizationModelID,
		IdentityWatermark:    auth.IdentityWatermark, ACLWatermark: auth.ACLWatermark,
		DelegationWatermark:       auth.DelegationWatermark,
		AgentTaskScopeFingerprint: auth.AgentTaskScopeFingerprint,
	}
	if err := result.ValidateFor(auth, invocation, request); err != nil {
		t.Fatalf("content-free result: %v", err)
	}
	registry, err := NewToolManifestRegistry([]ToolAuthorizationManifest{manifest})
	if err != nil {
		t.Fatalf("NewToolManifestRegistry: %v", err)
	}
	envelope := ToolAuthorizationEnvelope{
		Version: EnterpriseContractVersion, ManifestDigest: registry.Digest(),
		Invocation: invocation, Result: result,
	}
	if err := registry.ValidateEnvelope(auth, envelope); err != nil {
		t.Fatalf("tool authorization envelope: %v", err)
	}
	wrongDigest := envelope
	wrongDigest.ManifestDigest = "tool_manifest_ffffffffffffffffffffffffffffffff"
	if err := registry.ValidateEnvelope(auth, wrongDigest); err == nil {
		t.Fatal("tool authorization envelope from another registry was accepted")
	}
	result.Resources = []ResourceHandle{enterpriseTestResource(t, "unexpected")}
	if err := result.ValidateFor(auth, invocation, request); err == nil {
		t.Fatal("content-free result with a protected resource was accepted")
	}
}
