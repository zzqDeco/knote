package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAuthorizationContextRoundTripAndValidation(t *testing.T) {
	auth := testAuthorizationContext()
	if err := auth.Validate(); err != nil {
		t.Fatalf("validate context: %v", err)
	}
	data, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal context: %v", err)
	}
	for _, field := range []string{"tenant_id", "principal_id", "authorization_model_id", "acl_watermark"} {
		if !strings.Contains(string(data), `"`+field+`"`) {
			t.Fatalf("serialized context missing %s: %s", field, data)
		}
	}
	var decoded AuthorizationContext
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal context: %v", err)
	}
	if decoded != auth {
		t.Fatalf("round trip mismatch:\nwant %#v\n got %#v", auth, decoded)
	}

	invalid := auth
	invalid.Version = "v2"
	if err := invalid.Validate(); err == nil {
		t.Fatal("unsupported context version should fail")
	}
	invalid = auth
	invalid.Consistency = "eventual"
	if err := invalid.Validate(); err == nil {
		t.Fatal("unsupported consistency should fail")
	}
	invalid = auth
	invalid.RequestID = ""
	if err := invalid.Validate(); err == nil {
		t.Fatal("missing request id should fail")
	}
}

func TestStableResourceIDIgnoresMutableVersions(t *testing.T) {
	id, err := NewStableResourceID("local", "default", ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatalf("stable resource id: %v", err)
	}
	if err := id.Validate(); err != nil {
		t.Fatalf("validate resource id: %v", err)
	}
	handleA := testResourceHandle(t, id)
	handleB := handleA
	handleB.Versions = ResourceVersions{
		Source: "source-v2", Content: "content-v2", ACL: "acl-v2",
		Index: "index-v2", Graph: "graph-v2", Projection: "projection-v2",
	}
	if handleA.ResourceID != handleB.ResourceID {
		t.Fatal("resource identity changed with mutable versions")
	}
	other, err := NewStableResourceID("local", "default", ResourceDocument, "sources/other.md")
	if err != nil {
		t.Fatalf("second stable resource id: %v", err)
	}
	if other == id {
		t.Fatal("different source keys produced the same resource id")
	}
}

func TestProvenanceSemantics(t *testing.T) {
	id, err := NewStableResourceID("local", "default", ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	support := ProvenanceSupport{
		SupportID: "support-1", Resource: testResourceHandle(t, id),
		Evidence: []ResourceHandle{testResourceHandle(t, id)}, Complete: true,
	}
	if err := ValidateProvenance(DerivationAnySupport, []ProvenanceSupport{support}); err != nil {
		t.Fatalf("valid any-support provenance: %v", err)
	}
	incomplete := support
	incomplete.Complete = false
	if err := ValidateProvenance(DerivationAnySupport, []ProvenanceSupport{incomplete}); err == nil {
		t.Fatal("incomplete any-support provenance should fail")
	}
	if err := ValidateProvenance(DerivationAllRequired, []ProvenanceSupport{incomplete}); err != nil {
		t.Fatalf("partial supports may combine under all-required: %v", err)
	}
	if err := ValidateProvenance(DerivationAllRequired, nil); err == nil {
		t.Fatal("empty provenance should fail")
	}
}

func TestAuthorizationDecisionFailsClosed(t *testing.T) {
	id, err := NewStableResourceID("local", "default", ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	decision := testDecision(t, id)
	if !decision.Authorized() {
		t.Fatal("allow decision should authorize")
	}
	decision.Outcome = DecisionDeny
	if decision.Authorized() {
		t.Fatal("deny decision authorized")
	}
	decision.Outcome = DecisionIndeterminate
	if decision.Authorized() {
		t.Fatal("indeterminate decision authorized")
	}
	if err := decision.Validate(); err != nil {
		t.Fatalf("indeterminate is a valid fail-closed outcome: %v", err)
	}
	decision.CheckedAt = time.Time{}
	if err := decision.Validate(); err == nil {
		t.Fatal("decision without checked_at should fail validation")
	}
}

func TestChunkAuthorizationUsesParentDocumentBoundary(t *testing.T) {
	documentID, err := NewStableResourceID("local", "default", ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	chunkID, err := NewStableResourceID("local", "default", ResourceChunk, "sources/intro.md#chunk-1")
	if err != nil {
		t.Fatal(err)
	}
	document := testResourceHandle(t, documentID)
	chunk := testResourceHandle(t, chunkID)
	chunk.Type = ResourceChunk
	chunk.AuthorizationID = document.AuthorizationID
	chunk.AuthorizationResourceID = document.ResourceID

	decision := testDecision(t, chunkID)
	decision.Resource = chunk
	decision.AuthorizationResource = document
	if err := decision.Validate(); err != nil {
		t.Fatalf("valid inherited document authorization: %v", err)
	}

	chunkScoped := decision
	chunkScoped.AuthorizationResource = chunk
	if err := chunkScoped.Validate(); err == nil {
		t.Fatal("chunk-scoped authorization should fail")
	}

	otherDocumentID, err := NewStableResourceID("local", "default", ResourceDocument, "sources/other.md")
	if err != nil {
		t.Fatal(err)
	}
	wrongParent := decision
	wrongParent.AuthorizationResource = testResourceHandle(t, otherDocumentID)
	wrongParent.AuthorizationResource.AuthorizationID = document.AuthorizationID
	if err := wrongParent.Validate(); err == nil {
		t.Fatal("authorization through a forged document with the same authorization object should fail")
	}
}

func TestEvidencePackageBinding(t *testing.T) {
	auth := testAuthorizationContext()
	id, err := NewStableResourceID("local", "default", ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	resource := testResourceHandle(t, id)
	fingerprint, err := NewVisibilityFingerprint(auth, resource.Versions.Projection)
	if err != nil {
		t.Fatalf("visibility fingerprint: %v", err)
	}
	support := ProvenanceSupport{
		SupportID: "support-1", Resource: resource,
		Evidence: []ResourceHandle{resource}, Complete: true,
	}
	pkg := EvidencePackage{
		Version:               SecurityContractVersion,
		TenantID:              auth.TenantID,
		KnowledgeBaseID:       auth.KnowledgeBaseID,
		PrincipalID:           auth.PrincipalID,
		SessionID:             auth.SessionID,
		RequestID:             auth.RequestID,
		AuthorizationModelID:  auth.AuthorizationModelID,
		IdentityWatermark:     auth.IdentityWatermark,
		ACLWatermark:          auth.ACLWatermark,
		Consistency:           auth.Consistency,
		ProjectionVersion:     resource.Versions.Projection,
		VisibilityFingerprint: fingerprint,
		Items: []EvidenceItem{{
			Resource: resource, Content: "authorized content", Derivation: DerivationAnySupport,
			Supports: []ProvenanceSupport{support}, Citation: Citation{Handle: "citation-1", Resource: resource},
		}},
		Decisions: []AuthorizationDecision{testDecision(t, id)},
	}
	if err := pkg.ValidateFor(auth); err != nil {
		t.Fatalf("valid evidence package: %v", err)
	}

	mismatched := pkg
	mismatched.PrincipalID = "another-user"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("principal mismatch should fail")
	}
	mismatched = pkg
	mismatched.VisibilityFingerprint = "vis_00000000000000000000000000000000"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("visibility fingerprint mismatch should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].RequestID = "another-request"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("decision from another request should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].SessionID = "another-session"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("decision from another session should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].PrincipalID = "another-user"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("decision for another principal should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].IdentityWatermark = "identity-v0"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("decision from another identity watermark should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].Consistency = ConsistencyMinimizeLatency
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("decision from another consistency boundary should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].Relation = "can_edit"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("non-read allow decision should fail")
	}
	mismatched = pkg
	mismatched.Items = append([]EvidenceItem(nil), pkg.Items...)
	mismatched.Items[0].Supports = append([]ProvenanceSupport(nil), pkg.Items[0].Supports...)
	unauthorizedID, err := NewStableResourceID("local", "default", ResourceDocument, "sources/private.md")
	if err != nil {
		t.Fatal(err)
	}
	mismatched.Items[0].Supports[0].Evidence = []ResourceHandle{testResourceHandle(t, unauthorizedID)}
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("unauthorized provenance evidence should fail")
	}
	mismatched = pkg
	mismatched.Items = append([]EvidenceItem(nil), pkg.Items...)
	mismatched.Items[0].Supports = append([]ProvenanceSupport(nil), pkg.Items[0].Supports...)
	mismatched.Items[0].Supports[0].Resource.Versions.Content = "content-v0"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("provenance from another resource version should fail")
	}
	mismatched = pkg
	mismatched.Decisions = append([]AuthorizationDecision(nil), pkg.Decisions...)
	mismatched.Decisions[0].Outcome = DecisionIndeterminate
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("indeterminate evidence decision should fail closed")
	}
	mismatched = pkg
	mismatched.Items = append([]EvidenceItem(nil), pkg.Items...)
	mismatched.Items[0].Resource.Versions.Projection = "other-projection"
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("projection mismatch should fail")
	}
	mismatched = pkg
	mismatched.Items = append([]EvidenceItem(nil), pkg.Items...)
	mismatched.Items[0].Resource.Versions.Content = "content-v2"
	mismatched.Items[0].Citation.Resource = mismatched.Items[0].Resource
	if err := mismatched.ValidateFor(auth); err == nil {
		t.Fatal("resource version not covered by the allow decision should fail")
	}
}

func TestEntityEvidenceRequiresAuthorizedSourceSupport(t *testing.T) {
	auth := testAuthorizationContext()
	entityID, err := NewStableResourceID("local", "default", ResourceEntity, "entity:knote")
	if err != nil {
		t.Fatal(err)
	}
	entity := testResourceHandle(t, entityID)
	entity.Type = ResourceEntity
	entityDecision := testDecision(t, entityID)
	entityDecision.Resource = entity
	entityDecision.AuthorizationResource = entity

	fingerprint, err := NewVisibilityFingerprint(auth, entity.Versions.Projection)
	if err != nil {
		t.Fatal(err)
	}
	pkg := EvidencePackage{
		Version:               SecurityContractVersion,
		TenantID:              auth.TenantID,
		KnowledgeBaseID:       auth.KnowledgeBaseID,
		PrincipalID:           auth.PrincipalID,
		SessionID:             auth.SessionID,
		RequestID:             auth.RequestID,
		AuthorizationModelID:  auth.AuthorizationModelID,
		IdentityWatermark:     auth.IdentityWatermark,
		ACLWatermark:          auth.ACLWatermark,
		Consistency:           auth.Consistency,
		ProjectionVersion:     entity.Versions.Projection,
		VisibilityFingerprint: fingerprint,
		Items: []EvidenceItem{{
			Resource: entity, Content: "knote", Derivation: DerivationAnySupport,
			Supports: []ProvenanceSupport{{
				SupportID: "support-self", Resource: entity,
				Evidence: []ResourceHandle{entity}, Complete: true,
			}},
			Citation: Citation{Handle: "citation-entity", Resource: entity},
		}},
		Decisions: []AuthorizationDecision{entityDecision},
	}
	if err := pkg.ValidateFor(auth); err == nil {
		t.Fatal("entity self-support should fail")
	}

	documentID, err := NewStableResourceID("local", "default", ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	document := testResourceHandle(t, documentID)
	pkg.Items[0].Supports[0] = ProvenanceSupport{
		SupportID: "support-document", Resource: document,
		Evidence: []ResourceHandle{document}, Complete: true,
	}
	pkg.Decisions = append(pkg.Decisions, testDecision(t, documentID))
	if err := pkg.ValidateFor(auth); err != nil {
		t.Fatalf("entity with authorized document support: %v", err)
	}
}

func TestVisibilityFingerprintIncludesConsistency(t *testing.T) {
	auth := testAuthorizationContext()
	strict, err := NewVisibilityFingerprint(auth, "projection-v1")
	if err != nil {
		t.Fatal(err)
	}
	auth.Consistency = ConsistencyMinimizeLatency
	fast, err := NewVisibilityFingerprint(auth, "projection-v1")
	if err != nil {
		t.Fatal(err)
	}
	if strict == fast {
		t.Fatal("consistency preference must change the visibility fingerprint")
	}
}

func TestActionApprovalCompatibilityAliases(t *testing.T) {
	legacy := PermissionRequest{RequestID: "request-1", Tool: "knote_build"}
	var canonical ActionApprovalRequest = legacy
	if canonical.RequestID != legacy.RequestID || canonical.Tool != legacy.Tool {
		t.Fatal("action approval alias changed legacy values")
	}
	confirm := ConfirmRequest{RequestID: "request-2", Action: "build"}
	var canonicalConfirm ActionConfirmationRequest = confirm
	if canonicalConfirm != confirm {
		t.Fatal("action confirmation alias changed legacy values")
	}
}

func testAuthorizationContext() AuthorizationContext {
	return AuthorizationContext{
		Version:              SecurityContractVersion,
		TenantID:             "local",
		KnowledgeBaseID:      "default",
		PrincipalID:          "local-user",
		SessionID:            "session-1",
		RequestID:            "request-1",
		AuthorizationModelID: "local-v1",
		IdentityWatermark:    "identity-v1",
		ACLWatermark:         "acl-v1",
		Consistency:          ConsistencyHigherConsistency,
	}
}

func testResourceHandle(t *testing.T, id ResourceID) ResourceHandle {
	t.Helper()
	handle := ResourceHandle{
		ResourceID: id, Type: ResourceDocument, TenantID: "local", KnowledgeBaseID: "default",
		AuthorizationID: "document:" + string(id), AuthorizationResourceID: id, ServingState: ServingActive,
		Versions: ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
			Index: "index-v1", Graph: "graph-v1", Projection: "projection-v1",
		},
	}
	if err := handle.Validate(); err != nil {
		t.Fatalf("validate resource handle: %v", err)
	}
	return handle
}

func testDecision(t *testing.T, id ResourceID) AuthorizationDecision {
	t.Helper()
	resource := testResourceHandle(t, id)
	decision := AuthorizationDecision{
		CorrelationID: "decision-1", RequestID: "request-1", SessionID: "session-1", PrincipalID: "local-user",
		Relation: EvidenceReadRelation, Resource: resource, AuthorizationResource: resource,
		Outcome: DecisionAllow, AuthorizationModelID: "local-v1", IdentityWatermark: "identity-v1",
		ACLWatermark: "acl-v1", Consistency: ConsistencyHigherConsistency,
		CheckedAt: time.Unix(1, 0).UTC(),
	}
	if err := decision.Validate(); err != nil {
		t.Fatalf("validate decision: %v", err)
	}
	return decision
}
