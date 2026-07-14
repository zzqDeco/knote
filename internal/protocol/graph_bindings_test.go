package protocol

import (
	"strings"
	"testing"
)

func TestGraphResourceBindingsAreProjectionScopedAndDeterministic(t *testing.T) {
	first := mustGraphBinding(t, graphTestHandle(t, "00000000000000000000000000000001", ResourceDocument))
	second := mustGraphBinding(t, graphTestHandle(t, "00000000000000000000000000000002", ResourceEntity))
	bindings := []GraphResourceBinding{second, first}
	SortGraphResourceBindings(bindings)
	if err := ValidateGraphResourceBindings(bindings); err != nil {
		t.Fatal(err)
	}
	repeated := mustGraphBinding(t, first.Resource)
	if repeated.GraphObjectID != first.GraphObjectID {
		t.Fatalf("graph object ID is not deterministic: %s != %s", repeated.GraphObjectID, first.GraphObjectID)
	}
	if strings.Contains(string(first.GraphObjectID), string(first.Resource.ResourceID)) {
		t.Fatalf("graph object ID exposed the catalog resource ID: %s", first.GraphObjectID)
	}
}

func TestGraphResourceBindingsRejectForgedStaleDuplicateAndCrossScopeValues(t *testing.T) {
	base := mustGraphBinding(t, graphTestHandle(t, "00000000000000000000000000000001", ResourceDocument))
	other := mustGraphBinding(t, graphTestHandle(t, "00000000000000000000000000000002", ResourceEntity))

	tests := []struct {
		name   string
		mutate func(*GraphResourceBinding)
	}{
		{name: "forged ID", mutate: func(value *GraphResourceBinding) { value.GraphObjectID = "kg_ffffffffffffffffffffffffffffffff" }},
		{name: "stale ACL", mutate: func(value *GraphResourceBinding) { value.Resource.Versions.ACL = "acl_stale" }},
		{name: "stale index", mutate: func(value *GraphResourceBinding) { value.Resource.Versions.Index = "index_stale" }},
		{name: "stale graph", mutate: func(value *GraphResourceBinding) { value.Resource.Versions.Graph = "graph_stale" }},
		{name: "cross tenant", mutate: func(value *GraphResourceBinding) { value.Resource.TenantID = "tenant_other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := other
			test.mutate(&candidate)
			bindings := []GraphResourceBinding{base, candidate}
			SortGraphResourceBindings(bindings)
			if err := ValidateGraphResourceBindings(bindings); err == nil {
				t.Fatal("invalid graph binding set was accepted")
			}
		})
	}

	t.Run("stale projection", func(t *testing.T) {
		candidate := other
		candidate.Resource.Versions.Projection = "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		candidate.GraphObjectID, _ = NewGraphObjectID(candidate.Resource.Versions.Projection, candidate.Resource.ResourceID)
		bindings := []GraphResourceBinding{base, candidate}
		SortGraphResourceBindings(bindings)
		if err := ValidateGraphResourceBindings(bindings); err == nil {
			t.Fatal("mixed projections were accepted")
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		if err := ValidateGraphResourceBindings([]GraphResourceBinding{base, base}); err == nil {
			t.Fatal("duplicate graph bindings were accepted")
		}
	})
}

func TestClaimTripleBindingsRequireOpaqueSourceBackedGraphIdentities(t *testing.T) {
	document := graphTestHandle(t, "00000000000000000000000000000001", ResourceDocument)
	chunk := graphTestHandle(t, "00000000000000000000000000000002", ResourceChunk)
	chunk.AuthorizationResourceID = document.ResourceID
	chunk.AuthorizationID = document.AuthorizationID
	subject := graphTestHandle(t, "00000000000000000000000000000003", ResourceEntity)
	object := graphTestHandle(t, "00000000000000000000000000000004", ResourceEntity)
	claim := graphTestHandle(t, "00000000000000000000000000000005", ResourceClaim)
	resources := []GraphResourceBinding{
		mustGraphBinding(t, document), mustGraphBinding(t, chunk), mustGraphBinding(t, subject),
		mustGraphBinding(t, object), mustGraphBinding(t, claim),
	}
	SortGraphResourceBindings(resources)
	byResource := make(map[ResourceID]GraphObjectID, len(resources))
	for _, binding := range resources {
		byResource[binding.Resource.ResourceID] = binding.GraphObjectID
	}
	predicate, err := NewClaimPredicateKey("located_in")
	if err != nil {
		t.Fatal(err)
	}
	provenance := []GraphObjectID{byResource[chunk.ResourceID]}
	claimBinding := ClaimTripleBinding{
		Version: GraphBindingContractVersion, Claim: byResource[claim.ResourceID],
		Subject: byResource[subject.ResourceID], PredicateKey: predicate, Object: byResource[object.ResourceID],
		SourceDocument: byResource[document.ResourceID], Derivation: DerivationAllRequired, Provenance: provenance,
		SubjectResourceID: subject.ResourceID, ObjectResourceID: object.ResourceID,
		SourceDocumentResourceID: document.ResourceID, SourceVersion: document.Versions.Source,
		ProvenanceResourceIDs: []ResourceID{chunk.ResourceID},
	}
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{claimBinding}); err != nil {
		t.Fatal(err)
	}

	outside := claimBinding
	outside.Provenance = []GraphObjectID{byResource[subject.ResourceID]}
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{outside}); err == nil {
		t.Fatal("entity provenance was accepted as source evidence")
	}
	rawPredicate := claimBinding
	rawPredicate.PredicateKey = "located_in"
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{rawPredicate}); err == nil {
		t.Fatal("raw relation label was accepted as predicate_key")
	}
	unknownOpaquePredicate := claimBinding
	unknownOpaquePredicate.PredicateKey = "pred_ffffffffffffffffffffffffffffffff"
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{unknownOpaquePredicate}); err == nil {
		t.Fatal("undeclared opaque predicate was accepted")
	}
	mismatchedStableIdentity := claimBinding
	mismatchedStableIdentity.SubjectResourceID = object.ResourceID
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{mismatchedStableIdentity}); err == nil {
		t.Fatal("mismatched stable subject identity was accepted")
	}
	staleSource := claimBinding
	staleSource.SourceVersion = "source_v0"
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{staleSource}); err == nil {
		t.Fatal("stale claim source version was accepted")
	}
}

func graphTestHandle(t *testing.T, suffix string, resourceType ResourceType) ResourceHandle {
	t.Helper()
	resourceID := ResourceID("res_" + suffix)
	content := NewContentDigest(string(resourceID))
	return ResourceHandle{
		ResourceID: resourceID, Type: resourceType, TenantID: "tenant_one", KnowledgeBaseID: "kb_one",
		AuthorizationID: string(resourceType) + ":" + string(resourceID), AuthorizationResourceID: resourceID,
		ContentDigest: content,
		Versions: ResourceVersions{
			Source: "source_v1", Content: "content_" + suffix[:8], ACL: "acl_v1",
			Index: "index_prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Graph: "graph_prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Projection: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		ServingState: ServingActive,
	}
}

func mustGraphBinding(t *testing.T, handle ResourceHandle) GraphResourceBinding {
	t.Helper()
	binding, err := NewGraphResourceBinding(handle)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
