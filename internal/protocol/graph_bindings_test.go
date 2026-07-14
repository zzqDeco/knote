package protocol

import (
	"reflect"
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
		Supports: []ClaimSupportBinding{{
			SupportKey: mustClaimSupportKey(t, "support-chunk"), Provenance: provenance,
			ProvenanceResourceIDs: []ResourceID{chunk.ResourceID},
		}},
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
	brokenSupport := claimBinding
	brokenSupport.Supports = append([]ClaimSupportBinding(nil), claimBinding.Supports...)
	brokenSupport.Supports[0].ProvenanceResourceIDs = []ResourceID{document.ResourceID}
	if err := ValidateClaimTripleBindings(resources, []ClaimTripleBinding{brokenSupport}); err == nil {
		t.Fatal("support group with mismatched stable provenance was accepted")
	}
}

func TestUpgradeGraphBindingContractPreservesV1DerivationSemantics(t *testing.T) {
	for _, test := range []struct {
		name             string
		derivation       DerivationMode
		wantSupportCount int
		wantGroupSize    int
	}{
		{name: "all required", derivation: DerivationAllRequired, wantSupportCount: 1, wantGroupSize: 2},
		{name: "any support", derivation: DerivationAnySupport, wantSupportCount: 2, wantGroupSize: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			resources, claims := v1ClaimBindingFixture(t, test.derivation)
			if err := ValidateClaimTripleBindings(resources, claims); err != nil {
				t.Fatalf("v1 fixture is invalid: %v", err)
			}

			upgradedResources, upgradedClaims, err := UpgradeGraphBindingContract(resources, claims)
			if err != nil {
				t.Fatal(err)
			}
			repeatedResources, repeatedClaims, err := UpgradeGraphBindingContract(resources, claims)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(upgradedResources, repeatedResources) || !reflect.DeepEqual(upgradedClaims, repeatedClaims) {
				t.Fatal("v1 upgrade is not deterministic")
			}
			if err := ValidateClaimTripleBindings(upgradedResources, upgradedClaims); err != nil {
				t.Fatalf("upgraded v2 fixture is invalid: %v", err)
			}
			if upgradedResources[0].Version != GraphBindingContractVersion || upgradedClaims[0].Version != GraphBindingContractVersion {
				t.Fatal("v1 fixture did not upgrade to the current contract version")
			}
			if upgradedClaims[0].Claim == claims[0].Claim {
				t.Fatal("v1 claim graph identity was relabeled without a v2 identity migration")
			}
			if len(upgradedClaims[0].Supports) != test.wantSupportCount {
				t.Fatalf("support count = %d, want %d", len(upgradedClaims[0].Supports), test.wantSupportCount)
			}
			for _, support := range upgradedClaims[0].Supports {
				if len(support.Provenance) != test.wantGroupSize || len(support.ProvenanceResourceIDs) != test.wantGroupSize {
					t.Fatalf("support group size = (%d, %d), want %d", len(support.Provenance), len(support.ProvenanceResourceIDs), test.wantGroupSize)
				}
			}
		})
	}
}

func v1ClaimBindingFixture(t *testing.T, derivation DerivationMode) ([]GraphResourceBinding, []ClaimTripleBinding) {
	t.Helper()
	document := graphTestHandle(t, "00000000000000000000000000000001", ResourceDocument)
	chunkA := graphTestHandle(t, "00000000000000000000000000000002", ResourceChunk)
	chunkB := graphTestHandle(t, "00000000000000000000000000000006", ResourceChunk)
	for _, chunk := range []*ResourceHandle{&chunkA, &chunkB} {
		chunk.AuthorizationResourceID = document.ResourceID
		chunk.AuthorizationID = document.AuthorizationID
	}
	subject := graphTestHandle(t, "00000000000000000000000000000003", ResourceEntity)
	object := graphTestHandle(t, "00000000000000000000000000000004", ResourceEntity)
	claim := graphTestHandle(t, "00000000000000000000000000000005", ResourceClaim)
	resources := []GraphResourceBinding{
		mustGraphBindingVersion(t, GraphBindingContractVersionV1, document),
		mustGraphBindingVersion(t, GraphBindingContractVersionV1, chunkA),
		mustGraphBindingVersion(t, GraphBindingContractVersionV1, chunkB),
		mustGraphBindingVersion(t, GraphBindingContractVersionV1, subject),
		mustGraphBindingVersion(t, GraphBindingContractVersionV1, object),
		mustGraphBindingVersion(t, GraphBindingContractVersionV1, claim),
	}
	SortGraphResourceBindings(resources)
	byResource := make(map[ResourceID]GraphObjectID, len(resources))
	for _, resource := range resources {
		byResource[resource.Resource.ResourceID] = resource.GraphObjectID
	}
	predicate, err := NewClaimPredicateKey("located_in")
	if err != nil {
		t.Fatal(err)
	}
	provenance := canonicalGraphObjectIDs([]GraphObjectID{
		byResource[chunkA.ResourceID], byResource[chunkB.ResourceID],
	})
	return resources, []ClaimTripleBinding{{
		Version: GraphBindingContractVersionV1, Claim: byResource[claim.ResourceID],
		Subject: byResource[subject.ResourceID], PredicateKey: predicate, Object: byResource[object.ResourceID],
		SourceDocument: byResource[document.ResourceID], Derivation: derivation, Provenance: provenance,
	}}
}

func mustClaimSupportKey(t *testing.T, sourceIdentity string) ClaimSupportKey {
	t.Helper()
	key, err := NewClaimSupportKey(sourceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	return key
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

func mustGraphBindingVersion(t *testing.T, version int, handle ResourceHandle) GraphResourceBinding {
	t.Helper()
	graphObjectID, err := newGraphObjectID(version, handle.Versions.Projection, handle.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	binding := GraphResourceBinding{Version: version, GraphObjectID: graphObjectID, Resource: handle}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	return binding
}
