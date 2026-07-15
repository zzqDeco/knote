package authz

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestProjectCatalogClaimTuplesIsDeterministicAndBodyFree(t *testing.T) {
	projection := testCatalogProjection(t, "projection-v2")
	first, err := ProjectCatalogClaimTuples(projection)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProjectCatalogClaimTuples(projection)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("equal Catalog projections produced different tuple bytes:\n%s\n%s", firstJSON, secondJSON)
	}
	if bytes.Contains(firstJSON, []byte("claim-content-must-not-escape")) {
		t.Fatalf("tuple projection leaked Claim content: %s", firstJSON)
	}
	if len(first.Bindings) != 6 {
		t.Fatalf("binding count = %d, want 6 serving source-backed Claim bindings", len(first.Bindings))
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("projected bindings are invalid: %v", err)
	}
	for index := 1; index < len(first.Bindings); index++ {
		if catalogTupleBindingLess(first.Bindings[index], first.Bindings[index-1]) {
			t.Fatalf("bindings are not canonical: %#v", first.Bindings)
		}
	}

	want := map[Tuple]struct{}{
		{User: "document:source", Relation: RelationSourceDocument, Object: "claim:alpha"}: {},
		{User: "entity:alpha-subject", Relation: RelationSubject, Object: "claim:alpha"}:   {},
		{User: "entity:alpha-object", Relation: RelationObject, Object: "claim:alpha"}:     {},
		{User: "document:source", Relation: RelationSourceDocument, Object: "claim:zeta"}:  {},
		{User: "entity:zeta-subject", Relation: RelationSubject, Object: "claim:zeta"}:     {},
		{User: "entity:zeta-object", Relation: RelationObject, Object: "claim:zeta"}:       {},
	}
	for _, binding := range first.Bindings {
		if _, ok := want[binding.Tuple]; !ok {
			t.Fatalf("unexpected tuple binding: %#v", binding)
		}
		delete(want, binding.Tuple)
	}
	if len(want) != 0 {
		t.Fatalf("missing tuple bindings: %#v", want)
	}
}

func TestProjectCatalogClaimTuplesRejectsWrongAuthorizationType(t *testing.T) {
	projection := testCatalogProjection(t, "projection-v2")
	for index := range projection.Resources {
		resource := &projection.Resources[index]
		if resource.AuthorizationObject == "entity:alpha-subject" {
			resource.AuthorizationObject = "document:wrong-type"
		}
	}
	if _, err := ProjectCatalogClaimTuples(projection); err == nil {
		t.Fatal("wrong entity authorization type was accepted")
	}
}

func testCatalogProjection(t *testing.T, projectionVersion string) catalog.Projection {
	t.Helper()
	scope := catalog.Scope{TenantID: "tenant-authz", KnowledgeBaseID: "kb-authz"}
	versions := protocol.ResourceVersions{
		Source: "source-v2", Content: "content-v2", ACL: "acl-v2",
		Index: "index-v2", Graph: "graph-v2", Projection: projectionVersion,
	}
	documentDigest := protocol.NewContentDigest("document-content")
	document := testPublishedMetadata(
		t, scope, protocol.ResourceDocument, "source", "document:source",
		documentDigest, versions,
	)
	snapshot, err := catalog.NewSourceSnapshot(
		scope,
		"source-authz",
		versions.Source,
		"security-authz",
		[]catalog.SourceDocumentSnapshot{{
			SourceKey: "source", SourceVersion: versions.Source, ContentDigest: documentDigest,
			ACLVersion: versions.ACL, AuthorizationObject: document.AuthorizationObject,
			Sensitivity: catalog.SensitivityInternal, SecurityDomain: "security-authz",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	documentRef := catalog.DocumentVersionRef{
		ResourceID: document.ResourceID, SourceVersion: versions.Source,
		ContentVersion: versions.Content, ACLVersion: versions.ACL,
		ProjectionVersion: projectionVersion,
	}
	provenance := catalog.Provenance{
		DerivationMode: protocol.DerivationAllRequired,
		Supports: []catalog.Support{{
			SupportID: "support-source", Complete: true,
			Evidence: []catalog.EvidenceRef{{
				ResourceID: document.ResourceID, Type: protocol.ResourceDocument,
				Versions: versions, Document: documentRef,
			}},
		}},
	}
	predicate, err := protocol.NewClaimPredicateKey(string(protocol.ClaimPredicateRelatedTo))
	if err != nil {
		t.Fatal(err)
	}

	chunk, err := catalog.NewResourceMetadata(
		scope,
		protocol.ResourceChunk,
		"source#chunk:0",
		document.AuthorizationObject,
		document.ResourceID,
		protocol.NewContentDigest("document-chunk"),
		versions,
		catalog.SensitivityInternal,
		"security-authz",
	)
	if err != nil {
		t.Fatal(err)
	}
	chunk.ServingState = catalog.StatePublished
	chunk.ProjectionStatus = catalog.SucceededProjectionStatus()
	chunk.Dependencies = []protocol.ResourceID{document.ResourceID}

	resources := []catalog.ResourceMetadata{document, chunk}
	for _, suffix := range []string{"alpha", "zeta"} {
		subject := testPublishedMetadata(
			t, scope, protocol.ResourceEntity, suffix+"-subject", "entity:"+suffix+"-subject",
			protocol.NewContentDigest(suffix+"-subject"), versions,
		)
		subject.Dependencies = []protocol.ResourceID{document.ResourceID}
		object := testPublishedMetadata(
			t, scope, protocol.ResourceEntity, suffix+"-object", "entity:"+suffix+"-object",
			protocol.NewContentDigest(suffix+"-object"), versions,
		)
		object.Dependencies = []protocol.ResourceID{document.ResourceID}
		claim := testPublishedMetadata(
			t, scope, protocol.ResourceClaim, suffix, "claim:"+suffix,
			protocol.NewContentDigest("claim-content-must-not-escape-"+suffix), versions,
		)
		claim.ClaimRecord = &catalog.ClaimProjectionRecord{
			BindingState:      catalog.ClaimBindingSourceBacked,
			SubjectResourceID: subject.ResourceID,
			PredicateKey:      predicate,
			ObjectResourceID:  object.ResourceID,
			SourceDocument:    documentRef,
			Provenance:        provenance,
		}
		claim.Dependencies = canonicalTestResourceIDs(
			document.ResourceID, subject.ResourceID, object.ResourceID,
		)
		resources = append(resources, subject, object, claim)
	}

	unbound := testPublishedMetadata(
		t, scope, protocol.ResourceClaim, "unbound", "claim:unbound",
		protocol.NewContentDigest("unbound"), versions,
	)
	unbound.ClaimRecord = &catalog.ClaimProjectionRecord{
		BindingState:   catalog.ClaimBindingUnbound,
		SourceDocument: documentRef,
		Provenance:     provenance,
	}
	unbound.Dependencies = []protocol.ResourceID{document.ResourceID}
	resources = append(resources, unbound)

	revoked := testPublishedMetadata(
		t, scope, protocol.ResourceClaim, "revoked", "claim:revoked",
		protocol.NewContentDigest("revoked"), versions,
	)
	revoked.ServingState = catalog.StateRevoked
	revoked.ClaimRecord = &catalog.ClaimProjectionRecord{
		BindingState:   catalog.ClaimBindingUnbound,
		SourceDocument: documentRef,
		Provenance:     provenance,
	}
	revoked.Dependencies = []protocol.ResourceID{document.ResourceID}
	resources = append(resources, revoked)

	projection, err := catalog.NewProjection(
		scope, projectionVersion, snapshot.Ref(), catalog.StatePublished, resources,
	)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func testPublishedMetadata(
	t *testing.T,
	scope catalog.Scope,
	resourceType protocol.ResourceType,
	sourceKey string,
	authorizationObject string,
	digest protocol.ContentDigest,
	versions protocol.ResourceVersions,
) catalog.ResourceMetadata {
	t.Helper()
	metadata, err := catalog.NewResourceMetadata(
		scope,
		resourceType,
		sourceKey,
		authorizationObject,
		"",
		digest,
		versions,
		catalog.SensitivityInternal,
		"security-authz",
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata.ServingState = catalog.StatePublished
	metadata.ProjectionStatus = catalog.SucceededProjectionStatus()
	return metadata
}

func canonicalTestResourceIDs(resourceIDs ...protocol.ResourceID) []protocol.ResourceID {
	result := append([]protocol.ResourceID(nil), resourceIDs...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
