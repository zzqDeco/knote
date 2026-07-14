package catalog

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestSourceBackedClaimSupportModesAreCompleteSourceScopedAndDeterministic(t *testing.T) {
	for _, mode := range []protocol.DerivationMode{protocol.DerivationAnySupport, protocol.DerivationAllRequired} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newSourceBackedClaimFixture(t, "source-v1", "projection-v1", mode)
			canonical, err := fixture.catalog.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			record := canonical.Claims[0].Metadata.ClaimRecord
			if record == nil || !record.IsSourceBacked() || record.Provenance.DerivationMode != mode {
				t.Fatalf("source-backed Claim record was not persisted: %+v", record)
			}
			if got := []string{record.Provenance.Supports[0].SupportID, record.Provenance.Supports[1].SupportID}; !reflect.DeepEqual(got, []string{"support-document", "support-span"}) {
				t.Fatalf("support sets are not canonical: %v", got)
			}
			for _, support := range record.Provenance.Supports {
				if !support.Complete || len(support.Evidence) != 1 ||
					support.Evidence[0].Document != fixture.document.VersionRef() {
					t.Fatalf("support is not independently complete and source scoped: %+v", support)
				}
			}

			projection := publishedProjectionFromCatalog(t, canonical, fixture.document.Snapshot)
			resources, claims, err := ProjectionGraphBindings(projection)
			if err != nil {
				t.Fatal(err)
			}
			if len(claims) != 1 || claims[0].Derivation != mode || len(claims[0].ProvenanceResourceIDs) != 2 ||
				len(claims[0].Supports) != 2 {
				t.Fatalf("Claim binding did not preserve the complete support combination: %+v", claims)
			}
			documentSupport, err := protocol.NewClaimSupportKey("support-document")
			if err != nil {
				t.Fatal(err)
			}
			spanSupport, err := protocol.NewClaimSupportKey("support-span")
			if err != nil {
				t.Fatal(err)
			}
			gotSupports := []protocol.ClaimSupportKey{claims[0].Supports[0].SupportKey, claims[0].Supports[1].SupportKey}
			wantSupports := []protocol.ClaimSupportKey{documentSupport, spanSupport}
			sort.Slice(wantSupports, func(i, j int) bool { return wantSupports[i] < wantSupports[j] })
			if !reflect.DeepEqual(gotSupports, wantSupports) ||
				len(claims[0].Supports[0].ProvenanceResourceIDs) != 1 ||
				len(claims[0].Supports[1].ProvenanceResourceIDs) != 1 {
				t.Fatalf("Claim support boundaries were flattened: %+v", claims[0].Supports)
			}
			claimGraphBound := false
			for _, binding := range resources {
				claimGraphBound = claimGraphBound || binding.Resource.ResourceID == fixture.claim.Metadata.ResourceID
			}
			if !claimGraphBound {
				t.Fatal("source-backed Claim was not emitted as a graph resource")
			}
			repeatedResources, repeatedClaims, err := ProjectionGraphBindings(projection)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(resources, repeatedResources) || !reflect.DeepEqual(claims, repeatedClaims) {
				t.Fatal("repeated Claim projection was not deterministic")
			}
		})
	}

	fixture := newSourceBackedClaimFixture(t, "source-v1", "projection-v1", protocol.DerivationAnySupport)
	fixture.claim.Provenance.Supports[1].Complete = false
	if err := fixture.claim.Validate(); err == nil {
		t.Fatal("any_support accepted a branch that was not independently complete")
	}

	fixture = newSourceBackedClaimFixture(t, "source-v1", "projection-v1", protocol.DerivationAllRequired)
	fixture.claim.Provenance.Supports[1].Complete = false
	if err := fixture.claim.Validate(); err == nil {
		t.Fatal("source-backed all_required claim accepted incomplete support")
	}
}

func TestClaimBindingPreservesSupportGroupsWithIdenticalFlattenedProvenance(t *testing.T) {
	separate := newSourceBackedClaimFixture(t, "source-v1", "projection-v1", protocol.DerivationAnySupport)
	separateCanonical, err := separate.catalog.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	_, separateBindings, err := ProjectionGraphBindings(
		publishedProjectionFromCatalog(t, separateCanonical, separate.document.Snapshot),
	)
	if err != nil {
		t.Fatal(err)
	}

	combined := newSourceBackedClaimFixture(t, "source-v1", "projection-v1", protocol.DerivationAnySupport)
	combined.claim.Provenance.Supports = []Support{{
		SupportID: "support-combined",
		Evidence:  []EvidenceRef{combined.document.EvidenceRef(), combined.chunk.EvidenceRef()},
		Complete:  true,
	}}
	combined.catalog.Claims[0] = combined.claim
	combinedCanonical, err := combined.catalog.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	_, combinedBindings, err := ProjectionGraphBindings(
		publishedProjectionFromCatalog(t, combinedCanonical, combined.document.Snapshot),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(separateBindings[0].Provenance, combinedBindings[0].Provenance) ||
		!reflect.DeepEqual(separateBindings[0].ProvenanceResourceIDs, combinedBindings[0].ProvenanceResourceIDs) {
		t.Fatal("fixtures did not produce identical flattened provenance")
	}
	if reflect.DeepEqual(separateBindings[0].Supports, combinedBindings[0].Supports) ||
		len(separateBindings[0].Supports) != 2 || len(combinedBindings[0].Supports) != 1 {
		t.Fatalf("support grouping was not preserved: separate=%+v combined=%+v", separateBindings[0].Supports, combinedBindings[0].Supports)
	}
}

func TestProjectionGraphBindingsRequireMaterializedDerivedArtifactSecurity(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1", "content-document-v1", "projection-v1", "", "doc:a"),
		Snapshot: snapshot.Ref(), Path: "sources/a.md",
	}
	artifact := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:summary", "artifact", "source-v1", "content-artifact-v1", "projection-v1", "", "artifact:summary"),
		Kind:     "summary",
		Provenance: Provenance{DerivationMode: protocol.DerivationAllRequired, Supports: []Support{{
			SupportID: "support-document", Evidence: []EvidenceRef{document.EvidenceRef()}, Complete: true,
		}}},
	}
	materializeDerivedArtifactSecurity(t, &artifact, document.Metadata)
	resources, err := (Catalog{Documents: []Document{document}, DerivedArtifacts: []DerivedArtifact{artifact}}).ResourceMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for i := range resources {
		resources[i] = published(resources[i])
	}
	projection := testProjection(t, scope, "projection-v1", snapshot.Ref(), resources)
	bindings, _, err := ProjectionGraphBindings(projection)
	if err != nil {
		t.Fatal(err)
	}
	foundArtifact := false
	for _, binding := range bindings {
		foundArtifact = foundArtifact || binding.Resource.ResourceID == artifact.Metadata.ResourceID
	}
	if !foundArtifact {
		t.Fatal("materialized derived artifact was omitted from graph bindings")
	}

	legacyResources := append([]ResourceMetadata(nil), resources...)
	for i := range legacyResources {
		if legacyResources[i].ResourceID == artifact.Metadata.ResourceID {
			legacyResources[i].DerivedArtifactSecurity = nil
		}
	}
	legacy := testProjection(t, scope, "projection-v1", snapshot.Ref(), legacyResources)
	legacyBindings, _, err := ProjectionGraphBindings(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range legacyBindings {
		if binding.Resource.ResourceID == artifact.Metadata.ResourceID {
			t.Fatal("legacy derived artifact without a security record leaked into graph bindings")
		}
	}
}

func TestSourceBackedClaimRejectsCrossDocumentVersionAndUndeclaredKeys(t *testing.T) {
	fixture := newSourceBackedClaimFixture(t, "source-v2", "projection-v2", protocol.DerivationAllRequired)
	otherDocumentID, err := protocol.NewStableResourceID(
		fixture.claim.Metadata.Scope.TenantID,
		fixture.claim.Metadata.Scope.KnowledgeBaseID,
		protocol.ResourceDocument,
		"sources/other.md",
	)
	if err != nil {
		t.Fatal(err)
	}

	crossDocument := fixture.claim
	crossDocument.Provenance = crossDocument.Provenance.normalized()
	crossDocument.Provenance.Supports[0].Evidence[0].Document.ResourceID = otherDocumentID
	if err := crossDocument.Validate(); err == nil {
		t.Fatal("Claim merged support from another source document")
	}

	crossVersion := fixture.claim
	crossVersion.Provenance = crossVersion.Provenance.normalized()
	crossVersion.Provenance.Supports[0].Evidence[0].Document.SourceVersion = "source-v1"
	crossVersion.Provenance.Supports[0].Evidence[0].Versions.Source = "source-v1"
	if err := crossVersion.Validate(); err == nil {
		t.Fatal("Claim merged support from another source version")
	}

	const rawQuery = "MATCH (n:PrivateLabel) RETURN n.secret"
	undeclared := fixture.claim
	undeclared.PredicateKey = protocol.ClaimPredicateKey(rawQuery)
	err = undeclared.Validate()
	if err == nil || !errorsIsInvalidClaimRecord(err) || strings.Contains(err.Error(), rawQuery) {
		t.Fatalf("undeclared predicate error was not generic: %v", err)
	}

	resource := fixture.claim.Metadata
	resource.Type = protocol.ResourceType(rawQuery)
	err = resource.Validate()
	if err == nil || strings.Contains(err.Error(), rawQuery) {
		t.Fatalf("undeclared resource kind error exposed input: %v", err)
	}
}

func TestFullReconciliationRemovesStaleSourceBackedClaimFromEveryServingProjection(t *testing.T) {
	currentFixture := newSourceBackedClaimFixture(t, "source-v1", "projection-v1", protocol.DerivationAllRequired)
	currentCanonical, err := currentFixture.catalog.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	current := publishedProjectionFromCatalog(t, currentCanonical, currentFixture.document.Snapshot)
	_, currentClaims, err := ProjectionGraphBindings(current)
	if err != nil || len(currentClaims) != 1 {
		t.Fatalf("current source-backed Claim projection: claims=%+v err=%v", currentClaims, err)
	}

	desiredFixture := newSourceBackedClaimFixture(t, "source-v2", "projection-v2", protocol.DerivationAllRequired)
	desiredFixture.catalog.Claims = nil
	desiredCanonical, err := desiredFixture.catalog.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	run := testRun(current.Scope, current.Version, "projection-v2", desiredFixture.document.Snapshot)
	plan, err := PlanFullReconciliation(run, current, desiredCanonical)
	if err != nil {
		t.Fatal(err)
	}
	next, report, err := Replay(plan, current, SuccessfulResults(plan))
	if err != nil {
		t.Fatal(err)
	}
	if report.RunState != RunSucceeded || next.IsServing(currentFixture.claim.Metadata.ResourceID) {
		t.Fatalf("stale Claim remained in the serving Catalog: %+v", next)
	}
	for _, resource := range next.Resources {
		if resource.ResourceID == currentFixture.claim.Metadata.ResourceID && resource.ClaimRecord != nil {
			t.Fatalf("stale Claim record remained in the replacement projection: %+v", resource)
		}
	}
	resources, claims, err := ProjectionGraphBindings(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 0 {
		t.Fatalf("stale Claim binding remained after reconciliation: %+v", claims)
	}
	for _, binding := range resources {
		if binding.Resource.Type == protocol.ResourceClaim ||
			binding.Resource.ResourceID == currentFixture.claim.Metadata.ResourceID {
			t.Fatalf("stale graph Claim resource remained after reconciliation: %+v", binding)
		}
	}
}

type sourceBackedClaimFixture struct {
	catalog  Catalog
	document Document
	chunk    Chunk
	claim    Claim
}

func newSourceBackedClaimFixture(
	t *testing.T,
	sourceVersion string,
	projectionVersion string,
	mode protocol.DerivationMode,
) sourceBackedClaimFixture {
	t.Helper()
	scope := testScope()
	snapshot := testSnapshot(t, scope, sourceVersion, "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "sources/a.md:"+sourceVersion, sourceVersion,
			"content-document-"+sourceVersion, projectionVersion, "", "document:sources/a.md"),
		Snapshot: snapshot.Ref(), Path: "sources/a.md",
	}
	chunk := Chunk{
		Metadata: testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", sourceVersion,
			"content-chunk-"+sourceVersion, projectionVersion, document.Metadata.ResourceID, document.Metadata.AuthorizationObject),
		Document: document.VersionRef(), Ordinal: 0, Span: [2]int{0, 10},
	}
	entityProvenance := Provenance{DerivationMode: protocol.DerivationAnySupport, Supports: []Support{{
		SupportID: "entity-source", Evidence: []EvidenceRef{chunk.EvidenceRef()}, Complete: true,
	}}}
	subject := Entity{
		Metadata: testMetadata(t, scope, protocol.ResourceEntity, "entity:subject", "subject", sourceVersion,
			"content-subject-"+sourceVersion, projectionVersion, "", "entity:subject"),
		Name: "Subject", EntityType: "Topic", Provenance: entityProvenance,
	}
	object := Entity{
		Metadata: testMetadata(t, scope, protocol.ResourceEntity, "entity:object", "object", sourceVersion,
			"content-object-"+sourceVersion, projectionVersion, "", "entity:object"),
		Name: "Object", EntityType: "Place", Provenance: entityProvenance,
	}
	predicate, err := protocol.NewClaimPredicateKey(string(protocol.ClaimPredicateLocatedIn))
	if err != nil {
		t.Fatal(err)
	}
	claim := Claim{
		Metadata: testMetadata(t, scope, protocol.ResourceClaim, "claim:subject-located-in-object", "claim", sourceVersion,
			"content-claim-"+sourceVersion, projectionVersion, "", "claim:semantic"),
		BindingState: ClaimBindingSourceBacked, SubjectResourceID: subject.Metadata.ResourceID,
		PredicateKey: predicate, ObjectResourceID: object.Metadata.ResourceID,
		SourceDocument: document.VersionRef(), Text: "semantic claim",
		Provenance: Provenance{DerivationMode: mode, Supports: []Support{
			{SupportID: "support-span", Evidence: []EvidenceRef{chunk.EvidenceRef()}, Complete: true},
			{SupportID: "support-document", Evidence: []EvidenceRef{document.EvidenceRef()}, Complete: true},
		}},
	}
	return sourceBackedClaimFixture{
		catalog: Catalog{
			Documents: []Document{document}, Chunks: []Chunk{chunk},
			Entities: []Entity{subject, object}, Claims: []Claim{claim},
		},
		document: document, chunk: chunk, claim: claim,
	}
}

func publishedProjectionFromCatalog(t *testing.T, value Catalog, snapshot SourceSnapshotRef) Projection {
	t.Helper()
	resources, err := value.ResourceMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for index := range resources {
		resources[index] = published(resources[index])
	}
	return testProjection(t, snapshot.Scope, resources[0].Versions.Projection, snapshot, resources)
}

func errorsIsInvalidClaimRecord(err error) bool {
	return err == ErrInvalidClaimRecord || strings.Contains(err.Error(), ErrInvalidClaimRecord.Error())
}
