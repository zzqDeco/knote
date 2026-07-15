package catalog

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	phase2CatalogProjectionV1 = "projection-phase2-v1"
	phase2CatalogProjectionV2 = "projection-phase2-v2"
)

func TestPhase2FullReconciliationAcceptanceRemovesStaleContentBindingsAndClaims(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(
		t, scope, "source-phase2-v1", "sources/keep.md", "sources/stale.md",
	)
	keepV1 := newPhase2CatalogClaimPath(
		t, currentSnapshot.Ref(), phase2CatalogProjectionV1, "sources/keep.md", "keep",
	)
	staleV1 := newPhase2CatalogClaimPath(
		t, currentSnapshot.Ref(), phase2CatalogProjectionV1, "sources/stale.md", "stale",
	)
	currentCatalog := phase2MergeCatalogPaths(keepV1, staleV1)
	currentCanonical, err := currentCatalog.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	currentResources, err := currentCanonical.ResourceMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for index := range currentResources {
		currentResources[index] = published(currentResources[index])
	}
	current := testProjection(
		t, scope, phase2CatalogProjectionV1, currentSnapshot.Ref(), currentResources,
	)
	currentGraphResources, currentClaims, err := ProjectionGraphBindings(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(currentClaims) != 2 || !phase2GraphResourcesContain(
		currentGraphResources, staleV1.claim.Metadata.ResourceID,
	) {
		t.Fatalf("stale Claim was not present before reconciliation: resources=%+v claims=%+v", currentGraphResources, currentClaims)
	}

	nextSnapshot := testSnapshot(t, scope, "source-phase2-v2", "sources/keep.md")
	keepV2 := newPhase2CatalogClaimPath(
		t, nextSnapshot.Ref(), phase2CatalogProjectionV2, "sources/keep.md", "keep",
	)
	desired, err := keepV2.catalog.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	run := testRun(scope, current.Version, phase2CatalogProjectionV2, nextSnapshot.Ref())
	run.RunID = "run-phase2-full-reconciliation"
	run.IdempotencyKey = "sync-phase2-full-reconciliation"
	plan, err := PlanFullReconciliation(run, current, desired)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := PlanFullReconciliation(run, current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, repeated) {
		t.Fatalf("full reconciliation plan is not deterministic:\nfirst=%+v\nsecond=%+v", plan, repeated)
	}

	next, report, err := Replay(plan, current, SuccessfulResults(plan))
	if err != nil {
		t.Fatal(err)
	}
	if report.RunState != RunSucceeded || next.State != StatePublished ||
		next.SourceSnapshot != nextSnapshot.Ref() {
		t.Fatalf("full reconciliation outcome: report=%+v projection=%+v", report, next)
	}

	staleIDs := staleV1.resourceIDs()
	staleSet := make(map[protocol.ResourceID]struct{}, len(staleIDs))
	for _, resourceID := range staleIDs {
		staleSet[resourceID] = struct{}{}
		resource := acceptanceResourceByID(
			t, "stale Phase 2 resources leave every serving surface",
			phase2CatalogProjectionV2, acceptanceAuthzVersion, next, resourceID,
		)
		if resource.ServingState != StateTombstoned || resource.IsServing() || next.IsServing(resourceID) {
			t.Fatalf("stale resource %s remains serving: %+v", resourceID, resource)
		}
		if resource.Type == protocol.ResourceClaim && resource.ClaimRecord != nil {
			t.Fatalf("stale Claim %s retained its projection record: %+v", resourceID, resource.ClaimRecord)
		}
	}
	for _, resource := range next.Resources {
		if resource.IsServing() && resource.ContentDigest == staleV1.document.Metadata.ContentDigest {
			t.Fatalf("stale document content remains serving through %s", resource.ResourceID)
		}
	}
	for _, resourceID := range keepV2.resourceIDs() {
		if !next.IsServing(resourceID) {
			t.Fatalf("retained resource %s is not serving after reconciliation", resourceID)
		}
	}

	nextGraphResources, nextClaims, err := ProjectionGraphBindings(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProjectionGraphBindings(next, nextGraphResources, nextClaims); err != nil {
		t.Fatal(err)
	}
	for _, binding := range nextGraphResources {
		if _, stale := staleSet[binding.Resource.ResourceID]; stale {
			t.Fatalf("stale graph resource binding remains: %+v", binding)
		}
	}
	if len(nextClaims) != 1 ||
		nextClaims[0].SubjectResourceID != keepV2.subject.Metadata.ResourceID ||
		nextClaims[0].ObjectResourceID != keepV2.object.Metadata.ResourceID ||
		nextClaims[0].SourceDocumentResourceID != keepV2.document.Metadata.ResourceID ||
		nextClaims[0].SourceVersion != nextSnapshot.Ref().Version {
		t.Fatalf("replacement Claim bindings = %+v", nextClaims)
	}
	repeatedResources, repeatedClaims, err := ProjectionGraphBindings(next)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nextGraphResources, repeatedResources) || !reflect.DeepEqual(nextClaims, repeatedClaims) {
		t.Fatalf("replacement graph bindings are not deterministic")
	}
}

func TestPhase2ProjectionSkewAcceptancePublishesOneCompleteVersionSet(t *testing.T) {
	const skewSLO = 25 * time.Millisecond
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), phase2CatalogProjectionV2)
	componentAt := make(map[OperationKind]time.Duration, 4)
	componentVersions := make(map[OperationKind]protocol.ResourceVersions, 4)
	elapsed := time.Duration(0)
	executor := OperationExecutorFunc(func(_ context.Context, operation ProjectionOperation) (OperationResult, error) {
		switch operation.Kind {
		case OperationProjectContent, OperationProjectACL, OperationProjectIndex, OperationProjectGraph:
			elapsed += 5 * time.Millisecond
			componentAt[operation.Kind] = elapsed
			componentVersions[operation.Kind] = operation.Resource.Versions
		}
		return OperationResult{OperationID: operation.OperationID, Outcome: OperationSucceeded}, nil
	})
	execution, err := store.Execute(context.Background(), plan, current, executor)
	if err != nil {
		t.Fatal(err)
	}
	required := []OperationKind{
		OperationProjectContent, OperationProjectACL, OperationProjectIndex, OperationProjectGraph,
	}
	earliest, latest := time.Duration(0), time.Duration(0)
	var versions protocol.ResourceVersions
	for index, kind := range required {
		observedAt, ok := componentAt[kind]
		if !ok {
			t.Fatalf("component %s was not projected", kind)
		}
		if index == 0 || observedAt < earliest {
			earliest = observedAt
		}
		if observedAt > latest {
			latest = observedAt
		}
		if index == 0 {
			versions = componentVersions[kind]
		} else if componentVersions[kind] != versions {
			t.Fatalf("component %s versions=%+v, want %+v", kind, componentVersions[kind], versions)
		}
	}
	skew := latest - earliest
	if skew < 0 || skew > skewSLO {
		t.Fatalf("content/ACL/index/graph skew=%s exceeds %s", skew, skewSLO)
	}
	if execution.Report.RunState != RunSucceeded || !execution.PointerAdvanced ||
		execution.Projection.State != StatePublished {
		t.Fatalf("complete version set did not publish: %+v", execution)
	}
	resource := acceptanceResourceByID(
		t, "Phase 2 complete projection version set", phase2CatalogProjectionV2,
		acceptanceAuthzVersion, execution.Projection, plan.Operations[0].Resource.ResourceID,
	)
	if !resource.ProjectionStatus.Ready() || resource.Versions != versions {
		t.Fatalf("published resource has skewed component state: %+v", resource)
	}
	t.Logf(
		"metric=content_acl_index_graph_skew duration=%s slo=%s projection_version=%q authz_version=%q",
		skew, skewSLO, phase2CatalogProjectionV2, versions.ACL,
	)
}

type phase2CatalogClaimPath struct {
	catalog  Catalog
	document Document
	chunk    Chunk
	subject  Entity
	object   Entity
	claim    Claim
}

func newPhase2CatalogClaimPath(
	t *testing.T,
	snapshot SourceSnapshotRef,
	projectionVersion string,
	path string,
	suffix string,
) phase2CatalogClaimPath {
	t.Helper()
	document := Document{
		Metadata: testMetadata(
			t, snapshot.Scope, protocol.ResourceDocument, path, path+":"+snapshot.Version,
			snapshot.Version, "content-document-"+suffix+"-"+snapshot.Version,
			projectionVersion, "", "document:"+path,
		),
		Snapshot: snapshot,
		Path:     path,
	}
	chunk := Chunk{
		Metadata: testMetadata(
			t, snapshot.Scope, protocol.ResourceChunk, path+"#chunk:0", "chunk "+suffix,
			snapshot.Version, "content-chunk-"+suffix+"-"+snapshot.Version,
			projectionVersion, document.Metadata.ResourceID, document.Metadata.AuthorizationObject,
		),
		Document: document.VersionRef(), Ordinal: 0, Span: [2]int{0, 10},
	}
	entityProvenance := Provenance{
		DerivationMode: protocol.DerivationAnySupport,
		Supports: []Support{{
			SupportID: "entity-support-" + suffix,
			Evidence:  []EvidenceRef{chunk.EvidenceRef()}, Complete: true,
		}},
	}
	subject := Entity{
		Metadata: testMetadata(
			t, snapshot.Scope, protocol.ResourceEntity, "entities/"+suffix+"/subject", "subject "+suffix,
			snapshot.Version, "content-subject-"+suffix+"-"+snapshot.Version,
			projectionVersion, "", "entity:phase2-"+suffix+"-subject",
		),
		Name: "Subject " + suffix, EntityType: "Topic", Provenance: entityProvenance,
	}
	object := Entity{
		Metadata: testMetadata(
			t, snapshot.Scope, protocol.ResourceEntity, "entities/"+suffix+"/object", "object "+suffix,
			snapshot.Version, "content-object-"+suffix+"-"+snapshot.Version,
			projectionVersion, "", "entity:phase2-"+suffix+"-object",
		),
		Name: "Object " + suffix, EntityType: "Place", Provenance: entityProvenance,
	}
	predicate, err := protocol.NewClaimPredicateKey(string(protocol.ClaimPredicateLocatedIn))
	if err != nil {
		t.Fatal(err)
	}
	claim := Claim{
		Metadata: testMetadata(
			t, snapshot.Scope, protocol.ResourceClaim, "claims/"+suffix, "claim "+suffix,
			snapshot.Version, "content-claim-"+suffix+"-"+snapshot.Version,
			projectionVersion, "", "claim:phase2-"+suffix,
		),
		BindingState: ClaimBindingSourceBacked, SubjectResourceID: subject.Metadata.ResourceID,
		PredicateKey: predicate, ObjectResourceID: object.Metadata.ResourceID,
		SourceDocument: document.VersionRef(), Text: "Phase 2 claim " + suffix,
		Provenance: Provenance{
			DerivationMode: protocol.DerivationAllRequired,
			Supports: []Support{
				{SupportID: "document-support-" + suffix, Evidence: []EvidenceRef{document.EvidenceRef()}, Complete: true},
				{SupportID: "span-support-" + suffix, Evidence: []EvidenceRef{chunk.EvidenceRef()}, Complete: true},
			},
		},
	}
	return phase2CatalogClaimPath{
		catalog: Catalog{
			Documents: []Document{document}, Chunks: []Chunk{chunk},
			Entities: []Entity{subject, object}, Claims: []Claim{claim},
		},
		document: document, chunk: chunk, subject: subject, object: object, claim: claim,
	}
}

func phase2MergeCatalogPaths(paths ...phase2CatalogClaimPath) Catalog {
	var result Catalog
	for _, path := range paths {
		result.Documents = append(result.Documents, path.document)
		result.Chunks = append(result.Chunks, path.chunk)
		result.Entities = append(result.Entities, path.subject, path.object)
		result.Claims = append(result.Claims, path.claim)
	}
	return result
}

func (path phase2CatalogClaimPath) resourceIDs() []protocol.ResourceID {
	return []protocol.ResourceID{
		path.document.Metadata.ResourceID,
		path.chunk.Metadata.ResourceID,
		path.subject.Metadata.ResourceID,
		path.object.Metadata.ResourceID,
		path.claim.Metadata.ResourceID,
	}
}

func phase2GraphResourcesContain(
	resources []protocol.GraphResourceBinding,
	resourceID protocol.ResourceID,
) bool {
	for _, binding := range resources {
		if binding.Resource.ResourceID == resourceID {
			return true
		}
	}
	return false
}
