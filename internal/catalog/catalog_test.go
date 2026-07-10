package catalog

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestStableResourceIdentityAndImmutableSourceSnapshot(t *testing.T) {
	scope := testScope()
	documents := []SourceDocumentSnapshot{
		testSnapshotDocument("sources/b.md", "source-v2", "b"),
		testSnapshotDocument("sources/a.md", "source-v2", "a"),
	}
	snapshot, err := NewSourceSnapshot(scope, "git", "source-v2", "repo:knote", documents)
	if err != nil {
		t.Fatal(err)
	}
	digest := snapshot.Ref().Digest
	documents[0].SourceKey = "mutated-input"
	copy := snapshot.Documents()
	copy[0].SourceKey = "mutated-output"
	if got := snapshot.Documents(); got[0].SourceKey != "sources/a.md" || got[1].SourceKey != "sources/b.md" {
		t.Fatalf("snapshot documents were mutable or not canonical: %+v", got)
	}
	if snapshot.Ref().Digest != digest {
		t.Fatal("immutable snapshot digest changed after caller mutations")
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("validate immutable snapshot: %v", err)
	}

	first := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "body-v1", "source-v2", "content-v1", "projection-v2", "", "doc:a")
	second := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "body-v2", "source-v2", "content-v2", "projection-v2", "", "doc:a")
	if first.ResourceID != second.ResourceID {
		t.Fatalf("content update changed stable resource identity: %s != %s", first.ResourceID, second.ResourceID)
	}
	if first.ContentDigest == second.ContentDigest {
		t.Fatal("content update did not change the canonical content digest")
	}
	if first.Versions.Content == second.Versions.Content {
		t.Fatal("content update did not advance the content version")
	}
}

func TestSourceSnapshotRejectsMixedVersionAndSecurityDomainAndRoundTrips(t *testing.T) {
	scope := testScope()
	wrongVersion := []SourceDocumentSnapshot{testSnapshotDocument("sources/a.md", "source-v1", "a")}
	if _, err := NewSourceSnapshot(scope, "git", "source-v2", "repo:knote", wrongVersion); err == nil {
		t.Fatal("snapshot accepted a document from another source version")
	}
	mixedDomains := []SourceDocumentSnapshot{
		testSnapshotDocument("sources/a.md", "source-v2", "a"),
		testSnapshotDocument("sources/b.md", "source-v2", "b"),
	}
	mixedDomains[1].SecurityDomain = "repo:other"
	if _, err := NewSourceSnapshot(scope, "git", "source-v2", "repo:knote", mixedDomains); err == nil {
		t.Fatal("snapshot accepted mixed security domains")
	}

	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SourceSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.Ref(), decoded.Ref()) || !reflect.DeepEqual(snapshot.Documents(), decoded.Documents()) {
		t.Fatalf("snapshot round trip changed value: before=%+v after=%+v", snapshot, decoded)
	}
}

func TestCanonicalTypesPinProvenanceToDocumentVersions(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	documentMetadata := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v2", "content-doc-v2", "projection-v2", "", "doc:a")
	document := Document{
		Metadata: documentMetadata, Snapshot: snapshot.Ref(), Path: "sources/a.md", Title: "A",
	}
	if err := document.Validate(); err != nil {
		t.Fatalf("document: %v", err)
	}

	chunkMetadata := testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", "source-v2", "content-chunk-v2", "projection-v2", document.Metadata.ResourceID, document.Metadata.AuthorizationObject)
	chunk := Chunk{
		Metadata: chunkMetadata, Document: document.VersionRef(), Ordinal: 0, Span: [2]int{0, 5},
	}
	if err := chunk.Validate(); err != nil {
		t.Fatalf("chunk: %v", err)
	}

	provenance := Provenance{
		DerivationMode: protocol.DerivationAnySupport,
		Supports: []Support{{
			SupportID: "support-a-v2", Complete: true,
			Evidence: []EvidenceRef{chunk.EvidenceRef()},
		}},
	}
	claimMetadata := testMetadata(t, scope, protocol.ResourceClaim, "sources/a.md#claim:0", "claim", "source-v2", "content-claim-v2", "projection-v2", "", "claim:a:0")
	claim := Claim{
		Metadata: claimMetadata, SourceDocument: document.VersionRef(),
		Text: "A source-scoped claim", Confidence: "high", Provenance: provenance,
	}
	if claim.Metadata.AuthorizationResourceID != claim.Metadata.ResourceID {
		t.Fatal("claim authorization should be independent from its source document")
	}
	if err := claim.Validate(); err != nil {
		t.Fatalf("source-scoped claim: %v", err)
	}

	entity := Entity{
		Metadata: testMetadata(t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v2", "content-entity-v2", "projection-v2", "", "entity:a"),
		Name:     "A", EntityType: "Topic", Aliases: []string{"Topic A"}, Provenance: provenance,
	}
	artifact := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:a", "artifact", "source-v2", "content-artifact-v2", "projection-v2", "", "artifact:a"),
		Kind:     "summary", Provenance: Provenance{Supports: provenance.Supports},
	}
	catalog := Catalog{
		Documents: []Document{document}, Chunks: []Chunk{chunk}, Entities: []Entity{entity},
		Claims: []Claim{claim}, DerivedArtifacts: []DerivedArtifact{artifact},
	}
	canonical, err := catalog.Canonical()
	if err != nil {
		t.Fatalf("canonical catalog: %v", err)
	}
	if canonical.DerivedArtifacts[0].Provenance.DerivationMode != protocol.DerivationAllRequired {
		t.Fatalf("derived artifact default was not materialized: %+v", canonical.DerivedArtifacts[0])
	}
	resources, err := canonical.ResourceMetadata()
	if err != nil {
		t.Fatalf("canonical catalog: %v", err)
	}
	if len(resources) != 5 {
		t.Fatalf("catalog resource count = %d, want 5", len(resources))
	}
	for i := 1; i < len(resources); i++ {
		if resources[i-1].ResourceID > resources[i].ResourceID {
			t.Fatalf("catalog metadata is not sorted: %+v", resources)
		}
	}

	wrongVersion := claim
	wrongVersion.SourceDocument.ContentVersion = "content-doc-v1"
	if err := wrongVersion.Validate(); err == nil {
		t.Fatal("claim provenance from another document version should fail")
	}
}

func TestProjectionPlanIsDeterministicAndBoundToRun(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md", "sources/b.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	a := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a", "source-v2", "content-a-v2", run.ProjectionVersion, "", "doc:a")
	b := testMetadata(t, scope, protocol.ResourceDocument, "sources/b.md", "b", "source-v2", "content-b-v2", run.ProjectionVersion, "", "doc:b")

	first, err := PlanResources(run, current, []ResourceMetadata{b, a})
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanResources(run, current, []ResourceMetadata{a, b})
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
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("reordered desired resources changed the plan:\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
	if len(first.Operations) != 14 {
		t.Fatalf("operation count = %d, want 14", len(first.Operations))
	}
	for _, operation := range first.Operations {
		if operation.RunID != run.RunID || operation.ProjectionVersion != run.ProjectionVersion {
			t.Fatalf("operation is not bound to run/projection: %+v", operation)
		}
		if operation.IdempotencyKey == "" || operation.IdempotencyKey == run.IdempotencyKey {
			t.Fatalf("operation has no deterministic per-operation idempotency key: %+v", operation)
		}
	}
}

func TestFailedACLOrIndexProjectionCannotServe(t *testing.T) {
	for _, failedKind := range []OperationKind{OperationProjectACL, OperationProjectIndex} {
		t.Run(string(failedKind), func(t *testing.T) {
			scope := testScope()
			currentSnapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
			currentMetadata := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "old", "source-v1", "content-v1", "projection-v1", "", "doc:a"))
			current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), []ResourceMetadata{currentMetadata})
			nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
			run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
			desired := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "new", "source-v2", "content-v2", run.ProjectionVersion, "", "doc:a")
			plan, err := PlanResources(run, current, []ResourceMetadata{desired})
			if err != nil {
				t.Fatal(err)
			}
			results := SuccessfulResults(plan)
			for i, operation := range plan.Operations {
				if operation.Kind == failedKind {
					results[i].Outcome = OperationFailed
					results[i].ErrorCode = "projection_failed"
				}
			}
			projection, report, err := Replay(plan, current, results)
			if err != nil {
				t.Fatal(err)
			}
			if report.RunState != RunFailed || projection.State != StateFailed {
				t.Fatalf("failed component produced successful state: report=%+v projection=%+v", report, projection)
			}
			if projection.IsServing(desired.ResourceID) || projection.Resources[0].IsServing() {
				t.Fatalf("resource became serving after %s failed: %+v", failedKind, projection.Resources[0])
			}
			retryRun := testRun(scope, projection.Version, "projection-v3", projection.SourceSnapshot)
			retryDesired := projection.Resources[0]
			retryDesired.Versions.Projection = retryRun.ProjectionVersion
			retryDesired.ServingState = StateStaged
			retryDesired.ProjectionStatus = PendingProjectionStatus()
			if _, err := PlanResources(retryRun, projection, []ResourceMetadata{retryDesired}); err == nil {
				t.Fatal("failed projection was accepted as the base of another run")
			}
		})
	}
}

func TestProjectionPlanReplayIsIdempotent(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	desired := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a", "source-v2", "content-v2", run.ProjectionVersion, "", "doc:a")
	plan, err := PlanResources(run, current, []ResourceMetadata{desired})
	if err != nil {
		t.Fatal(err)
	}
	results := SuccessfulResults(plan)
	first, firstReport, err := Replay(plan, current, results)
	if err != nil {
		t.Fatal(err)
	}
	if firstReport.RunState != RunSucceeded || !first.IsServing(desired.ResourceID) {
		t.Fatalf("successful replay did not publish the complete projection: %+v %+v", firstReport, first)
	}
	second, secondReport, err := Replay(plan, first, results)
	if err != nil {
		t.Fatal(err)
	}
	if !secondReport.IdempotentNoop {
		t.Fatalf("second replay was not recognized as idempotent: %+v", secondReport)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("idempotent replay changed projection:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestReplayRejectsIncompleteProjectionPlan(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	currentResource := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "old", "source-v1", "content-v1", "projection-v1", "", "doc:a"))
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), []ResourceMetadata{currentResource})
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	desired := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "new", "source-v2", "content-v2", run.ProjectionVersion, "", "doc:a")
	plan, err := PlanResources(run, current, []ResourceMetadata{desired})
	if err != nil {
		t.Fatal(err)
	}
	filtered := plan.Operations[:0]
	for _, operation := range plan.Operations {
		if operation.Kind != OperationProjectACL {
			filtered = append(filtered, operation)
		}
	}
	plan.Operations = filtered
	plan.PlanID, err = projectionPlanID(plan.Run, plan.Operations)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Replay(plan, current, SuccessfulResults(plan)); err == nil {
		t.Fatal("replay accepted a target missing its ACL projection")
	}

	empty := ProjectionPlan{Run: run}
	empty.PlanID, err = projectionPlanID(empty.Run, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Replay(empty, current, nil); err == nil {
		t.Fatal("replay accepted an empty plan that dropped a live current resource")
	}
}

func TestCatalogRejectsMixedSecurityDomains(t *testing.T) {
	scope := testScope()
	first := Document{Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a", "source-v1", "content-a", "projection-v1", "", "doc:a"), Snapshot: testSnapshot(t, scope, "source-v1", "sources/a.md").Ref(), Path: "sources/a.md"}
	second := Document{Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/b.md", "b", "source-v1", "content-b", "projection-v1", "", "doc:b"), Snapshot: testSnapshot(t, scope, "source-v1", "sources/b.md").Ref(), Path: "sources/b.md"}
	second.Metadata.SecurityDomain = "repo:other"
	if _, err := (Catalog{Documents: []Document{first, second}}).Canonical(); err == nil {
		t.Fatal("catalog accepted resources from multiple security domains")
	}
}

func TestFullReconciliationTombstonesStaleResources(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1", "sources/keep.md", "sources/stale.md")
	keepV1 := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/keep.md", "keep", "source-v1", "content-keep-v1", "projection-v1", "", "doc:keep"))
	stale := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/stale.md", "stale", "source-v1", "content-stale-v1", "projection-v1", "", "doc:stale"))
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), []ResourceMetadata{stale, keepV1})
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/keep.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	keepV2 := testMetadata(t, scope, protocol.ResourceDocument, "sources/keep.md", "keep", "source-v2", "content-keep-v1", run.ProjectionVersion, "", "doc:keep")
	plan, err := PlanResources(run, current, []ResourceMetadata{keepV2})
	if err != nil {
		t.Fatal(err)
	}
	var foundTombstone, foundSupersede bool
	for _, operation := range plan.Operations {
		if operation.Resource.ResourceID == stale.ResourceID && operation.Kind == OperationTombstone {
			foundTombstone = true
		}
		if operation.Resource.ResourceID == keepV1.ResourceID && operation.Kind == OperationSupersede {
			foundSupersede = true
		}
	}
	if !foundTombstone || !foundSupersede {
		t.Fatalf("full plan missing tombstone or supersede: %+v", plan.Operations)
	}
	projection, _, err := Replay(plan, current, SuccessfulResults(plan))
	if err != nil {
		t.Fatal(err)
	}
	staleResult := resourceByID(t, projection, stale.ResourceID)
	if staleResult.ServingState != StateTombstoned || projection.IsServing(stale.ResourceID) {
		t.Fatalf("stale resource was not removed from serving state: %+v", staleResult)
	}
	if !projection.IsServing(keepV2.ResourceID) {
		t.Fatalf("retained resource is not serving in the complete projection: %+v", projection)
	}
}

func TestExplicitRevocationProducesNonServingReplacementProjection(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	resource := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a", "source-v1", "content-v1", "projection-v1", "", "doc:a"))
	current := testProjection(t, scope, "projection-v1", snapshot.Ref(), []ResourceMetadata{resource})
	run := testRun(scope, current.Version, "projection-v2", snapshot.Ref())
	plan, err := PlanRevocations(run, current, []protocol.ResourceID{resource.ResourceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Operations) != 1 || plan.Operations[0].Kind != OperationRevoke {
		t.Fatalf("unexpected revocation plan: %+v", plan.Operations)
	}
	projection, _, err := Replay(plan, current, SuccessfulResults(plan))
	if err != nil {
		t.Fatal(err)
	}
	revoked := resourceByID(t, projection, resource.ResourceID)
	if revoked.ServingState != StateRevoked || projection.IsServing(resource.ResourceID) {
		t.Fatalf("revoked resource is still serving: %+v", revoked)
	}
}

func testScope() Scope {
	return Scope{TenantID: "tenant-local", KnowledgeBaseID: "kb-default"}
}

func testSnapshotDocument(sourceKey, sourceVersion, content string) SourceDocumentSnapshot {
	return SourceDocumentSnapshot{
		SourceKey: sourceKey, SourceVersion: sourceVersion,
		ContentDigest: protocol.NewContentDigest(content), ACLVersion: "acl-v1",
		AuthorizationObject: "document:" + sourceKey, Sensitivity: SensitivityInternal,
		SecurityDomain: "repo:knote",
	}
}

func testSnapshot(t *testing.T, scope Scope, version string, sourceKeys ...string) SourceSnapshot {
	t.Helper()
	documents := make([]SourceDocumentSnapshot, len(sourceKeys))
	for i, sourceKey := range sourceKeys {
		documents[i] = testSnapshotDocument(sourceKey, version, sourceKey+":"+version)
	}
	snapshot, err := NewSourceSnapshot(scope, "git", version, "repo:knote", documents)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testVersions(source, content, projection string) protocol.ResourceVersions {
	return protocol.ResourceVersions{
		Source: source, Content: content, ACL: "acl-v1", Index: "index-v1",
		Graph: "graph-v1", Projection: projection,
	}
}

func testMetadata(
	t *testing.T,
	scope Scope,
	resourceType protocol.ResourceType,
	sourceKey string,
	content string,
	sourceVersion string,
	contentVersion string,
	projectionVersion string,
	authorizationResourceID protocol.ResourceID,
	authorizationObject string,
) ResourceMetadata {
	t.Helper()
	metadata, err := NewResourceMetadata(
		scope, resourceType, sourceKey, authorizationObject, authorizationResourceID,
		protocol.NewContentDigest(content), testVersions(sourceVersion, contentVersion, projectionVersion),
		SensitivityInternal, "repo:knote",
	)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func published(metadata ResourceMetadata) ResourceMetadata {
	metadata.ServingState = StatePublished
	metadata.ProjectionStatus = SucceededProjectionStatus()
	return metadata
}

func testProjection(
	t *testing.T,
	scope Scope,
	version string,
	snapshot SourceSnapshotRef,
	resources []ResourceMetadata,
) Projection {
	t.Helper()
	projection, err := NewProjection(scope, version, snapshot, StatePublished, resources)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func testRun(scope Scope, baseVersion, projectionVersion string, snapshot SourceSnapshotRef) SyncRun {
	return SyncRun{
		RunID: "run-38", Scope: scope, SourceSnapshot: snapshot,
		BaseProjectionVersion: baseVersion, ProjectionVersion: projectionVersion,
		IdempotencyKey: "sync-38", Reconciliation: ReconciliationFull, State: RunStaged,
	}
}

func resourceByID(t *testing.T, projection Projection, id protocol.ResourceID) ResourceMetadata {
	t.Helper()
	for _, resource := range projection.Resources {
		if resource.ResourceID == id {
			return resource
		}
	}
	t.Fatalf("resource %s not found in projection", id)
	return ResourceMetadata{}
}
