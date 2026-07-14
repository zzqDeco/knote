package catalog

import (
	"encoding/json"
	"reflect"
	"strings"
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

func TestResourceMetadataServingHandleRejectsNonServingLifecycle(t *testing.T) {
	metadata := testMetadata(
		t, testScope(), protocol.ResourceDocument, "sources/a.md", "body",
		"source-v1", "content-v1", "projection-v1", "", "document:a",
	)
	if _, err := metadata.ServingHandle(); err == nil {
		t.Fatal("staged resource produced a serving handle")
	}
	metadata = published(metadata)
	handle, err := metadata.ServingHandle()
	if err != nil {
		t.Fatal(err)
	}
	if handle.ResourceID != metadata.ResourceID || handle.AuthorizationID != metadata.AuthorizationObject ||
		handle.Versions != metadata.Versions || handle.ServingState != protocol.ServingActive {
		t.Fatalf("serving handle changed catalog identity: metadata=%+v handle=%+v", metadata, handle)
	}
	metadata.ServingState = StateRevoked
	if _, err := metadata.ServingHandle(); err == nil {
		t.Fatal("revoked resource produced a serving handle")
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
		BindingState: ClaimBindingUnbound,
		Text:         "A source-scoped claim", Confidence: "high", Provenance: provenance,
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
	staleEntity := entity
	staleEntity.Metadata.Versions.Projection = "projection-v3"
	if err := staleEntity.Validate(); err == nil {
		t.Fatal("entity accepted provenance from an older projection")
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

func TestPlanResourcesRejectsIncompleteDesiredDependencyClosure(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())

	for _, resourceType := range []protocol.ResourceType{
		protocol.ResourceClaim, protocol.ResourceEntity, protocol.ResourceDerivedArtifact,
	} {
		t.Run(string(resourceType)+" empty dependencies", func(t *testing.T) {
			desired := testMetadata(
				t, scope, resourceType, string(resourceType)+":a", "derived", "source-v2",
				"content-v2", run.ProjectionVersion, "", string(resourceType)+":a",
			)
			if _, err := PlanResources(run, current, []ResourceMetadata{desired}); err == nil {
				t.Fatal("planner returned operations for a dependency-less derived target")
			}
		})
	}

	t.Run("dependency absent from replacement", func(t *testing.T) {
		desired := testMetadata(
			t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v2",
			"content-v2", run.ProjectionVersion, "", "entity:a",
		)
		missing, err := protocol.NewStableResourceID(
			scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceClaim, "claim:missing",
		)
		if err != nil {
			t.Fatal(err)
		}
		desired.Dependencies = []protocol.ResourceID{missing}
		if _, err := PlanResources(run, current, []ResourceMetadata{desired}); err == nil {
			t.Fatal("planner returned operations with a dependency absent from the desired replacement")
		}
	})
}

func TestPlanResourcesAllowsClosedInitialDerivedProjection(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	document := testMetadata(
		t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v2",
		"content-document-v2", run.ProjectionVersion, "", "doc:a",
	)
	entity := testMetadata(
		t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v2",
		"content-entity-v2", run.ProjectionVersion, "", "entity:a",
	)
	entity.Dependencies = []protocol.ResourceID{document.ResourceID}

	if _, err := PlanResources(run, current, []ResourceMetadata{document, entity}); err != nil {
		t.Fatalf("planner rejected a closed initial desired projection: %v", err)
	}
}

func TestPlanResourcesRejectsDesiredDocumentCountMismatch(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md", "sources/b.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	documentA := testMetadata(
		t, scope, protocol.ResourceDocument, "sources/a.md", "document-a", "source-v2",
		"content-a-v2", run.ProjectionVersion, "", "doc:a",
	)

	if _, err := PlanResources(run, current, []ResourceMetadata{documentA}); err == nil {
		t.Fatal("planner returned operations for a desired document count that mismatches the source snapshot")
	}
}

func TestProjectionDocumentCountHandlesRevokedAndRemovedRecords(t *testing.T) {
	scope := testScope()
	withDocument := testSnapshot(t, scope, "source-v1", "sources/a.md")
	revoked := published(testMetadata(
		t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1",
		"content-v1", "projection-v1", "", "doc:a",
	))
	revoked.ServingState = StateRevoked
	if _, err := NewProjection(
		scope, "projection-v1", withDocument.Ref(), StatePublished, []ResourceMetadata{revoked},
	); err != nil {
		t.Fatalf("projection rejected a revoked document still present in the source snapshot: %v", err)
	}

	withoutDocument := testSnapshot(t, scope, "source-v2")
	tombstoned := revoked
	tombstoned.Versions.Source = "source-v2"
	tombstoned.Versions.Projection = "projection-v2"
	tombstoned.ServingState = StateTombstoned
	if _, err := NewProjection(
		scope, "projection-v2", withoutDocument.Ref(), StatePublished, []ResourceMetadata{tombstoned},
	); err != nil {
		t.Fatalf("projection counted a tombstoned document as part of the source snapshot: %v", err)
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
			replayed, replayReport, err := Replay(plan, projection, results)
			if err != nil {
				t.Fatalf("idempotent failed replay: %v", err)
			}
			if !replayReport.IdempotentNoop || !reflect.DeepEqual(replayed, projection) {
				t.Fatalf("failed replay was not idempotent: report=%+v", replayReport)
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

func TestIdempotentReplayReportsMatchedPlanState(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)

	firstSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	firstRun := testRun(scope, current.Version, "projection-v2", firstSnapshot.Ref())
	firstDesired := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "v2", "source-v2", "content-v2", firstRun.ProjectionVersion, "", "doc:a")
	firstPlan, err := PlanResources(firstRun, current, []ResourceMetadata{firstDesired})
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := Replay(firstPlan, current, SuccessfulResults(firstPlan))
	if err != nil {
		t.Fatal(err)
	}

	secondSnapshot := testSnapshot(t, scope, "source-v3", "sources/a.md")
	secondRun := testRun(scope, first.Version, "projection-v3", secondSnapshot.Ref())
	secondDesired := testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "v3", "source-v3", "content-v3", secondRun.ProjectionVersion, "", "doc:a")
	secondPlan, err := PlanResources(secondRun, first, []ResourceMetadata{secondDesired})
	if err != nil {
		t.Fatal(err)
	}
	failedResults := SuccessfulResults(secondPlan)
	for i, operation := range secondPlan.Operations {
		if operation.Kind == OperationProjectACL {
			failedResults[i] = OperationResult{
				OperationID: operation.OperationID,
				Outcome:     OperationFailed,
				ErrorCode:   "acl_projection_failed",
			}
		}
	}
	failedSuccessor, _, err := Replay(secondPlan, first, failedResults)
	if err != nil {
		t.Fatal(err)
	}
	if failedSuccessor.State != StateFailed {
		t.Fatalf("successor state = %q, want failed", failedSuccessor.State)
	}

	replayed, report, err := Replay(firstPlan, failedSuccessor, SuccessfulResults(firstPlan))
	if err != nil {
		t.Fatal(err)
	}
	if !report.IdempotentNoop || report.RunState != RunSucceeded {
		t.Fatalf("old successful plan reported successor state: %+v", report)
	}
	if !reflect.DeepEqual(replayed, failedSuccessor) {
		t.Fatal("idempotent replay changed the successor projection")
	}

	missingReceipt := failedSuccessor
	for index, receipt := range missingReceipt.AppliedOperations {
		if receipt.OperationID == firstPlan.Operations[0].OperationID {
			missingReceipt.AppliedOperations = append(
				append([]OperationReceipt(nil), missingReceipt.AppliedOperations[:index]...),
				missingReceipt.AppliedOperations[index+1:]...,
			)
			break
		}
	}
	if _, _, err := Replay(firstPlan, missingReceipt, SuccessfulResults(firstPlan)); err == nil {
		t.Fatal("idempotent replay accepted an applied plan with a missing receipt")
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

func TestCatalogRejectsUnresolvedCrossResourceReferences(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v2", "content-doc-v2", "projection-v2", "", "doc:a"),
		Snapshot: snapshot.Ref(),
		Path:     "sources/a.md",
	}
	chunk := Chunk{
		Metadata: testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", "source-v2", "content-chunk-v2", "projection-v2", document.Metadata.ResourceID, document.Metadata.AuthorizationObject),
		Document: document.VersionRef(),
		Ordinal:  0,
		Span:     [2]int{0, 5},
	}
	provenance := Provenance{
		DerivationMode: protocol.DerivationAnySupport,
		Supports: []Support{{
			SupportID: "support-a-v2",
			Evidence:  []EvidenceRef{chunk.EvidenceRef()},
			Complete:  true,
		}},
	}
	claim := Claim{
		Metadata:       testMetadata(t, scope, protocol.ResourceClaim, "sources/a.md#claim:0", "claim", "source-v2", "content-claim-v2", "projection-v2", "", "claim:a:0"),
		BindingState:   ClaimBindingUnbound,
		SourceDocument: document.VersionRef(),
		Text:           "claim",
		Provenance:     provenance,
	}
	entity := Entity{
		Metadata:   testMetadata(t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v2", "content-entity-v2", "projection-v2", "", "entity:a"),
		Name:       "A",
		EntityType: "Topic",
		Provenance: provenance,
	}
	artifact := DerivedArtifact{
		Metadata:   testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:a", "artifact", "source-v2", "content-artifact-v2", "projection-v2", "", "artifact:a"),
		Kind:       "summary",
		Provenance: provenance,
	}

	tests := []struct {
		name    string
		catalog Catalog
	}{
		{name: "claim source document", catalog: Catalog{Chunks: []Chunk{chunk}, Claims: []Claim{claim}}},
		{name: "claim evidence", catalog: Catalog{Documents: []Document{document}, Claims: []Claim{claim}}},
		{name: "entity evidence", catalog: Catalog{Documents: []Document{document}, Entities: []Entity{entity}}},
		{name: "derived artifact evidence", catalog: Catalog{Documents: []Document{document}, DerivedArtifacts: []DerivedArtifact{artifact}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.catalog.Validate(); err == nil {
				t.Fatal("catalog accepted an unresolved cross-resource reference")
			}
		})
	}
}

func TestCatalogRejectsChunkEvidenceAttributedToAnotherDocument(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md", "sources/b.md")
	documentA := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document-a", "source-v2", "content-a-v2", "projection-v2", "", "doc:a"),
		Snapshot: snapshot.Ref(),
		Path:     "sources/a.md",
	}
	documentB := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/b.md", "document-b", "source-v2", "content-b-v2", "projection-v2", "", "doc:b"),
		Snapshot: snapshot.Ref(),
		Path:     "sources/b.md",
	}
	chunk := Chunk{
		Metadata: testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk-a", "source-v2", "content-chunk-v2", "projection-v2", documentA.Metadata.ResourceID, documentA.Metadata.AuthorizationObject),
		Document: documentA.VersionRef(),
		Ordinal:  0,
		Span:     [2]int{0, 5},
	}
	evidence := chunk.EvidenceRef()
	evidence.Document = documentB.VersionRef()
	entity := Entity{
		Metadata:   testMetadata(t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v2", "content-entity-v2", "projection-v2", "", "entity:a"),
		Name:       "A",
		EntityType: "Topic",
		Provenance: Provenance{
			DerivationMode: protocol.DerivationAnySupport,
			Supports: []Support{{
				SupportID: "support-a-v2",
				Evidence:  []EvidenceRef{evidence},
				Complete:  true,
			}},
		},
	}

	if err := (Catalog{
		Documents: []Document{documentA, documentB},
		Chunks:    []Chunk{chunk},
		Entities:  []Entity{entity},
	}).Validate(); err == nil {
		t.Fatal("catalog accepted chunk evidence attributed to another document")
	}
}

func TestCatalogRejectsClaimEvidenceAttributedToAnotherDocument(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md", "sources/b.md")
	documentA := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document-a", "source-v2", "content-a-v2", "projection-v2", "", "doc:a"),
		Snapshot: snapshot.Ref(), Path: "sources/a.md",
	}
	documentB := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/b.md", "document-b", "source-v2", "content-b-v2", "projection-v2", "", "doc:b"),
		Snapshot: snapshot.Ref(), Path: "sources/b.md",
	}
	claim := Claim{
		Metadata:       testMetadata(t, scope, protocol.ResourceClaim, "claim:a", "claim", "source-v2", "content-claim-v2", "projection-v2", "", "claim:a"),
		BindingState:   ClaimBindingUnbound,
		SourceDocument: documentA.VersionRef(),
		Text:           "claim from document A",
		Provenance: Provenance{DerivationMode: protocol.DerivationAnySupport, Supports: []Support{{
			SupportID: "support-a", Evidence: []EvidenceRef{documentA.EvidenceRef()}, Complete: true,
		}}},
	}
	artifact := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:a", "artifact", "source-v2", "content-artifact-v2", "projection-v2", "", "artifact:a"),
		Kind:     "summary",
		Provenance: Provenance{DerivationMode: protocol.DerivationAnySupport, Supports: []Support{{
			SupportID: "support-claim", Evidence: []EvidenceRef{{
				ResourceID: claim.Metadata.ResourceID, Type: claim.Metadata.Type,
				Versions: claim.Metadata.Versions, Document: documentB.VersionRef(),
			}}, Complete: true,
		}}},
	}

	if err := (Catalog{
		Documents: []Document{documentA, documentB}, Claims: []Claim{claim},
		DerivedArtifacts: []DerivedArtifact{artifact},
	}).Validate(); err == nil {
		t.Fatal("catalog accepted claim evidence attributed to another document")
	}
}

func TestCatalogRejectsChunkWithUnresolvedDocument(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v2", "content-doc-v2", "projection-v2", "", "doc:a"),
		Snapshot: snapshot.Ref(),
		Path:     "sources/a.md",
	}
	chunk := Chunk{
		Metadata: testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", "source-v2", "content-chunk-v2", "projection-v2", document.Metadata.ResourceID, document.Metadata.AuthorizationObject),
		Document: document.VersionRef(),
		Ordinal:  0,
		Span:     [2]int{0, 5},
	}

	if err := (Catalog{Chunks: []Chunk{chunk}}).Validate(); err == nil {
		t.Fatal("catalog accepted a chunk whose document is absent")
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

func TestFullReconciliationRequiresExactDocumentSnapshot(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v2", "content-v2", run.ProjectionVersion, "", "doc:a"),
		Snapshot: nextSnapshot.Ref(),
		Path:     "sources/a.md",
	}

	tests := []struct {
		name   string
		mutate func(*SourceSnapshotRef)
	}{
		{name: "source id", mutate: func(snapshot *SourceSnapshotRef) { snapshot.SourceID = "other-source" }},
		{name: "digest", mutate: func(snapshot *SourceSnapshotRef) { snapshot.Digest = protocol.NewContentDigest("other-snapshot") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mismatched := document
			test.mutate(&mismatched.Snapshot)
			if _, err := PlanFullReconciliation(run, current, Catalog{Documents: []Document{mismatched}}); err == nil {
				t.Fatal("full reconciliation accepted a document from another source snapshot")
			}
		})
	}
}

func TestFullReconciliationRejectsIncompleteDesiredDocumentSet(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1", "sources/a.md", "sources/b.md")
	currentA := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a-v1", "source-v1", "content-a-v1", "projection-v1", "", "doc:a"))
	currentB := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/b.md", "b-v1", "source-v1", "content-b-v1", "projection-v1", "", "doc:b"))
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), []ResourceMetadata{currentA, currentB})
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md", "sources/b.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	documentA := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a-v2", "source-v2", "content-a-v2", run.ProjectionVersion, "", "doc:a"),
		Snapshot: nextSnapshot.Ref(),
		Path:     "sources/a.md",
	}

	if _, err := PlanFullReconciliation(run, current, Catalog{Documents: []Document{documentA}}); err == nil {
		t.Fatal("full reconciliation accepted fewer desired documents than the source snapshot")
	}
}

func TestProjectionOperationRejectsNonCanonicalOperationID(t *testing.T) {
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
	operation := plan.Operations[0]
	operation.OperationID = "op_caller_supplied"
	operation.IdempotencyKey = operationIdempotencyKey(run.IdempotencyKey, operation.OperationID)

	if err := operation.Validate(run); err == nil {
		t.Fatal("operation accepted a caller-supplied non-canonical operation ID")
	}
}

func TestPlannerRejectsSecurityDomainTransition(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1", "sources/stale.md")
	stale := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/stale.md", "stale", "source-v1", "content-v1", "projection-v1", "", "doc:stale"))
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), []ResourceMetadata{stale})
	nextSnapshot, err := NewSourceSnapshot(scope, "git", "source-v2", "repo:other", nil)
	if err != nil {
		t.Fatal(err)
	}
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	if _, err := PlanResources(run, current, nil); err == nil {
		t.Fatal("planner accepted a security-domain transition while planning stale resources")
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

func TestRevocationOfUnknownResourceReturnsErrorWithoutPanic(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", snapshot.Ref(), nil)
	run := testRun(scope, current.Version, "projection-v2", snapshot.Ref())
	unknown, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceDocument, "sources/missing.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanRevocations(run, current, []protocol.ResourceID{unknown}); err == nil {
		t.Fatal("unknown revocation target should return an error")
	}
}

func TestPlannerSkipsAlreadyTerminalResources(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1")
	terminal := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/old.md", "old", "source-v1", "content-v1", "projection-v1", "", "doc:old"))
	terminal.ServingState = StateSuperseded
	current := testProjection(t, scope, "projection-v1", snapshot.Ref(), []ResourceMetadata{terminal})
	nextSnapshot := testSnapshot(t, scope, "source-v2")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	plan, err := PlanResources(run, current, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Operations) != 0 {
		t.Fatalf("terminal resource produced stale operations: %+v", plan.Operations)
	}
	if _, _, err := Replay(plan, current, nil); err != nil {
		t.Fatalf("replay terminal cleanup plan: %v", err)
	}
}

func TestProjectionRejectsResourceFromAnotherSourceVersion(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	resource := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a", "source-v1", "content-v1", "projection-v2", "", "doc:a"))
	if _, err := NewProjection(scope, "projection-v2", snapshot.Ref(), StatePublished, []ResourceMetadata{resource}); err == nil {
		t.Fatal("projection accepted a resource from another source version")
	}
}

func TestProjectionValidatesServingChunkAuthorizationBoundary(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	document := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v2", "content-doc-v2", "projection-v2", "", "doc:a"))
	chunk := published(testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", "source-v2", "content-chunk-v2", "projection-v2", document.ResourceID, document.AuthorizationObject))

	if _, err := NewProjection(scope, "projection-v2", snapshot.Ref(), StatePublished, []ResourceMetadata{document, chunk}); err != nil {
		t.Fatalf("valid serving chunk boundary: %v", err)
	}

	tests := []struct {
		name      string
		resources []ResourceMetadata
	}{
		{name: "missing parent", resources: []ResourceMetadata{chunk}},
		{name: "authorization object mismatch", resources: []ResourceMetadata{document, func() ResourceMetadata {
			mismatched := chunk
			mismatched.AuthorizationObject = "document:other"
			return mismatched
		}()}},
		{name: "acl version mismatch", resources: []ResourceMetadata{document, func() ResourceMetadata {
			mismatched := chunk
			mismatched.Versions.ACL = "acl-v2"
			return mismatched
		}()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProjection(scope, "projection-v2", snapshot.Ref(), StatePublished, test.resources); err == nil {
				t.Fatal("projection accepted an invalid serving chunk authorization boundary")
			}
		})
	}
}

func TestFailedTerminalOperationRemainsFailedAndNonTerminal(t *testing.T) {
	tests := []struct {
		name string
		plan func(t *testing.T, run SyncRun, current Projection, resource ResourceMetadata) ProjectionPlan
	}{
		{
			name: "tombstone",
			plan: func(t *testing.T, run SyncRun, current Projection, _ ResourceMetadata) ProjectionPlan {
				t.Helper()
				plan, err := PlanResources(run, current, nil)
				if err != nil {
					t.Fatal(err)
				}
				return plan
			},
		},
		{
			name: "revoke",
			plan: func(t *testing.T, run SyncRun, current Projection, resource ResourceMetadata) ProjectionPlan {
				t.Helper()
				plan, err := PlanRevocations(run, current, []protocol.ResourceID{resource.ResourceID})
				if err != nil {
					t.Fatal(err)
				}
				return plan
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scope := testScope()
			currentSnapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
			resource := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "a", "source-v1", "content-v1", "projection-v1", "", "doc:a"))
			current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), []ResourceMetadata{resource})
			nextSnapshot := currentSnapshot
			if test.name == "tombstone" {
				nextSnapshot = testSnapshot(t, scope, "source-v2")
			}
			run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
			plan := test.plan(t, run, current, resource)
			if len(plan.Operations) != 1 {
				t.Fatalf("terminal plan operation count = %d, want 1", len(plan.Operations))
			}
			results := SuccessfulResults(plan)
			results[0] = OperationResult{
				OperationID: plan.Operations[0].OperationID,
				Outcome:     OperationFailed,
				ErrorCode:   "terminal_write_failed",
			}

			projection, report, err := Replay(plan, current, results)
			if err != nil {
				t.Fatal(err)
			}
			failed := resourceByID(t, projection, resource.ResourceID)
			if report.RunState != RunFailed || projection.State != StateFailed {
				t.Fatalf("failed terminal operation reported success: report=%+v projection=%+v", report, projection)
			}
			if failed.ServingState != StateFailed || failed.ServingState.IsTerminal() {
				t.Fatalf("failed terminal operation recorded a successful terminal state: %+v", failed)
			}
			if len(projection.AppliedOperations) != 1 || projection.AppliedOperations[0].Outcome != OperationFailed {
				t.Fatalf("failed terminal receipt was not preserved: %+v", projection.AppliedOperations)
			}
		})
	}
}

func TestFullReconciliationReconstructsSourceSnapshotFromDocuments(t *testing.T) {
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-v1")
	current := testProjection(t, scope, "projection-v1", currentSnapshot.Ref(), nil)
	nextSnapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	run := testRun(scope, current.Version, "projection-v2", nextSnapshot.Ref())
	document := Document{
		Metadata: testMetadata(
			t, scope, protocol.ResourceDocument, "sources/a.md", "sources/a.md:source-v2",
			"source-v2", "content-v2", run.ProjectionVersion, "", "document:sources/a.md",
		),
		Snapshot: nextSnapshot.Ref(),
		Path:     "sources/a.md",
	}
	if _, err := PlanFullReconciliation(run, current, Catalog{Documents: []Document{document}}); err != nil {
		t.Fatalf("matching source snapshot was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ResourceMetadata)
	}{
		{name: "content digest", mutate: func(metadata *ResourceMetadata) {
			metadata.ContentDigest = protocol.NewContentDigest("other-content")
		}},
		{name: "acl version", mutate: func(metadata *ResourceMetadata) {
			metadata.Versions.ACL = "acl-v2"
		}},
		{name: "authorization object", mutate: func(metadata *ResourceMetadata) {
			metadata.AuthorizationObject = "document:other"
		}},
		{name: "sensitivity", mutate: func(metadata *ResourceMetadata) {
			metadata.Sensitivity = SensitivityRestricted
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			drifted := document
			test.mutate(&drifted.Metadata)
			if _, err := PlanFullReconciliation(run, current, Catalog{Documents: []Document{drifted}}); err == nil {
				t.Fatal("full reconciliation accepted documents that do not reconstruct the source snapshot")
			}
		})
	}
}

func TestCatalogRejectsSelfReferentialAndCyclicProvenance(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v2", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "sources/a.md:source-v2", "source-v2", "content-doc-v2", "projection-v2", "", "document:sources/a.md"),
		Snapshot: snapshot.Ref(),
		Path:     "sources/a.md",
	}
	artifactA := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:a", "artifact-a", "source-v2", "content-artifact-a-v2", "projection-v2", "", "artifact:a"),
		Kind:     "summary",
	}
	artifactB := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:b", "artifact-b", "source-v2", "content-artifact-b-v2", "projection-v2", "", "artifact:b"),
		Kind:     "summary",
	}
	evidenceFor := func(metadata ResourceMetadata) EvidenceRef {
		return EvidenceRef{
			ResourceID: metadata.ResourceID,
			Type:       metadata.Type,
			Versions:   metadata.Versions,
			Document:   document.VersionRef(),
		}
	}
	provenanceFor := func(evidence EvidenceRef) Provenance {
		return Provenance{
			DerivationMode: protocol.DerivationAllRequired,
			Supports: []Support{{
				SupportID: "support-1",
				Evidence:  []EvidenceRef{evidence},
				Complete:  true,
			}},
		}
	}

	self := artifactA
	self.Provenance = provenanceFor(evidenceFor(self.Metadata))
	if err := (Catalog{Documents: []Document{document}, DerivedArtifacts: []DerivedArtifact{self}}).Validate(); err == nil {
		t.Fatal("catalog accepted self-referential provenance")
	}

	artifactA.Provenance = provenanceFor(evidenceFor(artifactB.Metadata))
	artifactB.Provenance = provenanceFor(evidenceFor(artifactA.Metadata))
	if err := (Catalog{
		Documents:        []Document{document},
		DerivedArtifacts: []DerivedArtifact{artifactA, artifactB},
	}).Validate(); err == nil {
		t.Fatal("catalog accepted a derived-resource provenance cycle")
	}
}

func TestDocumentRevocationCascadesToChildChunks(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	document := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1", "content-doc-v1", "projection-v1", "", "doc:a"))
	chunk := published(testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", "source-v1", "content-chunk-v1", "projection-v1", document.ResourceID, document.AuthorizationObject))
	current := testProjection(t, scope, "projection-v1", snapshot.Ref(), []ResourceMetadata{document, chunk})
	run := testRun(scope, current.Version, "projection-v2", snapshot.Ref())

	plan, err := PlanRevocations(run, current, []protocol.ResourceID{document.ResourceID})
	if err != nil {
		t.Fatal(err)
	}
	revoked := make(map[protocol.ResourceID]bool)
	for _, operation := range plan.Operations {
		if operation.Kind == OperationRevoke {
			revoked[operation.Resource.ResourceID] = true
		}
	}
	if !revoked[document.ResourceID] || !revoked[chunk.ResourceID] || len(revoked) != 2 {
		t.Fatalf("document revocation did not include its child chunks: %+v", plan.Operations)
	}
	projection, _, err := Replay(plan, current, SuccessfulResults(plan))
	if err != nil {
		t.Fatal(err)
	}
	for _, resourceID := range []protocol.ResourceID{document.ResourceID, chunk.ResourceID} {
		if resource := resourceByID(t, projection, resourceID); resource.ServingState != StateRevoked {
			t.Fatalf("resource %s was not revoked: %+v", resourceID, resource)
		}
	}
}

func TestProjectionOperationRejectsResourceFromAnotherProjectionVersion(t *testing.T) {
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
	operation := plan.Operations[0]
	operation.Resource.Versions.Projection = "projection-other"
	operation.OperationID = projectionOperationID(run, operation.Kind, operation.Resource)
	operation.IdempotencyKey = operationIdempotencyKey(run.IdempotencyKey, operation.OperationID)

	if err := operation.Validate(run); err == nil {
		t.Fatal("operation accepted a resource from another projection version")
	}
}

func TestProjectionOperationBindsResourceToRunBoundary(t *testing.T) {
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

	tests := []struct {
		name   string
		mutate func(*ResourceMetadata)
	}{
		{name: "scope", mutate: func(resource *ResourceMetadata) {
			resource.Scope = Scope{TenantID: "tenant-other", KnowledgeBaseID: scope.KnowledgeBaseID}
			resource.ResourceID, err = protocol.NewStableResourceID(
				resource.Scope.TenantID, resource.Scope.KnowledgeBaseID, resource.Type, resource.SourceKey,
			)
			if err != nil {
				t.Fatal(err)
			}
			resource.AuthorizationResourceID = resource.ResourceID
		}},
		{name: "source version", mutate: func(resource *ResourceMetadata) {
			resource.Versions.Source = "source-other"
		}},
		{name: "security domain", mutate: func(resource *ResourceMetadata) {
			resource.SecurityDomain = "repo:other"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := plan.Operations[0]
			test.mutate(&operation.Resource)
			operation.OperationID = projectionOperationID(run, operation.Kind, operation.Resource)
			operation.IdempotencyKey = operationIdempotencyKey(run.IdempotencyKey, operation.OperationID)
			if err := operation.Validate(run); err == nil {
				t.Fatal("operation accepted resource outside its run boundary")
			}
		})
	}
}

func TestSupersedeOperationCarriesTerminalMetadata(t *testing.T) {
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
	for _, operation := range plan.Operations {
		if operation.Kind == OperationSupersede {
			if operation.Resource.ServingState != StateSuperseded {
				t.Fatalf("supersede metadata state = %q, want %q", operation.Resource.ServingState, StateSuperseded)
			}
			return
		}
	}
	t.Fatal("changed resource has no supersede operation")
}

func TestProjectionOperationIdentityIncludesAllResourceMetadata(t *testing.T) {
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
	operation := plan.Operations[0]
	operation.Resource.Sensitivity = SensitivityRestricted
	if err := operation.Validate(run); err == nil {
		t.Fatal("operation identity ignored side-effecting resource metadata")
	}
}

func TestRevocationCascadesThroughCanonicalDependencies(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1", "content-doc-v1", "projection-v1", "", "doc:a"),
		Snapshot: snapshot.Ref(), Path: "sources/a.md",
	}
	chunk := Chunk{
		Metadata: testMetadata(t, scope, protocol.ResourceChunk, "sources/a.md#chunk:0", "chunk", "source-v1", "content-chunk-v1", "projection-v1", document.Metadata.ResourceID, document.Metadata.AuthorizationObject),
		Document: document.VersionRef(), Ordinal: 0, Span: [2]int{0, 10},
	}
	provenance := func(id string, evidence ...EvidenceRef) Provenance {
		return Provenance{DerivationMode: protocol.DerivationAllRequired, Supports: []Support{{
			SupportID: id, Evidence: evidence, Complete: true,
		}}}
	}
	claim := Claim{
		Metadata:       testMetadata(t, scope, protocol.ResourceClaim, "claim:a", "claim", "source-v1", "content-claim-v1", "projection-v1", "", "claim:a"),
		BindingState:   ClaimBindingUnbound,
		SourceDocument: document.VersionRef(), Text: "claim", Provenance: provenance("claim-support", chunk.EvidenceRef()),
	}
	entity := Entity{
		Metadata: testMetadata(t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v1", "content-entity-v1", "projection-v1", "", "entity:a"),
		Name:     "Entity", EntityType: "Topic", Provenance: provenance("entity-support", EvidenceRef{
			ResourceID: claim.Metadata.ResourceID, Type: claim.Metadata.Type,
			Versions: claim.Metadata.Versions, Document: document.VersionRef(),
		}, document.EvidenceRef()),
	}
	artifact := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifact:a", "artifact", "source-v1", "content-artifact-v1", "projection-v1", "", "artifact:a"),
		Kind:     "summary", Provenance: provenance("artifact-support", EvidenceRef{
			ResourceID: entity.Metadata.ResourceID, Type: entity.Metadata.Type,
			Versions: entity.Metadata.Versions, Document: document.VersionRef(),
		}, document.EvidenceRef()),
	}
	resources, err := (Catalog{
		Documents: []Document{document}, Chunks: []Chunk{chunk}, Claims: []Claim{claim},
		Entities: []Entity{entity}, DerivedArtifacts: []DerivedArtifact{artifact},
	}).ResourceMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for i := range resources {
		resources[i] = published(resources[i])
	}
	current := testProjection(t, scope, "projection-v1", snapshot.Ref(), resources)
	tests := []struct {
		name        string
		selected    protocol.ResourceID
		wantRevoked map[protocol.ResourceID]bool
	}{
		{
			name: "document", selected: document.Metadata.ResourceID,
			wantRevoked: map[protocol.ResourceID]bool{
				document.Metadata.ResourceID: true, chunk.Metadata.ResourceID: true,
				claim.Metadata.ResourceID: true, entity.Metadata.ResourceID: true,
				artifact.Metadata.ResourceID: true,
			},
		},
		{
			name: "chunk", selected: chunk.Metadata.ResourceID,
			wantRevoked: map[protocol.ResourceID]bool{
				chunk.Metadata.ResourceID: true, claim.Metadata.ResourceID: true,
				entity.Metadata.ResourceID: true, artifact.Metadata.ResourceID: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := testRun(scope, current.Version, "projection-v2", snapshot.Ref())
			plan, err := PlanRevocations(run, current, []protocol.ResourceID{test.selected})
			if err != nil {
				t.Fatal(err)
			}
			revoked := make(map[protocol.ResourceID]bool)
			for _, operation := range plan.Operations {
				if operation.Kind == OperationRevoke {
					revoked[operation.Resource.ResourceID] = true
				}
			}
			for _, resource := range resources {
				if revoked[resource.ResourceID] != test.wantRevoked[resource.ResourceID] {
					t.Errorf("resource %s revoked=%t, want %t", resource.ResourceID, revoked[resource.ResourceID], test.wantRevoked[resource.ResourceID])
				}
			}
		})
	}
}

func TestRevocationRejectsDependencylessDerivedProjection(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	document := published(testMetadata(
		t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1",
		"content-document-v1", "projection-v1", "", "doc:a",
	))
	entity := published(testMetadata(
		t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v1",
		"content-entity-v1", "projection-v1", "", "entity:a",
	))
	current := Projection{
		Scope: scope, Version: "projection-v1", SourceSnapshot: snapshot.Ref(),
		State: StatePublished, Resources: []ResourceMetadata{document, entity},
	}
	current.normalize()
	run := testRun(scope, current.Version, "projection-v2", snapshot.Ref())

	if _, err := PlanRevocations(run, current, []protocol.ResourceID{document.ResourceID}); err == nil {
		t.Fatal("revocation accepted dependency-less derived metadata")
	}
}

func TestPublishedProjectionRejectsServingResourceWithTerminalDependency(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	document := published(testMetadata(
		t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1",
		"content-document-v1", "projection-v1", "", "doc:a",
	))
	document.ServingState = StateRevoked
	entity := published(testMetadata(
		t, scope, protocol.ResourceEntity, "entity:a", "entity", "source-v1",
		"content-entity-v1", "projection-v1", "", "entity:a",
	))
	entity.Dependencies = []protocol.ResourceID{document.ResourceID}

	if _, err := NewProjection(
		scope, "projection-v1", snapshot.Ref(), StatePublished, []ResourceMetadata{document, entity},
	); err == nil {
		t.Fatal("published projection accepted a serving resource with a terminal dependency")
	}
}

func TestCatalogRejectsEntitySupportWithoutDocumentOrChunkEvidence(t *testing.T) {
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-v1", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document", "source-v1", "content-document-v1", "projection-v1", "", "doc:a"),
		Snapshot: snapshot.Ref(), Path: "sources/a.md",
	}
	provenance := func(supportID string, evidence ...EvidenceRef) Provenance {
		return Provenance{DerivationMode: protocol.DerivationAnySupport, Supports: []Support{{
			SupportID: supportID, Evidence: evidence, Complete: true,
		}}}
	}
	grounded := Entity{
		Metadata: testMetadata(t, scope, protocol.ResourceEntity, "entity:grounded", "grounded", "source-v1", "content-grounded-v1", "projection-v1", "", "entity:grounded"),
		Name:     "Grounded", EntityType: "Topic", Provenance: provenance("support-document", document.EvidenceRef()),
	}
	ungrounded := Entity{
		Metadata: testMetadata(t, scope, protocol.ResourceEntity, "entity:ungrounded", "ungrounded", "source-v1", "content-ungrounded-v1", "projection-v1", "", "entity:ungrounded"),
		Name:     "Ungrounded", EntityType: "Topic", Provenance: provenance("support-entity", EvidenceRef{
			ResourceID: grounded.Metadata.ResourceID, Type: grounded.Metadata.Type,
			Versions: grounded.Metadata.Versions, Document: document.VersionRef(),
		}),
	}

	if err := (Catalog{Documents: []Document{document}, Entities: []Entity{grounded, ungrounded}}).Validate(); err == nil {
		t.Fatal("catalog accepted entity provenance without direct document or chunk evidence")
	}
}

func TestResourceMetadataDependenciesAreBackwardCompatibleJSON(t *testing.T) {
	metadata := testMetadata(t, testScope(), protocol.ResourceDocument, "sources/a.md", "document", "source-v1", "content-v1", "projection-v1", "", "doc:a")
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"dependencies"`) {
		t.Fatalf("empty dependencies should remain omitted: %s", data)
	}
	var decoded ResourceMetadata
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("legacy metadata without dependencies is invalid: %v", err)
	}
	if len(decoded.Dependencies) != 0 {
		t.Fatalf("legacy metadata gained dependencies: %+v", decoded.Dependencies)
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
