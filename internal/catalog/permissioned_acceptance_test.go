package catalog

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	acceptanceProjectionVersion = "projection-acceptance-v2"
	acceptanceAuthzVersion      = "acl-v1"
)

func TestPermissionedAcceptanceContentSuccessACLFailureNeverServes(t *testing.T) {
	const (
		invariant = "content success plus ACL failure must never advance serving state"
		skewSLO   = 25 * time.Millisecond
	)
	store, current, plan := testProjectionStorePlan(t, t.TempDir(), acceptanceProjectionVersion)
	observation := projectionSkewObservation{}
	executor := OperationExecutorFunc(func(_ context.Context, operation ProjectionOperation) (OperationResult, error) {
		observation.advance(10 * time.Millisecond)
		switch operation.Kind {
		case OperationProjectContent:
			observation.contentAt = observation.elapsed
			observation.contentVersion = operation.Resource.Versions.Content
		case OperationProjectACL:
			observation.aclAt = observation.elapsed
			observation.authzVersion = operation.Resource.Versions.ACL
			return OperationResult{
				OperationID: operation.OperationID,
				Outcome:     OperationFailed,
				ErrorCode:   "acl_projection_failed",
			}, nil
		}
		return OperationResult{OperationID: operation.OperationID, Outcome: OperationSucceeded}, nil
	})

	execution, err := store.Execute(context.Background(), plan, current, executor)
	acceptanceNoError(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion, err)
	if observation.contentAt == 0 || observation.aclAt == 0 {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"skew observation missing: content_at=%s acl_at=%s", observation.contentAt, observation.aclAt)
	}
	if observation.authzVersion != acceptanceAuthzVersion {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"observed authz version=%q", observation.authzVersion)
	}
	skew := observation.aclAt - observation.contentAt
	if skew < 0 || skew > skewSLO {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"content/ACL skew=%s exceeds SLO=%s content_version=%q", skew, skewSLO, observation.contentVersion)
	}
	t.Logf("metric=content_acl_skew duration=%s slo=%s projection_version=%q authz_version=%q",
		skew, skewSLO, acceptanceProjectionVersion, observation.authzVersion)
	if execution.Report.RunState != RunFailed || execution.Projection.State != StateFailed {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"failed ACL projection produced run_state=%q projection_state=%q",
			execution.Report.RunState, execution.Projection.State)
	}
	resource := acceptanceResourceByID(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
		execution.Projection, plan.Operations[0].Resource.ResourceID)
	if resource.ProjectionStatus.Content != ComponentSucceeded || resource.ProjectionStatus.ACL != ComponentFailed {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"component status=%+v, want content=succeeded ACL=failed", resource.ProjectionStatus)
	}
	if resource.IsServing() || execution.Projection.IsServing(resource.ResourceID) || execution.PointerAdvanced {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"failed resource became serving: resource_state=%q pointer_advanced=%t",
			resource.ServingState, execution.PointerAdvanced)
	}
	pointer, err := store.ServingPointer()
	acceptanceNoError(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion, err)
	if pointer.ProjectionVersion != current.Version {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"serving pointer advanced to %q, want base %q", pointer.ProjectionVersion, current.Version)
	}
}

func TestPermissionedAcceptanceReconciliationRemovesStaleContent(t *testing.T) {
	const invariant = "full reconciliation must remove stale content from serving state"
	scope := testScope()
	currentSnapshot := testSnapshot(t, scope, "source-acceptance-v1", "sources/keep.md", "sources/stale.md")
	keepV1 := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/keep.md", "keep-v1",
		currentSnapshot.Ref().Version, "content-keep-v1", "projection-acceptance-v1", "", "document:keep"))
	stale := published(testMetadata(t, scope, protocol.ResourceDocument, "sources/stale.md", "stale-v1",
		currentSnapshot.Ref().Version, "content-stale-v1", "projection-acceptance-v1", "", "document:stale"))
	current := testProjection(t, scope, "projection-acceptance-v1", currentSnapshot.Ref(), []ResourceMetadata{keepV1, stale})
	nextSnapshot := testSnapshot(t, scope, "source-acceptance-v2", "sources/keep.md")
	run := testRun(scope, current.Version, acceptanceProjectionVersion, nextSnapshot.Ref())
	run.RunID = "run-acceptance-reconcile"
	run.IdempotencyKey = "sync-acceptance-reconcile"
	keepV2 := testMetadata(t, scope, protocol.ResourceDocument, "sources/keep.md", "keep-v2",
		nextSnapshot.Ref().Version, "content-keep-v2", acceptanceProjectionVersion, "", "document:keep")

	plan, err := PlanResources(run, current, []ResourceMetadata{keepV2})
	acceptanceNoError(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion, err)
	projection, report, err := Replay(plan, current, SuccessfulResults(plan))
	acceptanceNoError(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion, err)
	if report.RunState != RunSucceeded {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"reconciliation run_state=%q", report.RunState)
	}
	staleResult := acceptanceResourceByID(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
		projection, stale.ResourceID)
	if staleResult.ServingState != StateTombstoned || projection.IsServing(stale.ResourceID) {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"stale resource remains eligible: state=%q serving=%t", staleResult.ServingState, projection.IsServing(stale.ResourceID))
	}
	if !projection.IsServing(keepV2.ResourceID) {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"retained resource is not serving after reconciliation")
	}
}

func TestPermissionedAcceptanceProvenanceModesAndIntermediateRevocation(t *testing.T) {
	const invariant = "provenance modes and required dependency revocation must preserve declared semantics"
	scope := testScope()
	snapshot := testSnapshot(t, scope, "source-acceptance-v1", "sources/a.md")
	document := Document{
		Metadata: testMetadata(t, scope, protocol.ResourceDocument, "sources/a.md", "document",
			snapshot.Ref().Version, "content-document-v1", "projection-acceptance-v1", "", "document:a"),
		Snapshot: snapshot.Ref(),
		Path:     "sources/a.md",
	}
	claim := Claim{
		Metadata: testMetadata(t, scope, protocol.ResourceClaim, "claims/protected", "protected-claim",
			snapshot.Ref().Version, "content-claim-v1", "projection-acceptance-v1", "", "document:protected"),
		SourceDocument: document.VersionRef(),
		Text:           "protected claim",
		Provenance: Provenance{DerivationMode: protocol.DerivationAnySupport, Supports: []Support{
			{SupportID: "alternative-a", Evidence: []EvidenceRef{document.EvidenceRef()}, Complete: true},
			{SupportID: "alternative-b", Evidence: []EvidenceRef{document.EvidenceRef()}, Complete: true},
		}},
	}
	if err := claim.Provenance.Validate(); err != nil {
		acceptanceFatalf(t, invariant, "projection-acceptance-v1", acceptanceAuthzVersion,
			"valid any_support alternatives rejected: %v", err)
	}
	incompleteAny := claim.Provenance
	incompleteAny.Supports = append([]Support(nil), claim.Provenance.Supports...)
	incompleteAny.Supports[1].Complete = false
	if err := incompleteAny.Validate(); err == nil {
		acceptanceFatalf(t, invariant, "projection-acceptance-v1", acceptanceAuthzVersion,
			"any_support accepted an alternative that was not independently complete")
	}

	artifact := DerivedArtifact{
		Metadata: testMetadata(t, scope, protocol.ResourceDerivedArtifact, "artifacts/downstream", "downstream",
			snapshot.Ref().Version, "content-artifact-v1", "projection-acceptance-v1", "", "document:downstream"),
		Kind: "path-result",
		Provenance: Provenance{DerivationMode: protocol.DerivationAllRequired, Supports: []Support{
			{SupportID: "required-claim", Evidence: []EvidenceRef{{
				ResourceID: claim.Metadata.ResourceID,
				Type:       claim.Metadata.Type,
				Versions:   claim.Metadata.Versions,
				Document:   document.VersionRef(),
			}}, Complete: false},
			{SupportID: "required-source", Evidence: []EvidenceRef{document.EvidenceRef()}, Complete: true},
		}},
	}
	resources, err := (Catalog{
		Documents:        []Document{document},
		Claims:           []Claim{claim},
		DerivedArtifacts: []DerivedArtifact{artifact},
	}).ResourceMetadata()
	acceptanceNoError(t, invariant, "projection-acceptance-v1", acceptanceAuthzVersion, err)
	for index := range resources {
		resources[index] = published(resources[index])
	}
	current := testProjection(t, scope, "projection-acceptance-v1", snapshot.Ref(), resources)
	run := testRun(scope, current.Version, acceptanceProjectionVersion, snapshot.Ref())
	run.RunID = "run-acceptance-intermediate"
	run.IdempotencyKey = "sync-acceptance-intermediate"
	plan, err := PlanRevocations(run, current, []protocol.ResourceID{claim.Metadata.ResourceID})
	acceptanceNoError(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion, err)
	projection, _, err := Replay(plan, current, SuccessfulResults(plan))
	acceptanceNoError(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion, err)
	for _, resourceID := range []protocol.ResourceID{claim.Metadata.ResourceID, artifact.Metadata.ResourceID} {
		resource := acceptanceResourceByID(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			projection, resourceID)
		if resource.ServingState != StateRevoked || projection.IsServing(resourceID) {
			acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
				"required path resource %s remained eligible: state=%q", resourceID, resource.ServingState)
		}
	}
	if !projection.IsServing(document.Metadata.ResourceID) {
		acceptanceFatalf(t, invariant, acceptanceProjectionVersion, acceptanceAuthzVersion,
			"unselected source document was removed while revoking the intermediate claim")
	}
}

type projectionSkewObservation struct {
	elapsed        time.Duration
	contentAt      time.Duration
	aclAt          time.Duration
	contentVersion string
	authzVersion   string
}

func (o *projectionSkewObservation) advance(duration time.Duration) {
	o.elapsed += duration
}

func acceptanceResourceByID(
	t *testing.T,
	invariant, projectionVersion, authzVersion string,
	projection Projection,
	resourceID protocol.ResourceID,
) ResourceMetadata {
	t.Helper()
	for _, resource := range projection.Resources {
		if resource.ResourceID == resourceID {
			return resource
		}
	}
	acceptanceFatalf(t, invariant, projectionVersion, authzVersion,
		"resource %s is absent from projection", resourceID)
	return ResourceMetadata{}
}

func acceptanceNoError(t *testing.T, invariant, projectionVersion, authzVersion string, err error) {
	t.Helper()
	if err != nil {
		acceptanceFatalf(t, invariant, projectionVersion, authzVersion, "unexpected error: %v", err)
	}
}

func acceptanceFatalf(
	t *testing.T,
	invariant, projectionVersion, authzVersion, format string,
	args ...any,
) {
	t.Helper()
	prefix := fmt.Sprintf("invariant=%q projection_version=%q authz_version=%q: ",
		invariant, projectionVersion, authzVersion)
	t.Fatal(prefix + fmt.Sprintf(format, args...))
}
