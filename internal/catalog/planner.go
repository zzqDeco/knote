package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

type ReconciliationMode string

const ReconciliationFull ReconciliationMode = "full"

type RunState string

const (
	RunStaged    RunState = "staged"
	RunRunning   RunState = "running"
	RunSucceeded RunState = "succeeded"
	RunFailed    RunState = "failed"
)

type SyncRun struct {
	RunID                 string             `json:"run_id"`
	Scope                 Scope              `json:"scope"`
	SourceSnapshot        SourceSnapshotRef  `json:"source_snapshot"`
	BaseProjectionVersion string             `json:"base_projection_version"`
	ProjectionVersion     string             `json:"projection_version"`
	IdempotencyKey        string             `json:"idempotency_key"`
	Reconciliation        ReconciliationMode `json:"reconciliation"`
	State                 RunState           `json:"state"`
}

func (r SyncRun) Validate() error {
	if err := validateToken("run_id", r.RunID); err != nil {
		return err
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if err := r.SourceSnapshot.Validate(); err != nil {
		return err
	}
	if r.SourceSnapshot.Scope != r.Scope {
		return fmt.Errorf("source snapshot crosses the sync run scope")
	}
	if err := validateToken("base_projection_version", r.BaseProjectionVersion); err != nil {
		return err
	}
	if err := validateToken("projection_version", r.ProjectionVersion); err != nil {
		return err
	}
	if r.BaseProjectionVersion == r.ProjectionVersion {
		return fmt.Errorf("projection version must advance from the base projection")
	}
	if err := validateToken("idempotency_key", r.IdempotencyKey); err != nil {
		return err
	}
	if r.Reconciliation != ReconciliationFull {
		return fmt.Errorf("unsupported reconciliation mode %q", r.Reconciliation)
	}
	switch r.State {
	case RunStaged, RunRunning, RunSucceeded, RunFailed:
		return nil
	default:
		return fmt.Errorf("unsupported sync run state %q", r.State)
	}
}

type OperationKind string

const (
	OperationSupersede       OperationKind = "supersede"
	OperationStage           OperationKind = "stage"
	OperationProjectContent  OperationKind = "project_content"
	OperationProjectACL      OperationKind = "project_acl"
	OperationProjectIndex    OperationKind = "project_index"
	OperationProjectGraph    OperationKind = "project_graph"
	OperationProjectArtifact OperationKind = "project_artifact"
	OperationPublish         OperationKind = "publish"
	OperationRevoke          OperationKind = "revoke"
	OperationTombstone       OperationKind = "tombstone"
)

type ProjectionOperation struct {
	OperationID       string           `json:"operation_id"`
	Kind              OperationKind    `json:"kind"`
	RunID             string           `json:"run_id"`
	ProjectionVersion string           `json:"projection_version"`
	IdempotencyKey    string           `json:"idempotency_key"`
	Resource          ResourceMetadata `json:"resource"`
}

func (o ProjectionOperation) Validate(run SyncRun) error {
	if err := validateToken("operation_id", o.OperationID); err != nil {
		return err
	}
	if o.RunID != run.RunID || o.ProjectionVersion != run.ProjectionVersion {
		return fmt.Errorf("operation %s is not bound to its run and projection", o.OperationID)
	}
	expectedKey := operationIdempotencyKey(run.IdempotencyKey, o.OperationID)
	if o.IdempotencyKey != expectedKey {
		return fmt.Errorf("operation %s has an invalid idempotency binding", o.OperationID)
	}
	if err := validateOperationKind(o.Kind); err != nil {
		return err
	}
	if err := o.Resource.Validate(); err != nil {
		return fmt.Errorf("operation %s resource: %w", o.OperationID, err)
	}
	return nil
}

type ProjectionPlan struct {
	PlanID     string                `json:"plan_id"`
	Run        SyncRun               `json:"run"`
	Operations []ProjectionOperation `json:"operations"`
}

func (p ProjectionPlan) Validate() error {
	if err := p.Run.Validate(); err != nil {
		return err
	}
	if p.Run.State != RunStaged {
		return fmt.Errorf("projection plan requires a staged sync run")
	}
	if err := validateToken("plan_id", p.PlanID); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(p.Operations))
	for i, operation := range p.Operations {
		if err := operation.Validate(p.Run); err != nil {
			return err
		}
		if _, ok := seen[operation.OperationID]; ok {
			return fmt.Errorf("duplicate operation_id %q", operation.OperationID)
		}
		seen[operation.OperationID] = struct{}{}
		if i > 0 && operationLess(operation, p.Operations[i-1]) {
			return fmt.Errorf("projection operations are not in canonical order")
		}
	}
	expectedID, err := projectionPlanID(p.Run, p.Operations)
	if err != nil {
		return err
	}
	if p.PlanID != expectedID {
		return fmt.Errorf("plan_id does not match the canonical plan contents")
	}
	return nil
}

type Projection struct {
	Scope             Scope              `json:"scope"`
	Version           string             `json:"version"`
	SourceSnapshot    SourceSnapshotRef  `json:"source_snapshot"`
	State             LifecycleState     `json:"state"`
	Resources         []ResourceMetadata `json:"resources"`
	AppliedPlanIDs    []string           `json:"applied_plan_ids,omitempty"`
	AppliedOperations []OperationReceipt `json:"applied_operations,omitempty"`
}

func NewProjection(
	scope Scope,
	version string,
	snapshot SourceSnapshotRef,
	state LifecycleState,
	resources []ResourceMetadata,
) (Projection, error) {
	projection := Projection{
		Scope: scope, Version: version, SourceSnapshot: snapshot, State: state,
		Resources: append([]ResourceMetadata(nil), resources...),
	}
	projection.normalize()
	if err := projection.Validate(); err != nil {
		return Projection{}, err
	}
	return projection, nil
}

func (p Projection) Validate() error {
	if err := p.Scope.Validate(); err != nil {
		return err
	}
	if err := validateToken("projection version", p.Version); err != nil {
		return err
	}
	if err := p.SourceSnapshot.Validate(); err != nil {
		return err
	}
	if p.SourceSnapshot.Scope != p.Scope {
		return fmt.Errorf("projection source snapshot crosses its scope")
	}
	if err := p.State.Validate(); err != nil {
		return err
	}
	seenResources := make(map[protocol.ResourceID]struct{}, len(p.Resources))
	for i, resource := range p.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("resource %s: %w", resource.ResourceID, err)
		}
		if resource.Scope != p.Scope || resource.Versions.Projection != p.Version {
			return fmt.Errorf("resource %s crosses the projection scope or version", resource.ResourceID)
		}
		if resource.SecurityDomain != p.SourceSnapshot.SecurityDomain {
			return fmt.Errorf("resource %s crosses the projection security domain", resource.ResourceID)
		}
		if _, ok := seenResources[resource.ResourceID]; ok {
			return fmt.Errorf("duplicate resource_id %s", resource.ResourceID)
		}
		seenResources[resource.ResourceID] = struct{}{}
		if i > 0 && p.Resources[i-1].ResourceID > resource.ResourceID {
			return fmt.Errorf("projection resources are not in canonical order")
		}
		if p.State == StatePublished && !resource.ServingState.IsTerminal() && !resource.IsServing() {
			return fmt.Errorf("published projection contains non-serving resource %s", resource.ResourceID)
		}
		if p.State != StatePublished && resource.IsServing() {
			return fmt.Errorf("non-published projection contains serving resource %s", resource.ResourceID)
		}
	}
	if !sort.StringsAreSorted(p.AppliedPlanIDs) {
		return fmt.Errorf("applied plan ids are not in canonical order")
	}
	for i, receipt := range p.AppliedOperations {
		if err := receipt.Validate(); err != nil {
			return err
		}
		if i > 0 && p.AppliedOperations[i-1].OperationID > receipt.OperationID {
			return fmt.Errorf("operation receipts are not in canonical order")
		}
	}
	return nil
}

func (p Projection) IsServing(resourceID protocol.ResourceID) bool {
	if p.State != StatePublished {
		return false
	}
	index := sort.Search(len(p.Resources), func(i int) bool { return p.Resources[i].ResourceID >= resourceID })
	return index < len(p.Resources) && p.Resources[index].ResourceID == resourceID && p.Resources[index].IsServing()
}

func (p *Projection) normalize() {
	sort.Slice(p.Resources, func(i, j int) bool { return p.Resources[i].ResourceID < p.Resources[j].ResourceID })
	sort.Strings(p.AppliedPlanIDs)
	sort.Slice(p.AppliedOperations, func(i, j int) bool {
		return p.AppliedOperations[i].OperationID < p.AppliedOperations[j].OperationID
	})
}

func PlanFullReconciliation(run SyncRun, current Projection, desired Catalog) (ProjectionPlan, error) {
	canonical, err := desired.Canonical()
	if err != nil {
		return ProjectionPlan{}, err
	}
	resources, err := canonical.ResourceMetadata()
	if err != nil {
		return ProjectionPlan{}, err
	}
	return PlanResources(run, current, resources)
}

func PlanResources(run SyncRun, current Projection, desired []ResourceMetadata) (ProjectionPlan, error) {
	return planResources(run, current, desired, OperationTombstone)
}

// PlanRevocations creates a complete replacement projection that carries
// forward unselected resources and marks the selected resources revoked.
func PlanRevocations(
	run SyncRun,
	current Projection,
	resourceIDs []protocol.ResourceID,
) (ProjectionPlan, error) {
	revoked := make(map[protocol.ResourceID]struct{}, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		if err := resourceID.Validate(); err != nil {
			return ProjectionPlan{}, err
		}
		if _, duplicate := revoked[resourceID]; duplicate {
			return ProjectionPlan{}, fmt.Errorf("duplicate revoked resource_id %s", resourceID)
		}
		revoked[resourceID] = struct{}{}
	}
	desired := make([]ResourceMetadata, 0, len(current.Resources)-len(revoked))
	for _, resource := range current.Resources {
		if _, selected := revoked[resource.ResourceID]; selected {
			delete(revoked, resource.ResourceID)
			continue
		}
		if resource.ServingState == StateTombstoned || resource.ServingState == StateRevoked {
			continue
		}
		resource.Versions.Projection = run.ProjectionVersion
		desired = append(desired, resource)
	}
	if len(revoked) != 0 {
		missing := make([]string, 0, len(revoked))
		for resourceID := range revoked {
			missing = append(missing, string(resourceID))
		}
		sort.Strings(missing)
		return ProjectionPlan{}, fmt.Errorf("revoked resources are not in the current projection: %v", missing)
	}
	return planResources(run, current, desired, OperationRevoke)
}

func planResources(
	run SyncRun,
	current Projection,
	desired []ResourceMetadata,
	staleKind OperationKind,
) (ProjectionPlan, error) {
	if err := run.Validate(); err != nil {
		return ProjectionPlan{}, err
	}
	if run.State != RunStaged {
		return ProjectionPlan{}, fmt.Errorf("cannot plan sync run in state %q", run.State)
	}
	if err := current.Validate(); err != nil {
		return ProjectionPlan{}, fmt.Errorf("current projection: %w", err)
	}
	if current.State != StatePublished {
		return ProjectionPlan{}, fmt.Errorf("sync run requires a published base projection")
	}
	if current.Scope != run.Scope || current.Version != run.BaseProjectionVersion {
		return ProjectionPlan{}, fmt.Errorf("sync run does not match the current projection")
	}

	targets := make([]ResourceMetadata, len(desired))
	targetByID := make(map[protocol.ResourceID]ResourceMetadata, len(desired))
	for i, resource := range desired {
		if resource.Scope != run.Scope {
			return ProjectionPlan{}, fmt.Errorf("desired resource %s crosses the sync run scope", resource.ResourceID)
		}
		if resource.SecurityDomain != run.SourceSnapshot.SecurityDomain {
			return ProjectionPlan{}, fmt.Errorf("desired resource %s crosses the sync run security domain", resource.ResourceID)
		}
		if resource.Versions.Source != run.SourceSnapshot.Version {
			return ProjectionPlan{}, fmt.Errorf("desired resource %s is not bound to the run source snapshot", resource.ResourceID)
		}
		if resource.Versions.Projection != "" && resource.Versions.Projection != run.ProjectionVersion {
			return ProjectionPlan{}, fmt.Errorf("desired resource %s has another projection version", resource.ResourceID)
		}
		resource.Versions.Projection = run.ProjectionVersion
		resource.ServingState = StateStaged
		resource.ProjectionStatus = PendingProjectionStatus()
		if err := resource.Validate(); err != nil {
			return ProjectionPlan{}, fmt.Errorf("desired resource %s: %w", resource.ResourceID, err)
		}
		if _, duplicate := targetByID[resource.ResourceID]; duplicate {
			return ProjectionPlan{}, fmt.Errorf("duplicate desired resource_id %s", resource.ResourceID)
		}
		targets[i] = resource
		targetByID[resource.ResourceID] = resource
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ResourceID < targets[j].ResourceID })
	if err := validateChunkBoundaries(targets); err != nil {
		return ProjectionPlan{}, err
	}

	currentByID := make(map[protocol.ResourceID]ResourceMetadata, len(current.Resources))
	for _, resource := range current.Resources {
		currentByID[resource.ResourceID] = resource
	}
	operations := make([]ProjectionOperation, 0, len(targets)*7+len(current.Resources))
	for _, resource := range targets {
		if previous, ok := currentByID[resource.ResourceID]; ok && !sameResourceDefinition(previous, resource) {
			operations = append(operations, newProjectionOperation(run, OperationSupersede, previous))
		}
		for _, kind := range []OperationKind{
			OperationStage, OperationProjectContent, OperationProjectACL, OperationProjectIndex,
			OperationProjectGraph, OperationProjectArtifact, OperationPublish,
		} {
			operations = append(operations, newProjectionOperation(run, kind, resource))
		}
	}
	for _, resource := range current.Resources {
		if _, ok := targetByID[resource.ResourceID]; ok ||
			resource.ServingState == StateTombstoned || resource.ServingState == StateRevoked {
			continue
		}
		terminal := resource
		terminal.Versions.Projection = run.ProjectionVersion
		if staleKind == OperationRevoke {
			terminal.ServingState = StateRevoked
		} else {
			terminal.ServingState = StateTombstoned
		}
		operations = append(operations, newProjectionOperation(run, staleKind, terminal))
	}
	sort.Slice(operations, func(i, j int) bool { return operationLess(operations[i], operations[j]) })
	planID, err := projectionPlanID(run, operations)
	if err != nil {
		return ProjectionPlan{}, err
	}
	plan := ProjectionPlan{PlanID: planID, Run: run, Operations: operations}
	if err := plan.Validate(); err != nil {
		return ProjectionPlan{}, err
	}
	return plan, nil
}

func validateChunkBoundaries(resources []ResourceMetadata) error {
	byID := make(map[protocol.ResourceID]ResourceMetadata, len(resources))
	for _, resource := range resources {
		byID[resource.ResourceID] = resource
	}
	for _, resource := range resources {
		if resource.Type != protocol.ResourceChunk {
			continue
		}
		document, ok := byID[resource.AuthorizationResourceID]
		if !ok || document.Type != protocol.ResourceDocument {
			return fmt.Errorf("chunk %s has no desired parent document", resource.ResourceID)
		}
		if document.AuthorizationObject != resource.AuthorizationObject ||
			document.Versions.Source != resource.Versions.Source ||
			document.Versions.ACL != resource.Versions.ACL ||
			document.Versions.Projection != resource.Versions.Projection {
			return fmt.Errorf("chunk %s does not inherit the desired parent document authorization boundary", resource.ResourceID)
		}
	}
	return nil
}

func sameResourceDefinition(left, right ResourceMetadata) bool {
	left.Versions.Projection, right.Versions.Projection = "", ""
	left.ServingState, right.ServingState = StateStaged, StateStaged
	left.ProjectionStatus, right.ProjectionStatus = PendingProjectionStatus(), PendingProjectionStatus()
	return left == right
}

func newProjectionOperation(run SyncRun, kind OperationKind, resource ResourceMetadata) ProjectionOperation {
	operationID := stableID("op_", struct {
		RunID             string                    `json:"run_id"`
		ProjectionVersion string                    `json:"projection_version"`
		Kind              OperationKind             `json:"kind"`
		ResourceID        protocol.ResourceID       `json:"resource_id"`
		ContentDigest     protocol.ContentDigest    `json:"content_digest"`
		Versions          protocol.ResourceVersions `json:"versions"`
	}{
		RunID: run.RunID, ProjectionVersion: run.ProjectionVersion, Kind: kind,
		ResourceID: resource.ResourceID, ContentDigest: resource.ContentDigest, Versions: resource.Versions,
	})
	return ProjectionOperation{
		OperationID: operationID, Kind: kind, RunID: run.RunID,
		ProjectionVersion: run.ProjectionVersion,
		IdempotencyKey:    operationIdempotencyKey(run.IdempotencyKey, operationID),
		Resource:          resource,
	}
}

func operationIdempotencyKey(runKey, operationID string) string {
	return stableID("idem_", struct {
		RunKey      string `json:"run_key"`
		OperationID string `json:"operation_id"`
	}{RunKey: runKey, OperationID: operationID})
}

func projectionPlanID(run SyncRun, operations []ProjectionOperation) (string, error) {
	payload := struct {
		Run        SyncRun               `json:"run"`
		Operations []ProjectionOperation `json:"operations"`
	}{Run: run, Operations: operations}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal projection plan: %w", err)
	}
	return digestID("plan_", data), nil
}

func stableID(prefix string, value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("catalog stable id payload is not serializable: %v", err))
	}
	return digestID(prefix, data)
}

func digestID(prefix string, data []byte) string {
	sum := sha256.Sum256(data)
	return prefix + hex.EncodeToString(sum[:16])
}

func operationLess(left, right ProjectionOperation) bool {
	if left.Resource.ResourceID != right.Resource.ResourceID {
		return left.Resource.ResourceID < right.Resource.ResourceID
	}
	if operationRank(left.Kind) != operationRank(right.Kind) {
		return operationRank(left.Kind) < operationRank(right.Kind)
	}
	return left.OperationID < right.OperationID
}

func operationRank(kind OperationKind) int {
	switch kind {
	case OperationSupersede:
		return 0
	case OperationStage:
		return 1
	case OperationProjectContent:
		return 2
	case OperationProjectACL:
		return 3
	case OperationProjectIndex:
		return 4
	case OperationProjectGraph:
		return 5
	case OperationProjectArtifact:
		return 6
	case OperationPublish:
		return 7
	case OperationRevoke:
		return 8
	case OperationTombstone:
		return 9
	default:
		return 100
	}
}

func validateOperationKind(kind OperationKind) error {
	if operationRank(kind) == 100 {
		return fmt.Errorf("unsupported projection operation %q", kind)
	}
	return nil
}
