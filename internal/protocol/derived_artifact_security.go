package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const DerivedArtifactSecurityRecordVersion = "v1"

type DerivedArtifactKind string

const (
	DerivedArtifactSummary DerivedArtifactKind = "summary"
	DerivedArtifactOutline DerivedArtifactKind = "outline"
	DerivedArtifactTable   DerivedArtifactKind = "table"
)

// DefaultDerivedArtifactDerivationMode is deliberately fail-closed. Known
// display kinds and future kinds all require every support unless an explicit,
// independently complete any_support record is materialized.
func DefaultDerivedArtifactDerivationMode(kind string) DerivationMode {
	switch DerivedArtifactKind(kind) {
	case DerivedArtifactSummary, DerivedArtifactOutline, DerivedArtifactTable:
		return DerivationAllRequired
	default:
		return DerivationAllRequired
	}
}

// DerivedArtifactResourceIdentity is the body-free, exact identity persisted
// for an artifact and each resource that proves one support group.
type DerivedArtifactResourceIdentity struct {
	ResourceID              ResourceID       `json:"resource_id"`
	Type                    ResourceType     `json:"type"`
	AuthorizationID         string           `json:"authz_object"`
	AuthorizationResourceID ResourceID       `json:"authorization_resource_id"`
	ContentDigest           ContentDigest    `json:"content_digest"`
	Versions                ResourceVersions `json:"versions"`
}

func (r DerivedArtifactResourceIdentity) Validate() error {
	if err := r.ResourceID.Validate(); err != nil {
		return err
	}
	if err := r.AuthorizationResourceID.Validate(); err != nil {
		return fmt.Errorf("authorization_resource_id: %w", err)
	}
	if err := validateToken("authz_object", r.AuthorizationID); err != nil {
		return err
	}
	if err := r.ContentDigest.Validate(); err != nil {
		return err
	}
	if err := r.Versions.Validate(); err != nil {
		return err
	}
	switch r.Type {
	case ResourceDocument, ResourceChunk, ResourceEntity, ResourceClaim, ResourceDerivedArtifact:
	default:
		return fmt.Errorf("unsupported derived artifact resource type")
	}
	if r.Type == ResourceChunk {
		if r.AuthorizationResourceID == r.ResourceID {
			return fmt.Errorf("chunk authorization boundary must be a distinct parent document")
		}
	} else if r.AuthorizationResourceID != r.ResourceID {
		return fmt.Errorf("non-chunk resource must use itself as the authorization boundary")
	}
	return nil
}

type DerivedArtifactSupportGroup struct {
	SupportID string                            `json:"support_id"`
	Resources []DerivedArtifactResourceIdentity `json:"resources"`
	Complete  bool                              `json:"complete"`
}

// DerivedArtifactSecurityRecord preserves support grouping separately from
// the catalog's flattened dependency index.
type DerivedArtifactSecurityRecord struct {
	Version                   string                          `json:"version"`
	Kind                      string                          `json:"kind"`
	Artifact                  DerivedArtifactResourceIdentity `json:"artifact"`
	DerivationMode            DerivationMode                  `json:"derivation_mode"`
	Supports                  []DerivedArtifactSupportGroup   `json:"supports"`
	TenantID                  string                          `json:"tenant_id"`
	KnowledgeBaseID           string                          `json:"knowledge_base_id"`
	SecurityDomain            string                          `json:"security_domain"`
	PrincipalID               string                          `json:"principal_id"`
	AgentID                   string                          `json:"agent_id,omitempty"`
	TaskID                    string                          `json:"task_id,omitempty"`
	DelegationWatermark       string                          `json:"delegation_watermark,omitempty"`
	AgentTaskScopeFingerprint AgentTaskScopeFingerprint       `json:"agent_task_scope_fingerprint,omitempty"`
	Consistency               ConsistencyPreference           `json:"consistency"`
	AuthorizationModelID      string                          `json:"authorization_model_id"`
	IdentityWatermark         string                          `json:"identity_watermark"`
	ACLWatermark              string                          `json:"acl_watermark"`
	ProjectionWatermark       string                          `json:"projection_watermark"`
	VisibilityFingerprint     VisibilityFingerprint           `json:"visibility_fingerprint"`
}

func NewDerivedArtifactSecurityRecord(
	kind string,
	mode DerivationMode,
	artifact DerivedArtifactResourceIdentity,
	supports []DerivedArtifactSupportGroup,
	securityDomain string,
	auth AuthorizationContext,
) (DerivedArtifactSecurityRecord, error) {
	if err := auth.Validate(); err != nil {
		return DerivedArtifactSecurityRecord{}, err
	}
	if mode == "" {
		mode = DefaultDerivedArtifactDerivationMode(kind)
	}
	record := DerivedArtifactSecurityRecord{
		Version: DerivedArtifactSecurityRecordVersion, Kind: kind, Artifact: artifact,
		DerivationMode: mode, Supports: supports,
		TenantID: auth.TenantID, KnowledgeBaseID: auth.KnowledgeBaseID,
		SecurityDomain: securityDomain, PrincipalID: auth.PrincipalID,
		AgentID: auth.AgentID, TaskID: auth.TaskID,
		DelegationWatermark:       auth.DelegationWatermark,
		AgentTaskScopeFingerprint: auth.AgentTaskScopeFingerprint,
		Consistency:               auth.Consistency,
		AuthorizationModelID:      auth.AuthorizationModelID,
		IdentityWatermark:         auth.IdentityWatermark, ACLWatermark: auth.ACLWatermark,
		ProjectionWatermark: artifact.Versions.Projection,
	}
	record = record.normalized()
	record.VisibilityFingerprint = record.expectedVisibilityFingerprint()
	if err := record.Validate(); err != nil {
		return DerivedArtifactSecurityRecord{}, err
	}
	return record, nil
}

func (r DerivedArtifactSecurityRecord) Validate() error {
	if r.Version != DerivedArtifactSecurityRecordVersion {
		return fmt.Errorf("unsupported derived artifact security record version %q", r.Version)
	}
	for name, value := range map[string]string{
		"artifact_kind": r.Kind, "tenant_id": r.TenantID,
		"knowledge_base_id": r.KnowledgeBaseID, "security_domain": r.SecurityDomain,
		"principal_id": r.PrincipalID, "authorization_model_id": r.AuthorizationModelID,
		"identity_watermark": r.IdentityWatermark, "acl_watermark": r.ACLWatermark,
		"projection_watermark": r.ProjectionWatermark,
	} {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	if err := validateAgentTaskBinding(
		r.AgentID,
		r.TaskID,
		r.DelegationWatermark,
		r.AgentTaskScopeFingerprint,
	); err != nil {
		return err
	}
	switch r.Consistency {
	case ConsistencyMinimizeLatency, ConsistencyHigherConsistency:
	default:
		return fmt.Errorf("unsupported consistency preference %q", r.Consistency)
	}
	if err := r.Artifact.Validate(); err != nil {
		return fmt.Errorf("artifact identity: %w", err)
	}
	if r.Artifact.Type != ResourceDerivedArtifact {
		return fmt.Errorf("security record artifact identity is not a derived artifact")
	}
	if r.Artifact.Versions.Projection != r.ProjectionWatermark {
		return fmt.Errorf("artifact projection does not match the projection watermark")
	}
	if r.DerivationMode != DerivationAnySupport && r.DerivationMode != DerivationAllRequired {
		return fmt.Errorf("unsupported derivation mode %q", r.DerivationMode)
	}
	if len(r.Supports) == 0 {
		return fmt.Errorf("derived artifact security record has no support groups")
	}
	seenSupports := make(map[string]struct{}, len(r.Supports))
	for i, support := range r.Supports {
		if err := validateToken("support_id", support.SupportID); err != nil {
			return err
		}
		if _, duplicate := seenSupports[support.SupportID]; duplicate {
			return fmt.Errorf("duplicate support_id %q", support.SupportID)
		}
		seenSupports[support.SupportID] = struct{}{}
		if i > 0 && r.Supports[i-1].SupportID >= support.SupportID {
			return fmt.Errorf("derived artifact support groups are not in canonical order")
		}
		if r.DerivationMode == DerivationAnySupport && !support.Complete {
			return fmt.Errorf("support %s is not proven complete", support.SupportID)
		}
		if len(support.Resources) == 0 {
			return fmt.Errorf("support %s has no resources", support.SupportID)
		}
		seenResources := make(map[ResourceID]struct{}, len(support.Resources))
		for j, resource := range support.Resources {
			if err := resource.Validate(); err != nil {
				return fmt.Errorf("support %s resource: %w", support.SupportID, err)
			}
			if resource.ResourceID == r.Artifact.ResourceID {
				return fmt.Errorf("support %s is self-referential", support.SupportID)
			}
			if resource.Versions.Projection != r.ProjectionWatermark {
				return fmt.Errorf("support %s resource projection does not match the projection watermark", support.SupportID)
			}
			if _, duplicate := seenResources[resource.ResourceID]; duplicate {
				return fmt.Errorf("support %s repeats resource %s", support.SupportID, resource.ResourceID)
			}
			seenResources[resource.ResourceID] = struct{}{}
			if j > 0 && derivedArtifactResourceLess(resource, support.Resources[j-1]) {
				return fmt.Errorf("support %s resources are not in canonical order", support.SupportID)
			}
		}
	}
	if err := r.VisibilityFingerprint.Validate(); err != nil {
		return err
	}
	if r.VisibilityFingerprint != r.expectedVisibilityFingerprint() {
		return fmt.Errorf("visibility fingerprint does not match derived artifact security bindings")
	}
	if !reflect.DeepEqual(r, r.normalized()) {
		return fmt.Errorf("derived artifact security record is not canonical")
	}
	return nil
}

func (r DerivedArtifactSecurityRecord) ValidateFor(
	auth AuthorizationContext,
	securityDomain string,
	projectionVersion string,
) error {
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	bindings := []struct{ got, want string }{
		{r.TenantID, auth.TenantID}, {r.KnowledgeBaseID, auth.KnowledgeBaseID},
		{r.SecurityDomain, securityDomain}, {r.PrincipalID, auth.PrincipalID},
		{r.AgentID, auth.AgentID}, {r.TaskID, auth.TaskID},
		{r.DelegationWatermark, auth.DelegationWatermark},
		{string(r.AgentTaskScopeFingerprint), string(auth.AgentTaskScopeFingerprint)},
		{string(r.Consistency), string(auth.Consistency)},
		{r.AuthorizationModelID, auth.AuthorizationModelID},
		{r.IdentityWatermark, auth.IdentityWatermark}, {r.ACLWatermark, auth.ACLWatermark},
		{r.ProjectionWatermark, projectionVersion},
	}
	for _, binding := range bindings {
		if binding.got != binding.want {
			return fmt.Errorf("derived artifact security record does not match the authorization context")
		}
	}
	return nil
}

func (r DerivedArtifactSecurityRecord) Canonical() (DerivedArtifactSecurityRecord, error) {
	r = r.normalized()
	if err := r.Validate(); err != nil {
		return DerivedArtifactSecurityRecord{}, err
	}
	return r, nil
}

func (r DerivedArtifactSecurityRecord) RebindProjection(
	artifact DerivedArtifactResourceIdentity,
	supports []DerivedArtifactSupportGroup,
) (DerivedArtifactSecurityRecord, error) {
	r.Artifact = artifact
	r.Supports = supports
	r.ProjectionWatermark = artifact.Versions.Projection
	r = r.normalized()
	r.VisibilityFingerprint = r.expectedVisibilityFingerprint()
	if err := r.Validate(); err != nil {
		return DerivedArtifactSecurityRecord{}, err
	}
	return r, nil
}

func (r DerivedArtifactSecurityRecord) normalized() DerivedArtifactSecurityRecord {
	r.Supports = append([]DerivedArtifactSupportGroup(nil), r.Supports...)
	for i := range r.Supports {
		r.Supports[i].Resources = append([]DerivedArtifactResourceIdentity(nil), r.Supports[i].Resources...)
		sort.Slice(r.Supports[i].Resources, func(a, b int) bool {
			return derivedArtifactResourceLess(r.Supports[i].Resources[a], r.Supports[i].Resources[b])
		})
	}
	sort.Slice(r.Supports, func(i, j int) bool { return r.Supports[i].SupportID < r.Supports[j].SupportID })
	return r
}

func (r DerivedArtifactSecurityRecord) expectedVisibilityFingerprint() VisibilityFingerprint {
	parts := []string{
		SecurityContractVersion, r.TenantID, r.KnowledgeBaseID, r.PrincipalID,
		r.AuthorizationModelID, r.IdentityWatermark, r.ACLWatermark,
		r.AgentID, r.TaskID, r.DelegationWatermark,
		string(r.AgentTaskScopeFingerprint), string(r.Consistency), r.ProjectionWatermark,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return VisibilityFingerprint("vis_" + hex.EncodeToString(sum[:16]))
}

func derivedArtifactResourceLess(left, right DerivedArtifactResourceIdentity) bool {
	if left.ResourceID != right.ResourceID {
		return left.ResourceID < right.ResourceID
	}
	if left.Type != right.Type {
		return left.Type < right.Type
	}
	return left.Versions.Projection < right.Versions.Projection
}
