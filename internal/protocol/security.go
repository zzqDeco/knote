package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const SecurityContractVersion = "v1"

type ConsistencyPreference string

const (
	ConsistencyMinimizeLatency   ConsistencyPreference = "minimize_latency"
	ConsistencyHigherConsistency ConsistencyPreference = "higher_consistency"
)

type AuthorizationContext struct {
	Version              string                `json:"version"`
	TenantID             string                `json:"tenant_id"`
	KnowledgeBaseID      string                `json:"knowledge_base_id"`
	PrincipalID          string                `json:"principal_id"`
	SessionID            string                `json:"session_id"`
	RequestID            string                `json:"request_id"`
	AuthorizationModelID string                `json:"authorization_model_id"`
	IdentityWatermark    string                `json:"identity_watermark"`
	ACLWatermark         string                `json:"acl_watermark"`
	AgentID              string                `json:"agent_id,omitempty"`
	TaskID               string                `json:"task_id,omitempty"`
	Consistency          ConsistencyPreference `json:"consistency"`
}

func (c AuthorizationContext) Validate() error {
	required := map[string]string{
		"version":                c.Version,
		"tenant_id":              c.TenantID,
		"knowledge_base_id":      c.KnowledgeBaseID,
		"principal_id":           c.PrincipalID,
		"session_id":             c.SessionID,
		"request_id":             c.RequestID,
		"authorization_model_id": c.AuthorizationModelID,
		"identity_watermark":     c.IdentityWatermark,
		"acl_watermark":          c.ACLWatermark,
	}
	for name, value := range required {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	if c.Version != SecurityContractVersion {
		return fmt.Errorf("unsupported authorization context version %q", c.Version)
	}
	if c.AgentID != "" {
		if err := validateToken("agent_id", c.AgentID); err != nil {
			return err
		}
	}
	if c.TaskID != "" {
		if err := validateToken("task_id", c.TaskID); err != nil {
			return err
		}
	}
	switch c.Consistency {
	case ConsistencyMinimizeLatency, ConsistencyHigherConsistency:
		return nil
	default:
		return fmt.Errorf("unsupported consistency preference %q", c.Consistency)
	}
}

type ResourceID string

type ResourceType string

const (
	ResourceDocument        ResourceType = "document"
	ResourceChunk           ResourceType = "chunk"
	ResourceEntity          ResourceType = "entity"
	ResourceClaim           ResourceType = "claim"
	ResourceDerivedArtifact ResourceType = "derived_artifact"
)

func NewStableResourceID(tenantID, knowledgeBaseID string, resourceType ResourceType, sourceKey string) (ResourceID, error) {
	for name, value := range map[string]string{
		"tenant_id":         tenantID,
		"knowledge_base_id": knowledgeBaseID,
		"resource_type":     string(resourceType),
		"source_key":        sourceKey,
	} {
		if err := validateToken(name, value); err != nil {
			return "", err
		}
	}
	switch resourceType {
	case ResourceDocument, ResourceChunk, ResourceEntity, ResourceClaim, ResourceDerivedArtifact:
	default:
		return "", fmt.Errorf("unsupported resource type %q", resourceType)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID, knowledgeBaseID, string(resourceType), sourceKey}, "\x00")))
	return ResourceID("res_" + hex.EncodeToString(sum[:16])), nil
}

func (id ResourceID) Validate() error {
	value := string(id)
	if !strings.HasPrefix(value, "res_") || len(value) != len("res_")+32 {
		return fmt.Errorf("resource_id must be an opaque res_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "res_")); err != nil {
		return fmt.Errorf("resource_id must be hexadecimal: %w", err)
	}
	return nil
}

type ResourceVersions struct {
	Source     string `json:"source"`
	Content    string `json:"content"`
	ACL        string `json:"acl"`
	Index      string `json:"index"`
	Graph      string `json:"graph"`
	Projection string `json:"projection"`
}

func (v ResourceVersions) Validate() error {
	for name, value := range map[string]string{
		"source_version":     v.Source,
		"content_version":    v.Content,
		"acl_version":        v.ACL,
		"index_version":      v.Index,
		"graph_version":      v.Graph,
		"projection_version": v.Projection,
	} {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	return nil
}

type ServingState string

const (
	ServingStaged     ServingState = "staged"
	ServingActive     ServingState = "serving"
	ServingRevoked    ServingState = "revoked"
	ServingSuperseded ServingState = "superseded"
	ServingFailed     ServingState = "failed"
)

type ResourceHandle struct {
	ResourceID      ResourceID       `json:"resource_id"`
	Type            ResourceType     `json:"type"`
	TenantID        string           `json:"tenant_id"`
	KnowledgeBaseID string           `json:"knowledge_base_id"`
	AuthorizationID string           `json:"authz_object"`
	Versions        ResourceVersions `json:"versions"`
	ServingState    ServingState     `json:"serving_state"`
}

func (h ResourceHandle) Validate() error {
	if err := h.ResourceID.Validate(); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"tenant_id":         h.TenantID,
		"knowledge_base_id": h.KnowledgeBaseID,
		"authz_object":      h.AuthorizationID,
	} {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	switch h.Type {
	case ResourceDocument, ResourceChunk, ResourceEntity, ResourceClaim, ResourceDerivedArtifact:
	default:
		return fmt.Errorf("unsupported resource type %q", h.Type)
	}
	if h.ServingState != ServingActive {
		return fmt.Errorf("resource %s is not serving", h.ResourceID)
	}
	return h.Versions.Validate()
}

type DerivationMode string

const (
	DerivationAnySupport  DerivationMode = "any_support"
	DerivationAllRequired DerivationMode = "all_required"
)

type ProvenanceSupport struct {
	SupportID  string       `json:"support_id"`
	ResourceID ResourceID   `json:"resource_id"`
	Evidence   []ResourceID `json:"evidence_resource_ids"`
	Complete   bool         `json:"complete"`
}

func ValidateProvenance(mode DerivationMode, supports []ProvenanceSupport) error {
	if len(supports) == 0 {
		return fmt.Errorf("at least one provenance support is required")
	}
	if mode != DerivationAnySupport && mode != DerivationAllRequired {
		return fmt.Errorf("unsupported derivation mode %q", mode)
	}
	seen := make(map[string]struct{}, len(supports))
	for _, support := range supports {
		if err := validateToken("support_id", support.SupportID); err != nil {
			return err
		}
		if _, ok := seen[support.SupportID]; ok {
			return fmt.Errorf("duplicate support_id %q", support.SupportID)
		}
		seen[support.SupportID] = struct{}{}
		if err := support.ResourceID.Validate(); err != nil {
			return fmt.Errorf("support %s: %w", support.SupportID, err)
		}
		if len(support.Evidence) == 0 {
			return fmt.Errorf("support %s has no evidence", support.SupportID)
		}
		for _, evidenceID := range support.Evidence {
			if err := evidenceID.Validate(); err != nil {
				return fmt.Errorf("support %s evidence: %w", support.SupportID, err)
			}
		}
		if mode == DerivationAnySupport && !support.Complete {
			return fmt.Errorf("any_support requires every support to be independently complete")
		}
	}
	return nil
}

type DecisionOutcome string

const (
	DecisionAllow         DecisionOutcome = "allow"
	DecisionDeny          DecisionOutcome = "deny"
	DecisionIndeterminate DecisionOutcome = "indeterminate"
)

type AuthorizationDecision struct {
	CorrelationID        string          `json:"correlation_id"`
	Relation             string          `json:"relation"`
	Resource             ResourceHandle  `json:"resource"`
	Outcome              DecisionOutcome `json:"outcome"`
	AuthorizationModelID string          `json:"authorization_model_id"`
	ACLWatermark         string          `json:"acl_watermark"`
	CheckedAt            time.Time       `json:"checked_at"`
}

func (d AuthorizationDecision) Authorized() bool {
	return d.Outcome == DecisionAllow
}

func (d AuthorizationDecision) Validate() error {
	for name, value := range map[string]string{
		"correlation_id":         d.CorrelationID,
		"relation":               d.Relation,
		"authorization_model_id": d.AuthorizationModelID,
		"acl_watermark":          d.ACLWatermark,
	} {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	if err := d.Resource.Validate(); err != nil {
		return err
	}
	if d.CheckedAt.IsZero() {
		return fmt.Errorf("checked_at is required")
	}
	switch d.Outcome {
	case DecisionAllow, DecisionDeny, DecisionIndeterminate:
		return nil
	default:
		return fmt.Errorf("unsupported authorization decision %q", d.Outcome)
	}
}

type VisibilityFingerprint string

func (f VisibilityFingerprint) Validate() error {
	value := string(f)
	if !strings.HasPrefix(value, "vis_") || len(value) != len("vis_")+32 {
		return fmt.Errorf("visibility_fingerprint must be an opaque vis_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "vis_")); err != nil {
		return fmt.Errorf("visibility_fingerprint must be hexadecimal: %w", err)
	}
	return nil
}

func NewVisibilityFingerprint(auth AuthorizationContext, projectionVersion string) (VisibilityFingerprint, error) {
	if err := auth.Validate(); err != nil {
		return "", err
	}
	if err := validateToken("projection_version", projectionVersion); err != nil {
		return "", err
	}
	parts := []string{
		auth.Version, auth.TenantID, auth.KnowledgeBaseID, auth.PrincipalID,
		auth.AuthorizationModelID, auth.IdentityWatermark, auth.ACLWatermark,
		auth.AgentID, auth.TaskID, projectionVersion,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return VisibilityFingerprint("vis_" + hex.EncodeToString(sum[:16])), nil
}

type Citation struct {
	Handle   string         `json:"handle"`
	Resource ResourceHandle `json:"resource"`
}

type EvidenceItem struct {
	Resource   ResourceHandle      `json:"resource"`
	Content    string              `json:"content"`
	Derivation DerivationMode      `json:"derivation"`
	Supports   []ProvenanceSupport `json:"supports"`
	Citation   Citation            `json:"citation"`
}

type EvidencePackage struct {
	Version               string                  `json:"version"`
	TenantID              string                  `json:"tenant_id"`
	KnowledgeBaseID       string                  `json:"knowledge_base_id"`
	PrincipalID           string                  `json:"principal_id"`
	SessionID             string                  `json:"session_id"`
	RequestID             string                  `json:"request_id"`
	AuthorizationModelID  string                  `json:"authorization_model_id"`
	ACLWatermark          string                  `json:"acl_watermark"`
	ProjectionVersion     string                  `json:"projection_version"`
	VisibilityFingerprint VisibilityFingerprint   `json:"visibility_fingerprint"`
	Items                 []EvidenceItem          `json:"items"`
	Decisions             []AuthorizationDecision `json:"decisions"`
}

func (p EvidencePackage) ValidateFor(auth AuthorizationContext) error {
	if err := auth.Validate(); err != nil {
		return err
	}
	if p.Version != SecurityContractVersion {
		return fmt.Errorf("unsupported evidence package version %q", p.Version)
	}
	bindings := []struct {
		name string
		got  string
		want string
	}{
		{"tenant_id", p.TenantID, auth.TenantID},
		{"knowledge_base_id", p.KnowledgeBaseID, auth.KnowledgeBaseID},
		{"principal_id", p.PrincipalID, auth.PrincipalID},
		{"session_id", p.SessionID, auth.SessionID},
		{"request_id", p.RequestID, auth.RequestID},
		{"authorization_model_id", p.AuthorizationModelID, auth.AuthorizationModelID},
		{"acl_watermark", p.ACLWatermark, auth.ACLWatermark},
	}
	for _, binding := range bindings {
		if binding.got != binding.want {
			return fmt.Errorf("evidence package %s does not match authorization context", binding.name)
		}
	}
	if err := validateToken("projection_version", p.ProjectionVersion); err != nil {
		return err
	}
	if err := p.VisibilityFingerprint.Validate(); err != nil {
		return err
	}
	expectedFingerprint, err := NewVisibilityFingerprint(auth, p.ProjectionVersion)
	if err != nil {
		return err
	}
	if p.VisibilityFingerprint != expectedFingerprint {
		return fmt.Errorf("visibility fingerprint does not match authorization context")
	}
	if len(p.Items) == 0 {
		return fmt.Errorf("evidence package has no items")
	}
	allowed := make(map[ResourceID]struct{}, len(p.Decisions))
	for _, decision := range p.Decisions {
		if err := decision.Validate(); err != nil {
			return err
		}
		if !decision.Authorized() {
			return fmt.Errorf("evidence package contains a non-allow decision")
		}
		if decision.AuthorizationModelID != p.AuthorizationModelID || decision.ACLWatermark != p.ACLWatermark {
			return fmt.Errorf("decision authorization binding does not match evidence package")
		}
		if decision.Resource.TenantID != p.TenantID || decision.Resource.KnowledgeBaseID != p.KnowledgeBaseID {
			return fmt.Errorf("decision resource crosses the authorization scope")
		}
		if decision.Resource.Versions.Projection != p.ProjectionVersion {
			return fmt.Errorf("decision projection does not match evidence package")
		}
		if _, duplicate := allowed[decision.Resource.ResourceID]; duplicate {
			return fmt.Errorf("duplicate allow decision for resource %s", decision.Resource.ResourceID)
		}
		allowed[decision.Resource.ResourceID] = struct{}{}
	}
	for _, item := range p.Items {
		if err := item.Resource.Validate(); err != nil {
			return err
		}
		if item.Resource.TenantID != p.TenantID || item.Resource.KnowledgeBaseID != p.KnowledgeBaseID {
			return fmt.Errorf("evidence resource crosses the authorization scope")
		}
		if item.Resource.Versions.Projection != p.ProjectionVersion {
			return fmt.Errorf("evidence resource projection does not match package")
		}
		if _, ok := allowed[item.Resource.ResourceID]; !ok {
			return fmt.Errorf("evidence resource %s has no allow decision", item.Resource.ResourceID)
		}
		if strings.TrimSpace(item.Content) == "" {
			return fmt.Errorf("evidence resource %s has empty content", item.Resource.ResourceID)
		}
		if err := ValidateProvenance(item.Derivation, item.Supports); err != nil {
			return err
		}
		if err := validateToken("citation_handle", item.Citation.Handle); err != nil {
			return err
		}
		if err := item.Citation.Resource.Validate(); err != nil {
			return err
		}
		if item.Citation.Resource != item.Resource {
			return fmt.Errorf("citation resource does not match evidence item")
		}
	}
	return nil
}

type QueryRequest struct {
	Question      string               `json:"question"`
	Authorization AuthorizationContext `json:"authorization"`
}

func (r QueryRequest) Validate() error {
	if strings.TrimSpace(r.Question) == "" {
		return fmt.Errorf("question is required")
	}
	return r.Authorization.Validate()
}

func validateToken(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s contains leading or trailing whitespace", name)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains control characters", name)
	}
	return nil
}
