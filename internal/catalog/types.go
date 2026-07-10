package catalog

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/zzqDeco/knote/internal/protocol"
)

// Scope is the tenant and knowledge-base boundary for every catalog value.
type Scope struct {
	TenantID        string `json:"tenant_id"`
	KnowledgeBaseID string `json:"knowledge_base_id"`
}

func (s Scope) Validate() error {
	if err := validateToken("tenant_id", s.TenantID); err != nil {
		return err
	}
	return validateToken("knowledge_base_id", s.KnowledgeBaseID)
}

type Sensitivity string

const (
	SensitivityPublic       Sensitivity = "public"
	SensitivityInternal     Sensitivity = "internal"
	SensitivityConfidential Sensitivity = "confidential"
	SensitivityRestricted   Sensitivity = "restricted"
)

func (s Sensitivity) Validate() error {
	switch s {
	case SensitivityPublic, SensitivityInternal, SensitivityConfidential, SensitivityRestricted:
		return nil
	default:
		return fmt.Errorf("unsupported sensitivity %q", s)
	}
}

// LifecycleState extends protocol.ServingState with an explicit tombstone.
// StatePublished intentionally serializes as "serving" for protocol compatibility.
type LifecycleState string

const (
	StateStaged     LifecycleState = LifecycleState(protocol.ServingStaged)
	StatePublished  LifecycleState = LifecycleState(protocol.ServingActive)
	StateRevoked    LifecycleState = LifecycleState(protocol.ServingRevoked)
	StateTombstoned LifecycleState = "tombstoned"
	StateSuperseded LifecycleState = LifecycleState(protocol.ServingSuperseded)
	StateFailed     LifecycleState = LifecycleState(protocol.ServingFailed)
)

func (s LifecycleState) Validate() error {
	switch s {
	case StateStaged, StatePublished, StateRevoked, StateTombstoned, StateSuperseded, StateFailed:
		return nil
	default:
		return fmt.Errorf("unsupported lifecycle state %q", s)
	}
}

func (s LifecycleState) IsServing() bool {
	return s == StatePublished
}

func (s LifecycleState) IsTerminal() bool {
	return s == StateRevoked || s == StateTombstoned || s == StateSuperseded
}

type ComponentState string

const (
	ComponentPending   ComponentState = "pending"
	ComponentSucceeded ComponentState = "succeeded"
	ComponentFailed    ComponentState = "failed"
)

func (s ComponentState) Validate() error {
	switch s {
	case ComponentPending, ComponentSucceeded, ComponentFailed:
		return nil
	default:
		return fmt.Errorf("unsupported component state %q", s)
	}
}

// ProjectionStatus prevents content, authorization, index, graph, and public
// artifacts from representing different projection versions.
type ProjectionStatus struct {
	Content   ComponentState `json:"content"`
	ACL       ComponentState `json:"acl"`
	Index     ComponentState `json:"index"`
	Graph     ComponentState `json:"graph"`
	Artifacts ComponentState `json:"artifacts"`
}

func PendingProjectionStatus() ProjectionStatus {
	return ProjectionStatus{
		Content: ComponentPending, ACL: ComponentPending, Index: ComponentPending,
		Graph: ComponentPending, Artifacts: ComponentPending,
	}
}

func SucceededProjectionStatus() ProjectionStatus {
	return ProjectionStatus{
		Content: ComponentSucceeded, ACL: ComponentSucceeded, Index: ComponentSucceeded,
		Graph: ComponentSucceeded, Artifacts: ComponentSucceeded,
	}
}

func (s ProjectionStatus) Validate() error {
	for name, state := range map[string]ComponentState{
		"content": s.Content, "acl": s.ACL, "index": s.Index,
		"graph": s.Graph, "artifacts": s.Artifacts,
	} {
		if err := state.Validate(); err != nil {
			return fmt.Errorf("%s projection: %w", name, err)
		}
	}
	return nil
}

func (s ProjectionStatus) Ready() bool {
	return s.Content == ComponentSucceeded && s.ACL == ComponentSucceeded &&
		s.Index == ComponentSucceeded && s.Graph == ComponentSucceeded &&
		s.Artifacts == ComponentSucceeded
}

func (s ProjectionStatus) Failed() bool {
	return s.Content == ComponentFailed || s.ACL == ComponentFailed ||
		s.Index == ComponentFailed || s.Graph == ComponentFailed ||
		s.Artifacts == ComponentFailed
}

// ResourceMetadata is the catalog-wide metadata shared by every resource kind.
// ResourceID is derived only from Scope, Type, and SourceKey, never content.
type ResourceMetadata struct {
	ResourceID              protocol.ResourceID       `json:"resource_id"`
	Type                    protocol.ResourceType     `json:"type"`
	Scope                   Scope                     `json:"scope"`
	SourceKey               string                    `json:"source_key"`
	AuthorizationObject     string                    `json:"authz_object"`
	AuthorizationResourceID protocol.ResourceID       `json:"authorization_resource_id"`
	ContentDigest           protocol.ContentDigest    `json:"content_digest"`
	Versions                protocol.ResourceVersions `json:"versions"`
	ServingState            LifecycleState            `json:"serving_state"`
	ProjectionStatus        ProjectionStatus          `json:"projection_status"`
	Sensitivity             Sensitivity               `json:"sensitivity"`
	SecurityDomain          string                    `json:"security_domain"`
}

func NewResourceMetadata(
	scope Scope,
	resourceType protocol.ResourceType,
	sourceKey string,
	authorizationObject string,
	authorizationResourceID protocol.ResourceID,
	contentDigest protocol.ContentDigest,
	versions protocol.ResourceVersions,
	sensitivity Sensitivity,
	securityDomain string,
) (ResourceMetadata, error) {
	id, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, resourceType, sourceKey)
	if err != nil {
		return ResourceMetadata{}, err
	}
	metadata := ResourceMetadata{
		ResourceID: id, Type: resourceType, Scope: scope, SourceKey: sourceKey,
		AuthorizationObject: authorizationObject, AuthorizationResourceID: authorizationResourceID,
		ContentDigest: contentDigest, Versions: versions, ServingState: StateStaged,
		ProjectionStatus: PendingProjectionStatus(), Sensitivity: sensitivity,
		SecurityDomain: securityDomain,
	}
	if metadata.AuthorizationResourceID == "" && resourceType != protocol.ResourceChunk {
		metadata.AuthorizationResourceID = metadata.ResourceID
	}
	if err := metadata.Validate(); err != nil {
		return ResourceMetadata{}, err
	}
	return metadata, nil
}

func (m ResourceMetadata) Validate() error {
	if err := m.Scope.Validate(); err != nil {
		return err
	}
	if err := validateResourceType(m.Type); err != nil {
		return err
	}
	if err := validateToken("source_key", m.SourceKey); err != nil {
		return err
	}
	expectedID, err := protocol.NewStableResourceID(
		m.Scope.TenantID, m.Scope.KnowledgeBaseID, m.Type, m.SourceKey,
	)
	if err != nil {
		return err
	}
	if m.ResourceID != expectedID {
		return fmt.Errorf("resource_id does not match the stable source identity")
	}
	if err := validateToken("authz_object", m.AuthorizationObject); err != nil {
		return err
	}
	if err := m.AuthorizationResourceID.Validate(); err != nil {
		return fmt.Errorf("authorization_resource_id: %w", err)
	}
	if m.Type == protocol.ResourceChunk {
		if m.AuthorizationResourceID == m.ResourceID {
			return fmt.Errorf("chunk authorization boundary must be its parent document")
		}
	} else if m.AuthorizationResourceID != m.ResourceID {
		return fmt.Errorf("non-chunk resource must use itself as the authorization boundary")
	}
	if err := m.ContentDigest.Validate(); err != nil {
		return err
	}
	if err := m.Versions.Validate(); err != nil {
		return err
	}
	if err := m.ServingState.Validate(); err != nil {
		return err
	}
	if err := m.ProjectionStatus.Validate(); err != nil {
		return err
	}
	if m.ServingState.IsServing() && !m.ProjectionStatus.Ready() {
		return fmt.Errorf("serving resource has an incomplete projection")
	}
	if err := m.Sensitivity.Validate(); err != nil {
		return err
	}
	return validateToken("security_domain", m.SecurityDomain)
}

func (m ResourceMetadata) IsServing() bool {
	return m.ServingState.IsServing() && m.ProjectionStatus.Ready()
}

// DocumentVersionRef pins provenance to an exact source document version.
type DocumentVersionRef struct {
	ResourceID        protocol.ResourceID `json:"resource_id"`
	SourceVersion     string              `json:"source_version"`
	ContentVersion    string              `json:"content_version"`
	ACLVersion        string              `json:"acl_version"`
	ProjectionVersion string              `json:"projection_version"`
}

func (r DocumentVersionRef) Validate() error {
	if err := r.ResourceID.Validate(); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"source_version": r.SourceVersion, "content_version": r.ContentVersion,
		"acl_version": r.ACLVersion, "projection_version": r.ProjectionVersion,
	} {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	return nil
}

type EvidenceRef struct {
	ResourceID protocol.ResourceID       `json:"resource_id"`
	Type       protocol.ResourceType     `json:"type"`
	Versions   protocol.ResourceVersions `json:"versions"`
	Document   DocumentVersionRef        `json:"document"`
}

func (r EvidenceRef) Validate() error {
	if err := r.ResourceID.Validate(); err != nil {
		return err
	}
	if err := validateResourceType(r.Type); err != nil {
		return err
	}
	if err := r.Versions.Validate(); err != nil {
		return err
	}
	if err := r.Document.Validate(); err != nil {
		return fmt.Errorf("source document: %w", err)
	}
	if r.Versions.Projection != r.Document.ProjectionVersion {
		return fmt.Errorf("evidence and source document projection versions differ")
	}
	if r.Versions.Source != r.Document.SourceVersion || r.Versions.ACL != r.Document.ACLVersion {
		return fmt.Errorf("evidence does not pin the source document source and ACL versions")
	}
	if r.Type == protocol.ResourceDocument {
		if r.ResourceID != r.Document.ResourceID || r.Versions.Content != r.Document.ContentVersion {
			return fmt.Errorf("document evidence does not match its document version")
		}
	}
	return nil
}

type Support struct {
	SupportID string        `json:"support_id"`
	Evidence  []EvidenceRef `json:"evidence"`
	Complete  bool          `json:"complete"`
}

type Provenance struct {
	DerivationMode protocol.DerivationMode `json:"derivation_mode"`
	Supports       []Support               `json:"supports"`
}

func (p Provenance) Validate() error {
	if p.DerivationMode != protocol.DerivationAnySupport && p.DerivationMode != protocol.DerivationAllRequired {
		return fmt.Errorf("unsupported derivation mode %q", p.DerivationMode)
	}
	if len(p.Supports) == 0 {
		return fmt.Errorf("at least one provenance support is required")
	}
	seen := make(map[string]struct{}, len(p.Supports))
	for _, support := range p.Supports {
		if err := validateToken("support_id", support.SupportID); err != nil {
			return err
		}
		if _, ok := seen[support.SupportID]; ok {
			return fmt.Errorf("duplicate support_id %q", support.SupportID)
		}
		seen[support.SupportID] = struct{}{}
		if len(support.Evidence) == 0 {
			return fmt.Errorf("support %s has no evidence", support.SupportID)
		}
		if p.DerivationMode == protocol.DerivationAnySupport && !support.Complete {
			return fmt.Errorf("any_support requires every support to be independently complete")
		}
		for _, evidence := range support.Evidence {
			if err := evidence.Validate(); err != nil {
				return fmt.Errorf("support %s: %w", support.SupportID, err)
			}
		}
	}
	return nil
}

func (p Provenance) normalized() Provenance {
	out := Provenance{DerivationMode: p.DerivationMode, Supports: append([]Support(nil), p.Supports...)}
	for i := range out.Supports {
		out.Supports[i].Evidence = append([]EvidenceRef(nil), out.Supports[i].Evidence...)
		sort.Slice(out.Supports[i].Evidence, func(a, b int) bool {
			left, right := out.Supports[i].Evidence[a], out.Supports[i].Evidence[b]
			if left.Document.ResourceID != right.Document.ResourceID {
				return left.Document.ResourceID < right.Document.ResourceID
			}
			return left.ResourceID < right.ResourceID
		})
	}
	sort.Slice(out.Supports, func(i, j int) bool {
		return out.Supports[i].SupportID < out.Supports[j].SupportID
	})
	return out
}

type Document struct {
	Metadata ResourceMetadata  `json:"metadata"`
	Snapshot SourceSnapshotRef `json:"source_snapshot"`
	Path     string            `json:"path"`
	Title    string            `json:"title,omitempty"`
}

func (d Document) Validate() error {
	if d.Metadata.Type != protocol.ResourceDocument {
		return fmt.Errorf("document metadata has type %q", d.Metadata.Type)
	}
	if err := d.Metadata.Validate(); err != nil {
		return err
	}
	if err := d.Snapshot.Validate(); err != nil {
		return err
	}
	if d.Snapshot.Scope != d.Metadata.Scope {
		return fmt.Errorf("document snapshot crosses the resource scope")
	}
	if d.Snapshot.SecurityDomain != d.Metadata.SecurityDomain {
		return fmt.Errorf("document snapshot crosses the resource security domain")
	}
	if d.Snapshot.Version != d.Metadata.Versions.Source {
		return fmt.Errorf("document source version does not match its snapshot")
	}
	return validateToken("path", d.Path)
}

func (d Document) VersionRef() DocumentVersionRef {
	return DocumentVersionRef{
		ResourceID: d.Metadata.ResourceID, SourceVersion: d.Metadata.Versions.Source,
		ContentVersion: d.Metadata.Versions.Content, ACLVersion: d.Metadata.Versions.ACL,
		ProjectionVersion: d.Metadata.Versions.Projection,
	}
}

func (d Document) EvidenceRef() EvidenceRef {
	return EvidenceRef{
		ResourceID: d.Metadata.ResourceID, Type: protocol.ResourceDocument,
		Versions: d.Metadata.Versions, Document: d.VersionRef(),
	}
}

type Chunk struct {
	Metadata ResourceMetadata   `json:"metadata"`
	Document DocumentVersionRef `json:"document"`
	Ordinal  int                `json:"ordinal"`
	Span     [2]int             `json:"span"`
}

func (c Chunk) Validate() error {
	if c.Metadata.Type != protocol.ResourceChunk {
		return fmt.Errorf("chunk metadata has type %q", c.Metadata.Type)
	}
	if err := c.Metadata.Validate(); err != nil {
		return err
	}
	if err := c.Document.Validate(); err != nil {
		return err
	}
	if c.Metadata.AuthorizationResourceID != c.Document.ResourceID {
		return fmt.Errorf("chunk authorization boundary does not match its document")
	}
	if c.Metadata.Versions.Source != c.Document.SourceVersion ||
		c.Metadata.Versions.ACL != c.Document.ACLVersion ||
		c.Metadata.Versions.Projection != c.Document.ProjectionVersion {
		return fmt.Errorf("chunk does not inherit its document source, ACL, and projection versions")
	}
	if c.Ordinal < 0 || c.Span[0] < 0 || c.Span[1] <= c.Span[0] {
		return fmt.Errorf("chunk ordinal and span must be non-negative and non-empty")
	}
	return nil
}

func (c Chunk) EvidenceRef() EvidenceRef {
	return EvidenceRef{
		ResourceID: c.Metadata.ResourceID, Type: protocol.ResourceChunk,
		Versions: c.Metadata.Versions, Document: c.Document,
	}
}

type Entity struct {
	Metadata   ResourceMetadata `json:"metadata"`
	Name       string           `json:"name"`
	EntityType string           `json:"entity_type"`
	Aliases    []string         `json:"aliases,omitempty"`
	Provenance Provenance       `json:"provenance"`
}

func (e Entity) Validate() error {
	if e.Metadata.Type != protocol.ResourceEntity {
		return fmt.Errorf("entity metadata has type %q", e.Metadata.Type)
	}
	if err := e.Metadata.Validate(); err != nil {
		return err
	}
	if err := validateToken("entity name", e.Name); err != nil {
		return err
	}
	if err := validateToken("entity type", e.EntityType); err != nil {
		return err
	}
	return e.Provenance.Validate()
}

type Claim struct {
	Metadata       ResourceMetadata   `json:"metadata"`
	SourceDocument DocumentVersionRef `json:"source_document"`
	Text           string             `json:"text"`
	Confidence     string             `json:"confidence,omitempty"`
	Provenance     Provenance         `json:"provenance"`
}

func (c Claim) Validate() error {
	if c.Metadata.Type != protocol.ResourceClaim {
		return fmt.Errorf("claim metadata has type %q", c.Metadata.Type)
	}
	if err := c.Metadata.Validate(); err != nil {
		return err
	}
	if err := c.SourceDocument.Validate(); err != nil {
		return err
	}
	if err := validateToken("claim text", c.Text); err != nil {
		return err
	}
	if err := c.Provenance.Validate(); err != nil {
		return err
	}
	for _, support := range c.Provenance.Supports {
		for _, evidence := range support.Evidence {
			if evidence.Document != c.SourceDocument {
				return fmt.Errorf("source-scoped claim support %s resolves to another document version", support.SupportID)
			}
		}
	}
	return nil
}

type DerivedArtifact struct {
	Metadata   ResourceMetadata `json:"metadata"`
	Kind       string           `json:"kind"`
	Provenance Provenance       `json:"provenance"`
}

func (a DerivedArtifact) Validate() error {
	if a.Metadata.Type != protocol.ResourceDerivedArtifact {
		return fmt.Errorf("derived artifact metadata has type %q", a.Metadata.Type)
	}
	if err := a.Metadata.Validate(); err != nil {
		return err
	}
	if err := validateToken("artifact kind", a.Kind); err != nil {
		return err
	}
	return a.EffectiveProvenance().Validate()
}

func (a DerivedArtifact) EffectiveProvenance() Provenance {
	provenance := a.Provenance
	if provenance.DerivationMode == "" {
		provenance.DerivationMode = protocol.DerivationAllRequired
	}
	return provenance
}

type Catalog struct {
	Documents        []Document        `json:"documents"`
	Chunks           []Chunk           `json:"chunks"`
	Entities         []Entity          `json:"entities"`
	Claims           []Claim           `json:"claims"`
	DerivedArtifacts []DerivedArtifact `json:"derived_artifacts"`
}

// Canonical returns a validated deep copy with deterministic collection order.
func (c Catalog) Canonical() (Catalog, error) {
	out := Catalog{
		Documents:        append([]Document(nil), c.Documents...),
		Chunks:           append([]Chunk(nil), c.Chunks...),
		Entities:         append([]Entity(nil), c.Entities...),
		Claims:           append([]Claim(nil), c.Claims...),
		DerivedArtifacts: append([]DerivedArtifact(nil), c.DerivedArtifacts...),
	}
	for i := range out.Entities {
		out.Entities[i].Aliases = append([]string(nil), out.Entities[i].Aliases...)
		sort.Strings(out.Entities[i].Aliases)
		out.Entities[i].Provenance = out.Entities[i].Provenance.normalized()
	}
	for i := range out.Claims {
		out.Claims[i].Provenance = out.Claims[i].Provenance.normalized()
	}
	for i := range out.DerivedArtifacts {
		out.DerivedArtifacts[i].Provenance = out.DerivedArtifacts[i].EffectiveProvenance().normalized()
	}
	sort.Slice(out.Documents, func(i, j int) bool {
		return out.Documents[i].Metadata.ResourceID < out.Documents[j].Metadata.ResourceID
	})
	sort.Slice(out.Chunks, func(i, j int) bool {
		return out.Chunks[i].Metadata.ResourceID < out.Chunks[j].Metadata.ResourceID
	})
	sort.Slice(out.Entities, func(i, j int) bool {
		return out.Entities[i].Metadata.ResourceID < out.Entities[j].Metadata.ResourceID
	})
	sort.Slice(out.Claims, func(i, j int) bool {
		return out.Claims[i].Metadata.ResourceID < out.Claims[j].Metadata.ResourceID
	})
	sort.Slice(out.DerivedArtifacts, func(i, j int) bool {
		return out.DerivedArtifacts[i].Metadata.ResourceID < out.DerivedArtifacts[j].Metadata.ResourceID
	})
	if _, err := out.ResourceMetadata(); err != nil {
		return Catalog{}, err
	}
	return out, nil
}

func (c Catalog) ResourceMetadata() ([]ResourceMetadata, error) {
	resources := make([]ResourceMetadata, 0,
		len(c.Documents)+len(c.Chunks)+len(c.Entities)+len(c.Claims)+len(c.DerivedArtifacts))
	for _, document := range c.Documents {
		if err := document.Validate(); err != nil {
			return nil, fmt.Errorf("document %s: %w", document.Metadata.ResourceID, err)
		}
		resources = append(resources, document.Metadata)
	}
	for _, chunk := range c.Chunks {
		if err := chunk.Validate(); err != nil {
			return nil, fmt.Errorf("chunk %s: %w", chunk.Metadata.ResourceID, err)
		}
		resources = append(resources, chunk.Metadata)
	}
	for _, entity := range c.Entities {
		if err := entity.Validate(); err != nil {
			return nil, fmt.Errorf("entity %s: %w", entity.Metadata.ResourceID, err)
		}
		resources = append(resources, entity.Metadata)
	}
	for _, claim := range c.Claims {
		if err := claim.Validate(); err != nil {
			return nil, fmt.Errorf("claim %s: %w", claim.Metadata.ResourceID, err)
		}
		resources = append(resources, claim.Metadata)
	}
	for _, artifact := range c.DerivedArtifacts {
		if err := artifact.Validate(); err != nil {
			return nil, fmt.Errorf("derived artifact %s: %w", artifact.Metadata.ResourceID, err)
		}
		resources = append(resources, artifact.Metadata)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	if len(resources) > 0 {
		scope := resources[0].Scope
		securityDomain := resources[0].SecurityDomain
		for _, resource := range resources[1:] {
			if resource.Scope != scope {
				return nil, fmt.Errorf("catalog mixes resource scopes")
			}
			if resource.SecurityDomain != securityDomain {
				return nil, fmt.Errorf("catalog mixes security domains %q and %q", securityDomain, resource.SecurityDomain)
			}
		}
	}
	for i := 1; i < len(resources); i++ {
		if resources[i-1].ResourceID == resources[i].ResourceID {
			return nil, fmt.Errorf("duplicate resource_id %s", resources[i].ResourceID)
		}
	}
	return resources, nil
}

func validateResourceType(resourceType protocol.ResourceType) error {
	switch resourceType {
	case protocol.ResourceDocument, protocol.ResourceChunk, protocol.ResourceEntity,
		protocol.ResourceClaim, protocol.ResourceDerivedArtifact:
		return nil
	default:
		return fmt.Errorf("unsupported resource type %q", resourceType)
	}
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
