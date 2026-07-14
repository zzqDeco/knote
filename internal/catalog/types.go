package catalog

import (
	"errors"
	"fmt"
	"reflect"
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
	Dependencies            []protocol.ResourceID     `json:"dependencies,omitempty"`
	ClaimRecord             *ClaimProjectionRecord    `json:"claim_record,omitempty"`
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
	if err := validateToken("security_domain", m.SecurityDomain); err != nil {
		return err
	}
	if m.Type == protocol.ResourceClaim {
		if m.ClaimRecord != nil {
			if err := m.ClaimRecord.Validate(); err != nil {
				return err
			}
			if m.Versions.Source != m.ClaimRecord.SourceDocument.SourceVersion ||
				m.Versions.ACL != m.ClaimRecord.SourceDocument.ACLVersion ||
				m.Versions.Projection != m.ClaimRecord.SourceDocument.ProjectionVersion {
				return ErrInvalidClaimRecord
			}
			if err := validateProvenanceVersions(m, m.ClaimRecord.Provenance); err != nil {
				return ErrInvalidClaimRecord
			}
		}
	} else if m.ClaimRecord != nil {
		return ErrInvalidClaimRecord
	}
	for i, dependency := range m.Dependencies {
		if err := dependency.Validate(); err != nil {
			return fmt.Errorf("dependency %d: %w", i, err)
		}
		if dependency == m.ResourceID {
			return fmt.Errorf("resource cannot depend on itself")
		}
		if i > 0 && m.Dependencies[i-1] >= dependency {
			return fmt.Errorf("resource dependencies must be unique and in canonical order")
		}
	}
	return nil
}

func (m ResourceMetadata) IsServing() bool {
	return m.ServingState.IsServing() && m.ProjectionStatus.Ready()
}

// ServingHandle returns the exact body-free protocol identity for a published
// catalog resource. Staged, revoked, tombstoned, superseded, and failed
// metadata cannot be projected into a query binding.
func (m ResourceMetadata) ServingHandle() (protocol.ResourceHandle, error) {
	if err := m.Validate(); err != nil {
		return protocol.ResourceHandle{}, err
	}
	if !m.IsServing() {
		return protocol.ResourceHandle{}, fmt.Errorf("resource %s is not serving", m.ResourceID)
	}
	handle := protocol.ResourceHandle{
		ResourceID:              m.ResourceID,
		Type:                    m.Type,
		TenantID:                m.Scope.TenantID,
		KnowledgeBaseID:         m.Scope.KnowledgeBaseID,
		AuthorizationID:         m.AuthorizationObject,
		AuthorizationResourceID: m.AuthorizationResourceID,
		ContentDigest:           m.ContentDigest,
		Versions:                m.Versions,
		ServingState:            protocol.ServingActive,
	}
	return handle, handle.Validate()
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
		seenEvidence := make(map[struct {
			document protocol.ResourceID
			resource protocol.ResourceID
		}]struct{}, len(support.Evidence))
		for _, evidence := range support.Evidence {
			if err := evidence.Validate(); err != nil {
				return fmt.Errorf("support %s: %w", support.SupportID, err)
			}
			key := struct {
				document protocol.ResourceID
				resource protocol.ResourceID
			}{document: evidence.Document.ResourceID, resource: evidence.ResourceID}
			if _, duplicate := seenEvidence[key]; duplicate {
				return fmt.Errorf("support %s contains duplicate evidence", support.SupportID)
			}
			seenEvidence[key] = struct{}{}
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

var ErrInvalidClaimRecord = errors.New("invalid catalog claim record")

type ClaimBindingState string

const (
	ClaimBindingUnbound      ClaimBindingState = "unbound"
	ClaimBindingSourceBacked ClaimBindingState = "source_backed"
)

// ClaimProjectionRecord is the body-free Claim record persisted in a Catalog
// projection. Unbound Phase 1 text claims retain source provenance but cannot
// become graph resources or ClaimTripleBindings.
type ClaimProjectionRecord struct {
	BindingState      ClaimBindingState          `json:"binding_state"`
	SubjectResourceID protocol.ResourceID        `json:"subject_resource_id,omitempty"`
	PredicateKey      protocol.ClaimPredicateKey `json:"predicate_key,omitempty"`
	ObjectResourceID  protocol.ResourceID        `json:"object_resource_id,omitempty"`
	SourceDocument    DocumentVersionRef         `json:"source_document"`
	Provenance        Provenance                 `json:"provenance"`
}

func (r ClaimProjectionRecord) Validate() error {
	if err := r.validate(); err != nil {
		return ErrInvalidClaimRecord
	}
	if !reflect.DeepEqual(r, r.normalized()) {
		return ErrInvalidClaimRecord
	}
	return nil
}

func (r ClaimProjectionRecord) validate() error {
	if err := r.SourceDocument.Validate(); err != nil {
		return err
	}
	if err := r.Provenance.Validate(); err != nil {
		return err
	}
	for _, support := range r.Provenance.Supports {
		for _, evidence := range support.Evidence {
			if evidence.Document != r.SourceDocument {
				return ErrInvalidClaimRecord
			}
		}
	}
	switch r.BindingState {
	case ClaimBindingUnbound:
		if r.SubjectResourceID != "" || r.PredicateKey != "" || r.ObjectResourceID != "" {
			return ErrInvalidClaimRecord
		}
	case ClaimBindingSourceBacked:
		if err := r.SubjectResourceID.Validate(); err != nil {
			return err
		}
		if err := r.PredicateKey.Validate(); err != nil {
			return err
		}
		if err := r.ObjectResourceID.Validate(); err != nil {
			return err
		}
		for _, support := range r.Provenance.Supports {
			if !support.Complete {
				return ErrInvalidClaimRecord
			}
			for _, evidence := range support.Evidence {
				if evidence.Type != protocol.ResourceDocument && evidence.Type != protocol.ResourceChunk {
					return ErrInvalidClaimRecord
				}
			}
		}
	default:
		return ErrInvalidClaimRecord
	}
	return nil
}

func (r ClaimProjectionRecord) normalized() ClaimProjectionRecord {
	r.Provenance = r.Provenance.normalized()
	return r
}

func (r ClaimProjectionRecord) IsSourceBacked() bool {
	return r.BindingState == ClaimBindingSourceBacked
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
	if err := e.Provenance.Validate(); err != nil {
		return err
	}
	return validateProvenanceVersions(e.Metadata, e.Provenance)
}

type Claim struct {
	Metadata          ResourceMetadata           `json:"metadata"`
	BindingState      ClaimBindingState          `json:"binding_state"`
	SubjectResourceID protocol.ResourceID        `json:"subject_resource_id,omitempty"`
	PredicateKey      protocol.ClaimPredicateKey `json:"predicate_key,omitempty"`
	ObjectResourceID  protocol.ResourceID        `json:"object_resource_id,omitempty"`
	SourceDocument    DocumentVersionRef         `json:"source_document"`
	Text              string                     `json:"text"`
	Confidence        string                     `json:"confidence,omitempty"`
	Provenance        Provenance                 `json:"provenance"`
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
	if c.Metadata.Versions.Source != c.SourceDocument.SourceVersion ||
		c.Metadata.Versions.ACL != c.SourceDocument.ACLVersion ||
		c.Metadata.Versions.Projection != c.SourceDocument.ProjectionVersion {
		return fmt.Errorf("claim metadata does not match its source document versions")
	}
	if err := validateToken("claim text", c.Text); err != nil {
		return err
	}
	if err := c.Provenance.Validate(); err != nil {
		return err
	}
	record := c.projectionRecord().normalized()
	if err := record.Validate(); err != nil {
		return err
	}
	if c.Metadata.ClaimRecord != nil && !reflect.DeepEqual(c.Metadata.ClaimRecord, &record) {
		return ErrInvalidClaimRecord
	}
	if err := validateProvenanceVersions(c.Metadata, c.Provenance); err != nil {
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

func (c Claim) projectionRecord() ClaimProjectionRecord {
	return ClaimProjectionRecord{
		BindingState: c.BindingState, SubjectResourceID: c.SubjectResourceID,
		PredicateKey: c.PredicateKey, ObjectResourceID: c.ObjectResourceID,
		SourceDocument: c.SourceDocument, Provenance: c.Provenance,
	}
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
	provenance := a.EffectiveProvenance()
	if err := provenance.Validate(); err != nil {
		return err
	}
	return validateProvenanceVersions(a.Metadata, provenance)
}

func validateProvenanceVersions(metadata ResourceMetadata, provenance Provenance) error {
	for _, support := range provenance.Supports {
		for _, evidence := range support.Evidence {
			if evidence.Versions.Source != metadata.Versions.Source ||
				evidence.Versions.Projection != metadata.Versions.Projection {
				return fmt.Errorf("support %s evidence %s is stale for resource %s", support.SupportID, evidence.ResourceID, metadata.ResourceID)
			}
		}
	}
	return nil
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

func (c Catalog) Validate() error {
	_, err := c.ResourceMetadata()
	return err
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
		record := out.Claims[i].projectionRecord().normalized()
		out.Claims[i].Metadata.ClaimRecord = &record
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
		metadata, err := metadataWithDependencies(document.Metadata, nil)
		if err != nil {
			return nil, fmt.Errorf("document %s: %w", document.Metadata.ResourceID, err)
		}
		resources = append(resources, metadata)
	}
	for _, chunk := range c.Chunks {
		if err := chunk.Validate(); err != nil {
			return nil, fmt.Errorf("chunk %s: %w", chunk.Metadata.ResourceID, err)
		}
		metadata, err := metadataWithDependencies(chunk.Metadata, []protocol.ResourceID{chunk.Document.ResourceID})
		if err != nil {
			return nil, fmt.Errorf("chunk %s: %w", chunk.Metadata.ResourceID, err)
		}
		resources = append(resources, metadata)
	}
	for _, entity := range c.Entities {
		if err := entity.Validate(); err != nil {
			return nil, fmt.Errorf("entity %s: %w", entity.Metadata.ResourceID, err)
		}
		metadata, err := metadataWithDependencies(entity.Metadata, provenanceDependencies(entity.Provenance))
		if err != nil {
			return nil, fmt.Errorf("entity %s: %w", entity.Metadata.ResourceID, err)
		}
		resources = append(resources, metadata)
	}
	for _, claim := range c.Claims {
		if err := claim.Validate(); err != nil {
			return nil, fmt.Errorf("claim %s: %w", claim.Metadata.ResourceID, err)
		}
		dependencies := append(provenanceDependencies(claim.Provenance), claim.SourceDocument.ResourceID)
		if claim.BindingState == ClaimBindingSourceBacked {
			dependencies = append(dependencies, claim.SubjectResourceID, claim.ObjectResourceID)
		}
		metadata := claim.Metadata
		record := claim.projectionRecord().normalized()
		if metadata.ClaimRecord != nil && !reflect.DeepEqual(metadata.ClaimRecord, &record) {
			return nil, fmt.Errorf("claim %s: %w", claim.Metadata.ResourceID, ErrInvalidClaimRecord)
		}
		metadata.ClaimRecord = &record
		metadata, err := metadataWithDependencies(metadata, dependencies)
		if err != nil {
			return nil, fmt.Errorf("claim %s: %w", claim.Metadata.ResourceID, err)
		}
		resources = append(resources, metadata)
	}
	for _, artifact := range c.DerivedArtifacts {
		if err := artifact.Validate(); err != nil {
			return nil, fmt.Errorf("derived artifact %s: %w", artifact.Metadata.ResourceID, err)
		}
		metadata, err := metadataWithDependencies(artifact.Metadata, provenanceDependencies(artifact.EffectiveProvenance()))
		if err != nil {
			return nil, fmt.Errorf("derived artifact %s: %w", artifact.Metadata.ResourceID, err)
		}
		resources = append(resources, metadata)
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
	if err := c.validateReferences(resources); err != nil {
		return nil, err
	}
	return resources, nil
}

func provenanceDependencies(provenance Provenance) []protocol.ResourceID {
	dependencies := make([]protocol.ResourceID, 0)
	for _, support := range provenance.Supports {
		for _, evidence := range support.Evidence {
			dependencies = append(dependencies, evidence.ResourceID)
		}
	}
	return dependencies
}

func metadataWithDependencies(metadata ResourceMetadata, dependencies []protocol.ResourceID) (ResourceMetadata, error) {
	dependencies = canonicalResourceIDs(dependencies)
	if len(metadata.Dependencies) != 0 && !resourceIDsEqual(metadata.Dependencies, dependencies) {
		return ResourceMetadata{}, fmt.Errorf("dependencies do not match canonical catalog references")
	}
	metadata.Dependencies = dependencies
	return metadata, nil
}

func canonicalResourceIDs(resourceIDs []protocol.ResourceID) []protocol.ResourceID {
	if len(resourceIDs) == 0 {
		return nil
	}
	canonical := append([]protocol.ResourceID(nil), resourceIDs...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	result := canonical[:0]
	for _, resourceID := range canonical {
		if len(result) == 0 || result[len(result)-1] != resourceID {
			result = append(result, resourceID)
		}
	}
	return result
}

func resourceIDsEqual(left, right []protocol.ResourceID) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (c Catalog) validateReferences(resources []ResourceMetadata) error {
	resourcesByID := make(map[protocol.ResourceID]ResourceMetadata, len(resources))
	for _, resource := range resources {
		resourcesByID[resource.ResourceID] = resource
	}
	documentsByID := make(map[protocol.ResourceID]DocumentVersionRef, len(c.Documents))
	for _, document := range c.Documents {
		documentsByID[document.Metadata.ResourceID] = document.VersionRef()
	}
	claimDocumentsByID := make(map[protocol.ResourceID]DocumentVersionRef, len(c.Claims))
	for _, claim := range c.Claims {
		claimDocumentsByID[claim.Metadata.ResourceID] = claim.SourceDocument
	}

	for _, chunk := range c.Chunks {
		if err := resolveDocumentReference(chunk.Document, documentsByID); err != nil {
			return fmt.Errorf("chunk %s document: %w", chunk.Metadata.ResourceID, err)
		}
	}
	for _, claim := range c.Claims {
		if err := resolveDocumentReference(claim.SourceDocument, documentsByID); err != nil {
			return fmt.Errorf("claim %s source document: %w", claim.Metadata.ResourceID, err)
		}
		if claim.BindingState == ClaimBindingSourceBacked {
			for _, endpoint := range []protocol.ResourceID{claim.SubjectResourceID, claim.ObjectResourceID} {
				resource, ok := resourcesByID[endpoint]
				if !ok || resource.Type != protocol.ResourceEntity {
					return fmt.Errorf("claim %s: %w", claim.Metadata.ResourceID, ErrInvalidClaimRecord)
				}
			}
		}
		if err := resolveProvenanceReferences(claim.Metadata, claim.Provenance, resourcesByID, documentsByID, claimDocumentsByID); err != nil {
			return fmt.Errorf("claim %s provenance: %w", claim.Metadata.ResourceID, err)
		}
	}
	for _, entity := range c.Entities {
		if err := resolveProvenanceReferences(entity.Metadata, entity.Provenance, resourcesByID, documentsByID, claimDocumentsByID); err != nil {
			return fmt.Errorf("entity %s provenance: %w", entity.Metadata.ResourceID, err)
		}
	}
	for _, artifact := range c.DerivedArtifacts {
		if err := resolveProvenanceReferences(artifact.Metadata, artifact.EffectiveProvenance(), resourcesByID, documentsByID, claimDocumentsByID); err != nil {
			return fmt.Errorf("derived artifact %s provenance: %w", artifact.Metadata.ResourceID, err)
		}
	}
	return c.validateProvenanceAcyclic()
}

func resolveProvenanceReferences(
	metadata ResourceMetadata,
	provenance Provenance,
	resourcesByID map[protocol.ResourceID]ResourceMetadata,
	documentsByID map[protocol.ResourceID]DocumentVersionRef,
	claimDocumentsByID map[protocol.ResourceID]DocumentVersionRef,
) error {
	for _, support := range provenance.Supports {
		requiresSource := metadata.Type == protocol.ResourceEntity
		hasSource := false
		for _, evidence := range support.Evidence {
			if evidence.ResourceID == metadata.ResourceID {
				return fmt.Errorf("support %s is self-referential", support.SupportID)
			}
			resource, ok := resourcesByID[evidence.ResourceID]
			if !ok || resource.Type != evidence.Type || resource.Versions != evidence.Versions {
				return fmt.Errorf("support %s evidence %s does not resolve in the catalog", support.SupportID, evidence.ResourceID)
			}
			if resource.Type == protocol.ResourceChunk && resource.AuthorizationResourceID != evidence.Document.ResourceID {
				return fmt.Errorf("support %s chunk evidence %s does not resolve to its authorization document", support.SupportID, evidence.ResourceID)
			}
			if resource.Type == protocol.ResourceClaim && claimDocumentsByID[evidence.ResourceID] != evidence.Document {
				return fmt.Errorf("support %s claim evidence %s does not resolve to its source document", support.SupportID, evidence.ResourceID)
			}
			if err := resolveDocumentReference(evidence.Document, documentsByID); err != nil {
				return fmt.Errorf("support %s evidence %s document: %w", support.SupportID, evidence.ResourceID, err)
			}
			requiresSource = requiresSource || evidence.Type == protocol.ResourceEntity
			hasSource = hasSource || evidence.Type == protocol.ResourceDocument || evidence.Type == protocol.ResourceChunk
		}
		if requiresSource && !hasSource {
			return fmt.Errorf("support %s involving entity evidence requires document or chunk evidence", support.SupportID)
		}
	}
	return nil
}

func (c Catalog) validateProvenanceAcyclic() error {
	provenanceByID := make(map[protocol.ResourceID]Provenance, len(c.Claims)+len(c.Entities)+len(c.DerivedArtifacts))
	for _, claim := range c.Claims {
		provenanceByID[claim.Metadata.ResourceID] = claim.Provenance
	}
	for _, entity := range c.Entities {
		provenanceByID[entity.Metadata.ResourceID] = entity.Provenance
	}
	for _, artifact := range c.DerivedArtifacts {
		provenanceByID[artifact.Metadata.ResourceID] = artifact.EffectiveProvenance()
	}
	resourceIDs := make([]protocol.ResourceID, 0, len(provenanceByID))
	for resourceID := range provenanceByID {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Slice(resourceIDs, func(i, j int) bool { return resourceIDs[i] < resourceIDs[j] })
	states := make(map[protocol.ResourceID]uint8, len(provenanceByID))
	var visit func(protocol.ResourceID) error
	visit = func(resourceID protocol.ResourceID) error {
		states[resourceID] = 1
		for _, support := range provenanceByID[resourceID].Supports {
			for _, evidence := range support.Evidence {
				if _, derived := provenanceByID[evidence.ResourceID]; !derived {
					continue
				}
				switch states[evidence.ResourceID] {
				case 1:
					return fmt.Errorf("provenance cycle includes resources %s and %s", resourceID, evidence.ResourceID)
				case 0:
					if err := visit(evidence.ResourceID); err != nil {
						return err
					}
				}
			}
		}
		states[resourceID] = 2
		return nil
	}
	for _, resourceID := range resourceIDs {
		if states[resourceID] == 0 {
			if err := visit(resourceID); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveDocumentReference(
	reference DocumentVersionRef,
	documentsByID map[protocol.ResourceID]DocumentVersionRef,
) error {
	document, ok := documentsByID[reference.ResourceID]
	if !ok || document != reference {
		return fmt.Errorf("document %s does not resolve in the catalog", reference.ResourceID)
	}
	return nil
}

func validateResourceType(resourceType protocol.ResourceType) error {
	for _, allowed := range protocol.SupportedGraphResourceKinds() {
		if string(resourceType) == string(allowed) {
			return nil
		}
	}
	return fmt.Errorf("unsupported resource type")
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
