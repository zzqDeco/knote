package authorized

import (
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

// DerivedArtifactSupportMetadata is the body-free serving identity for one
// persisted derivation support group.
type DerivedArtifactSupportMetadata struct {
	SupportID string
	Resources []protocol.ResourceHandle
	Complete  bool
}

// DerivedArtifactMetadata is the complete body-free contract discovered from
// the selected manifest and projection before protected content is read.
type DerivedArtifactMetadata struct {
	Artifact          protocol.ResourceHandle
	SecurityRecord    protocol.DerivedArtifactSecurityRecord
	SecurityDomain    string
	ProjectionVersion string
	Dependencies      []protocol.ResourceID
	Supports          []DerivedArtifactSupportMetadata
	SelectionDigest   protocol.ContentDigest
}

// Validate proves that every persisted support identity resolves to the exact
// serving handle discovered in the same selected projection.
func (m DerivedArtifactMetadata) Validate() error {
	if err := m.Artifact.Validate(); err != nil {
		return fmt.Errorf("derived artifact handle: %w", err)
	}
	if m.Artifact.Type != protocol.ResourceDerivedArtifact {
		return fmt.Errorf("derived artifact metadata does not describe a derived artifact")
	}
	if err := m.SecurityRecord.Validate(); err != nil {
		return fmt.Errorf("derived artifact security record: %w", err)
	}
	if m.SecurityRecord.Artifact != derivedArtifactIdentity(m.Artifact) {
		return fmt.Errorf("derived artifact security record does not match the serving handle")
	}
	if m.SecurityRecord.TenantID != m.Artifact.TenantID ||
		m.SecurityRecord.KnowledgeBaseID != m.Artifact.KnowledgeBaseID ||
		m.SecurityRecord.SecurityDomain != m.SecurityDomain ||
		m.SecurityRecord.ProjectionWatermark != m.ProjectionVersion ||
		m.Artifact.Versions.Projection != m.ProjectionVersion {
		return fmt.Errorf("derived artifact metadata crosses its serving boundary")
	}
	if err := m.SelectionDigest.Validate(); err != nil {
		return fmt.Errorf("selected metadata digest: %w", err)
	}
	if len(m.Supports) != len(m.SecurityRecord.Supports) {
		return fmt.Errorf("derived artifact support metadata does not match its security record")
	}

	dependencyIDs := make([]protocol.ResourceID, 0)
	allHandles := make(map[protocol.ResourceID]protocol.ResourceHandle)
	for index, support := range m.Supports {
		recorded := m.SecurityRecord.Supports[index]
		if support.SupportID != recorded.SupportID || support.Complete != recorded.Complete ||
			len(support.Resources) != len(recorded.Resources) {
			return fmt.Errorf("derived artifact support metadata does not match its security record")
		}
		for resourceIndex, resource := range support.Resources {
			if err := resource.Validate(); err != nil {
				return fmt.Errorf("derived artifact support %s: %w", support.SupportID, err)
			}
			if resource.TenantID != m.Artifact.TenantID ||
				resource.KnowledgeBaseID != m.Artifact.KnowledgeBaseID ||
				resource.Versions.Projection != m.ProjectionVersion ||
				derivedArtifactIdentity(resource) != recorded.Resources[resourceIndex] {
				return fmt.Errorf("derived artifact support %s does not match its serving handle", support.SupportID)
			}
			if existing, duplicate := allHandles[resource.ResourceID]; duplicate && existing != resource {
				return fmt.Errorf("derived artifact support resource %s has conflicting serving handles", resource.ResourceID)
			}
			allHandles[resource.ResourceID] = resource
			dependencyIDs = append(dependencyIDs, resource.ResourceID)
		}
	}
	if !equalDerivedResourceIDs(m.Dependencies, canonicalDerivedResourceIDs(dependencyIDs)) {
		return fmt.Errorf("derived artifact dependencies do not match its support identities")
	}
	if err := validateDerivedChunkBoundaries(m); err != nil {
		return err
	}
	return nil
}

func derivedArtifactIdentity(resource protocol.ResourceHandle) protocol.DerivedArtifactResourceIdentity {
	return protocol.DerivedArtifactResourceIdentity{
		ResourceID: resource.ResourceID, Type: resource.Type,
		AuthorizationID: resource.AuthorizationID, AuthorizationResourceID: resource.AuthorizationResourceID,
		ContentDigest: resource.ContentDigest, Versions: resource.Versions,
	}
}

func derivedArtifactEvidenceItem(metadata DerivedArtifactMetadata, content string) protocol.EvidenceItem {
	supports := make([]protocol.ProvenanceSupport, len(metadata.Supports))
	for index, support := range metadata.Supports {
		resources := append([]protocol.ResourceHandle(nil), support.Resources...)
		supports[index] = protocol.ProvenanceSupport{
			SupportID: support.SupportID,
			Resource:  resources[0],
			Evidence:  resources,
			Complete:  support.Complete,
		}
	}
	return protocol.EvidenceItem{
		Resource: metadata.Artifact, Content: content,
		Derivation: metadata.SecurityRecord.DerivationMode, Supports: supports,
		Citation: protocol.Citation{
			Handle:   "artifact-" + string(metadata.Artifact.ResourceID),
			Resource: metadata.Artifact,
		},
	}
}

func validateDerivedChunkBoundaries(metadata DerivedArtifactMetadata) error {
	all := make(map[protocol.ResourceID]protocol.ResourceHandle)
	for _, support := range metadata.Supports {
		for _, resource := range support.Resources {
			all[resource.ResourceID] = resource
		}
	}
	for _, support := range metadata.Supports {
		available := all
		if metadata.SecurityRecord.DerivationMode == protocol.DerivationAnySupport {
			available = make(map[protocol.ResourceID]protocol.ResourceHandle, len(support.Resources))
			for _, resource := range support.Resources {
				available[resource.ResourceID] = resource
			}
		}
		for _, resource := range support.Resources {
			if resource.Type != protocol.ResourceChunk {
				continue
			}
			boundary, ok := available[resource.AuthorizationResourceID]
			if !ok || validateBoundary(resource, boundary) != nil {
				return fmt.Errorf("derived artifact support %s has no exact chunk authorization boundary", support.SupportID)
			}
		}
	}
	return nil
}

func canonicalDerivedResourceIDs(ids []protocol.ResourceID) []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{}, len(ids))
	result := make([]protocol.ResourceID, 0, len(ids))
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func equalDerivedResourceIDs(left, right []protocol.ResourceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalDerivedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
