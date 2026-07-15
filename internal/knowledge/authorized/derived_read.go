package authorized

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zzqDeco/knote/internal/protocol"
)

// DerivedArtifactLoader preserves the two-stage protected-content boundary:
// discovery is body-free and exact loading is called only after authorization.
type DerivedArtifactLoader interface {
	DiscoverDerivedArtifact(context.Context, protocol.ResourceID) (DerivedArtifactMetadata, error)
	LoadDerivedArtifact(context.Context, DerivedArtifactMetadata) (protocol.EvidenceItem, error)
}

// ReadDerivedArtifact authorizes and materializes one exact derived artifact.
// Callers can wrap this production entrypoint with their own revision guards;
// the bundle loader also detects selected-pointer changes during body loading.
func (s *Service) ReadDerivedArtifact(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	resource protocol.ResourceHandle,
) (protocol.EvidenceItem, error) {
	item, err := s.readDerivedArtifact(ctx, authorization, resource)
	if err != nil {
		return protocol.EvidenceItem{}, ErrProtectedContentUnavailable
	}
	return item, nil
}

func (s *Service) readDerivedArtifact(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	resource protocol.ResourceHandle,
) (protocol.EvidenceItem, error) {
	if s == nil || s.loader == nil || s.authorizer == nil || ctx == nil {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact reader is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return protocol.EvidenceItem{}, err
	}
	if err := authorization.Validate(); err != nil {
		return protocol.EvidenceItem{}, err
	}
	if err := resource.ValidateFor(authorization); err != nil || resource.Type != protocol.ResourceDerivedArtifact {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact handle is invalid")
	}
	loader, ok := s.loader.(DerivedArtifactLoader)
	if !ok {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact loader is not configured")
	}
	metadata, err := loader.DiscoverDerivedArtifact(ctx, resource.ResourceID)
	if err != nil || metadata.Artifact != resource {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact metadata is unavailable")
	}
	if err := metadata.SecurityRecord.ValidateFor(
		authorization, metadata.SecurityDomain, metadata.ProjectionVersion,
	); err != nil {
		return protocol.EvidenceItem{}, err
	}
	if err := metadata.Validate(); err != nil {
		return protocol.EvidenceItem{}, err
	}
	if metadata.SecurityRecord.Kind != string(protocol.DerivedArtifactSummary) {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact body kind is unsupported")
	}
	protectedIDs := derivedArtifactProtectedResourceIDs(metadata)
	if s.cache != nil && s.cache.containsInvalidatedResource(protectedIDs) {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact resources were invalidated")
	}

	checked, err := s.checkLiveObjects(ctx, authorization, "dr-pre", derivedArtifactReadHandles(metadata))
	if err != nil || !derivedArtifactPolicyAllows(metadata, checked) {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact sources are not authorized")
	}
	item, err := loader.LoadDerivedArtifact(ctx, metadata)
	if err != nil || !derivedArtifactItemMatches(metadata, authorization, item) {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact body is unavailable")
	}

	checked, err = s.checkLiveObjects(ctx, authorization, "dr-final", derivedArtifactReadHandles(metadata))
	if err != nil {
		return protocol.EvidenceItem{}, err
	}
	if !derivedArtifactPolicyAllows(metadata, checked) {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact sources are no longer authorized")
	}
	selected, ok := selectDerivedArtifactSourceEvidence(item, func(handle protocol.ResourceHandle) bool {
		return resourceAllowed(handle, checked)
	})
	if !ok {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact sources are no longer authorized")
	}
	if s.cache != nil && s.cache.containsInvalidatedResource(protectedIDs) {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact resources were invalidated")
	}
	return selected, nil
}

func derivedArtifactReadHandles(metadata DerivedArtifactMetadata) []protocol.ResourceHandle {
	resources := make([]protocol.ResourceHandle, 0)
	for _, support := range metadata.Supports {
		resources = append(resources, support.Resources...)
	}
	return resources
}

func derivedArtifactPolicyAllows(
	metadata DerivedArtifactMetadata,
	checked map[string]objectCheck,
) bool {
	resources := derivedArtifactReadHandles(metadata)
	if len(resources) == 0 {
		return false
	}
	for _, resource := range resources {
		if !resourceAllowed(resource, checked) {
			return false
		}
	}
	return true
}

func selectDerivedArtifactSourceEvidence(
	item protocol.EvidenceItem,
	allowed func(protocol.ResourceHandle) bool,
) (protocol.EvidenceItem, bool) {
	if item.Resource.Type != protocol.ResourceDerivedArtifact || allowed == nil {
		return protocol.EvidenceItem{}, false
	}
	mode := item.Derivation
	if mode == "" {
		mode = protocol.DerivationAllRequired
	}
	if err := protocol.ValidateProvenance(mode, item.Supports); err != nil {
		return protocol.EvidenceItem{}, false
	}

	selected := cloneEvidenceItems([]protocol.EvidenceItem{item})[0]
	selected.Derivation = mode
	switch mode {
	case protocol.DerivationAllRequired:
		for _, support := range item.Supports {
			if !supportAllowedBy(support, allowed) {
				return protocol.EvidenceItem{}, false
			}
		}
	case protocol.DerivationAnySupport:
		selected.Supports = selected.Supports[:0]
		for _, support := range item.Supports {
			if supportAllowedBy(support, allowed) {
				selected.Supports = append(selected.Supports, cloneProvenanceSupport(support))
			}
		}
		if len(selected.Supports) == 0 {
			return protocol.EvidenceItem{}, false
		}
	default:
		return protocol.EvidenceItem{}, false
	}
	return selected, true
}

func derivedArtifactItemMatches(
	metadata DerivedArtifactMetadata,
	authorization protocol.AuthorizationContext,
	item protocol.EvidenceItem,
) bool {
	if err := validateLoadedItem(authorization, item); err != nil {
		return false
	}
	expected := derivedArtifactEvidenceItem(metadata, item.Content)
	return reflect.DeepEqual(item, expected)
}

func derivedArtifactProtectedResourceIDs(metadata DerivedArtifactMetadata) []protocol.ResourceID {
	ids := []protocol.ResourceID{
		metadata.Artifact.ResourceID,
		metadata.Artifact.AuthorizationResourceID,
	}
	for _, support := range metadata.Supports {
		for _, resource := range support.Resources {
			ids = append(ids, resource.ResourceID, resource.AuthorizationResourceID)
		}
	}
	return canonicalDerivedResourceIDs(ids)
}
