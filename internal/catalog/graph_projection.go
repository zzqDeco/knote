package catalog

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

// ProjectionGraphBindings derives the complete graph projection from the
// selected serving Catalog. Callers must not supplement this result with
// adapter or model supplied graph records.
func ProjectionGraphBindings(
	projection Projection,
) ([]protocol.GraphResourceBinding, []protocol.ClaimTripleBinding, error) {
	if err := projection.Validate(); err != nil {
		return nil, nil, err
	}
	if projection.State != StatePublished {
		return nil, nil, fmt.Errorf("graph projection requires a published Catalog")
	}

	resources := make([]protocol.GraphResourceBinding, 0, len(projection.Resources))
	byResourceID := make(map[protocol.ResourceID]protocol.GraphObjectID, len(projection.Resources))
	for _, resource := range projection.Resources {
		if !resource.IsServing() || (resource.Type == protocol.ResourceClaim &&
			(resource.ClaimRecord == nil || !resource.ClaimRecord.IsSourceBacked())) {
			continue
		}
		handle, err := resource.ServingHandle()
		if err != nil {
			return nil, nil, err
		}
		binding, err := protocol.NewGraphResourceBinding(handle)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, binding)
		byResourceID[resource.ResourceID] = binding.GraphObjectID
	}
	protocol.SortGraphResourceBindings(resources)
	if err := protocol.ValidateGraphResourceBindings(resources); err != nil {
		return nil, nil, err
	}

	claims := make([]protocol.ClaimTripleBinding, 0)
	for _, resource := range projection.Resources {
		if !resource.IsServing() || resource.Type != protocol.ResourceClaim ||
			resource.ClaimRecord == nil || !resource.ClaimRecord.IsSourceBacked() {
			continue
		}
		record := resource.ClaimRecord
		provenanceResourceIDs := make([]protocol.ResourceID, 0)
		for _, support := range record.Provenance.Supports {
			for _, evidence := range support.Evidence {
				provenanceResourceIDs = append(provenanceResourceIDs, evidence.ResourceID)
			}
		}
		provenanceResourceIDs = canonicalResourceIDs(provenanceResourceIDs)
		provenance := make([]protocol.GraphObjectID, 0, len(provenanceResourceIDs))
		for _, resourceID := range provenanceResourceIDs {
			graphObjectID, ok := byResourceID[resourceID]
			if !ok {
				return nil, nil, ErrInvalidClaimRecord
			}
			provenance = append(provenance, graphObjectID)
		}
		sort.Slice(provenance, func(i, j int) bool { return provenance[i] < provenance[j] })
		binding := protocol.ClaimTripleBinding{
			Version: protocol.GraphBindingContractVersion,
			Claim:   byResourceID[resource.ResourceID], Subject: byResourceID[record.SubjectResourceID],
			PredicateKey: record.PredicateKey, Object: byResourceID[record.ObjectResourceID],
			SourceDocument: byResourceID[record.SourceDocument.ResourceID],
			Derivation:     record.Provenance.DerivationMode, Provenance: provenance,
			SubjectResourceID: record.SubjectResourceID, ObjectResourceID: record.ObjectResourceID,
			SourceDocumentResourceID: record.SourceDocument.ResourceID,
			SourceVersion:            record.SourceDocument.SourceVersion,
			ProvenanceResourceIDs:    provenanceResourceIDs,
		}
		claims = append(claims, binding)
	}
	protocol.SortClaimTripleBindings(claims)
	if err := protocol.ValidateClaimTripleBindings(resources, claims); err != nil {
		return nil, nil, err
	}
	return resources, claims, nil
}

func ValidateProjectionGraphBindings(
	projection Projection,
	resources []protocol.GraphResourceBinding,
	claims []protocol.ClaimTripleBinding,
) error {
	expectedResources, expectedClaims, err := ProjectionGraphBindings(projection)
	if err != nil {
		return err
	}
	actualResources := append([]protocol.GraphResourceBinding(nil), resources...)
	actualClaims := append([]protocol.ClaimTripleBinding(nil), claims...)
	protocol.SortGraphResourceBindings(actualResources)
	protocol.SortClaimTripleBindings(actualClaims)
	if !bindingSlicesEqual(actualResources, expectedResources) || !bindingSlicesEqual(actualClaims, expectedClaims) {
		return fmt.Errorf("graph bindings do not match the selected Catalog projection")
	}
	return nil
}

func bindingSlicesEqual[T any](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !reflect.DeepEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}
