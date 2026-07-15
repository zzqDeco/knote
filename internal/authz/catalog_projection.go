package authz

import (
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
)

// CatalogTupleBinding associates an OpenFGA tuple with the opaque Catalog
// resource whose authorization depends on it. It never carries resource
// content, source keys, or human-readable Claim fields.
type CatalogTupleBinding struct {
	ResourceID protocol.ResourceID `json:"resource_id"`
	Tuple      Tuple               `json:"tuple"`
}

func (b CatalogTupleBinding) Validate() error {
	if err := b.ResourceID.Validate(); err != nil {
		return fmt.Errorf("catalog tuple resource_id: %w", err)
	}
	if err := b.Tuple.Validate(); err != nil {
		return err
	}
	object, err := parseReference("catalog tuple object", b.Tuple.Object, false)
	if err != nil {
		return err
	}
	if object.typeName != TypeClaim || !isSingularClaimBindingRelation(b.Tuple.Relation) {
		return fmt.Errorf("%w: catalog tuple must be a Claim source, subject, or object binding", ErrInvalidRequest)
	}
	return nil
}

// CatalogTupleProjection is the complete body-free Claim tuple snapshot for a
// published Catalog projection.
type CatalogTupleProjection struct {
	ProjectionVersion string                `json:"projection_version"`
	Bindings          []CatalogTupleBinding `json:"bindings"`
}

func (p CatalogTupleProjection) Validate() error {
	if err := validateToken("projection_version", p.ProjectionVersion); err != nil {
		return err
	}
	tuples := make([]Tuple, len(p.Bindings))
	resourcesByObject := make(map[string]protocol.ResourceID)
	seen := make(map[Tuple]struct{}, len(p.Bindings))
	for index, binding := range p.Bindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("binding %d: %w", index, err)
		}
		if index > 0 && catalogTupleBindingLess(binding, p.Bindings[index-1]) {
			return fmt.Errorf("%w: catalog tuple bindings are not in canonical order", ErrInvalidRequest)
		}
		if _, duplicate := seen[binding.Tuple]; duplicate {
			return fmt.Errorf("%w: duplicate catalog tuple", ErrInvalidRequest)
		}
		seen[binding.Tuple] = struct{}{}
		if resourceID, ok := resourcesByObject[binding.Tuple.Object]; ok && resourceID != binding.ResourceID {
			return fmt.Errorf("%w: Claim authorization object maps to multiple resources", ErrInvalidRequest)
		}
		resourcesByObject[binding.Tuple.Object] = binding.ResourceID
		tuples[index] = binding.Tuple
	}
	return ValidateTuples(tuples)
}

func (p CatalogTupleProjection) Tuples() []Tuple {
	tuples := make([]Tuple, len(p.Bindings))
	for index, binding := range p.Bindings {
		tuples[index] = binding.Tuple
	}
	return tuples
}

// ProjectCatalogClaimTuples derives the complete OpenFGA Claim relationship
// snapshot from a selected, published Catalog projection.
func ProjectCatalogClaimTuples(projection catalog.Projection) (CatalogTupleProjection, error) {
	if err := projection.Validate(); err != nil {
		return CatalogTupleProjection{}, err
	}
	if projection.State != catalog.StatePublished {
		return CatalogTupleProjection{}, fmt.Errorf("%w: Claim tuple projection requires a published Catalog", ErrInvalidRequest)
	}

	resourcesByID := make(map[protocol.ResourceID]catalog.ResourceMetadata, len(projection.Resources))
	resourcesByAuthorizationObject := make(map[string]protocol.ResourceID, len(projection.Resources))
	for _, resource := range projection.Resources {
		resourcesByID[resource.ResourceID] = resource
		if !resource.IsServing() {
			continue
		}
		authorizationBoundary := resource.AuthorizationResourceID
		if existing, ok := resourcesByAuthorizationObject[resource.AuthorizationObject]; ok && existing != authorizationBoundary {
			return CatalogTupleProjection{}, fmt.Errorf(
				"%w: authorization object maps to multiple serving Catalog resources",
				ErrInvalidRequest,
			)
		}
		resourcesByAuthorizationObject[resource.AuthorizationObject] = authorizationBoundary
	}

	bindings := make([]CatalogTupleBinding, 0)
	for _, claim := range projection.Resources {
		if !claim.IsServing() || claim.Type != protocol.ResourceClaim ||
			claim.ClaimRecord == nil || !claim.ClaimRecord.IsSourceBacked() {
			continue
		}
		record := claim.ClaimRecord
		source, err := servingAuthorizationResource(resourcesByID, record.SourceDocument.ResourceID, protocol.ResourceDocument)
		if err != nil {
			return CatalogTupleProjection{}, fmt.Errorf("claim %s source: %w", claim.ResourceID, err)
		}
		subject, err := servingAuthorizationResource(resourcesByID, record.SubjectResourceID, protocol.ResourceEntity)
		if err != nil {
			return CatalogTupleProjection{}, fmt.Errorf("claim %s subject: %w", claim.ResourceID, err)
		}
		object, err := servingAuthorizationResource(resourcesByID, record.ObjectResourceID, protocol.ResourceEntity)
		if err != nil {
			return CatalogTupleProjection{}, fmt.Errorf("claim %s object: %w", claim.ResourceID, err)
		}
		for _, tuple := range []Tuple{
			{User: source.AuthorizationObject, Relation: RelationSourceDocument, Object: claim.AuthorizationObject},
			{User: subject.AuthorizationObject, Relation: RelationSubject, Object: claim.AuthorizationObject},
			{User: object.AuthorizationObject, Relation: RelationObject, Object: claim.AuthorizationObject},
		} {
			bindings = append(bindings, CatalogTupleBinding{ResourceID: claim.ResourceID, Tuple: tuple})
		}
	}

	sort.Slice(bindings, func(i, j int) bool { return catalogTupleBindingLess(bindings[i], bindings[j]) })
	result := CatalogTupleProjection{
		ProjectionVersion: projection.Version,
		Bindings:          bindings,
	}
	if err := result.Validate(); err != nil {
		return CatalogTupleProjection{}, err
	}
	return result, nil
}

func servingAuthorizationResource(
	resources map[protocol.ResourceID]catalog.ResourceMetadata,
	resourceID protocol.ResourceID,
	resourceType protocol.ResourceType,
) (catalog.ResourceMetadata, error) {
	resource, ok := resources[resourceID]
	if !ok || resource.Type != resourceType || !resource.IsServing() {
		return catalog.ResourceMetadata{}, fmt.Errorf("%w: referenced %s is not a serving %s", ErrInvalidRequest, resourceID, resourceType)
	}
	return resource, nil
}

func catalogTupleBindingLess(left, right CatalogTupleBinding) bool {
	if tupleLess(left.Tuple, right.Tuple) {
		return true
	}
	if tupleLess(right.Tuple, left.Tuple) {
		return false
	}
	return left.ResourceID < right.ResourceID
}

func tupleLess(left, right Tuple) bool {
	if left.Object != right.Object {
		return left.Object < right.Object
	}
	if left.Relation != right.Relation {
		return left.Relation < right.Relation
	}
	return left.User < right.User
}
