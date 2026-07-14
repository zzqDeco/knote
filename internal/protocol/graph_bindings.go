package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const GraphBindingContractVersion = 1

const (
	GraphBindingsArtifactPath = "graph_bindings.jsonl"
	ClaimBindingsArtifactPath = "claim_bindings.jsonl"
)

type GraphObjectID string

func NewGraphObjectID(projectionVersion string, resourceID ResourceID) (GraphObjectID, error) {
	if err := validateToken("projection_version", projectionVersion); err != nil {
		return "", err
	}
	if err := resourceID.Validate(); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", GraphBindingContractVersion, projectionVersion, resourceID)))
	return GraphObjectID("kg_" + hex.EncodeToString(digest[:16])), nil
}

func (id GraphObjectID) Validate() error {
	value := string(id)
	if !strings.HasPrefix(value, "kg_") || len(value) != len("kg_")+32 {
		return fmt.Errorf("graph_object_id must be an opaque kg_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "kg_")); err != nil {
		return fmt.Errorf("graph_object_id must be hexadecimal: %w", err)
	}
	return nil
}

type ClaimPredicateKey string

func NewClaimPredicateKey(sourceIdentity string) (ClaimPredicateKey, error) {
	if err := validateToken("predicate source identity", sourceIdentity); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(sourceIdentity))
	return ClaimPredicateKey("pred_" + hex.EncodeToString(digest[:16])), nil
}

func (key ClaimPredicateKey) Validate() error {
	value := string(key)
	if !strings.HasPrefix(value, "pred_") || len(value) != len("pred_")+32 {
		return fmt.Errorf("predicate_key must be an opaque pred_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "pred_")); err != nil {
		return fmt.Errorf("predicate_key must be hexadecimal: %w", err)
	}
	return nil
}

// GraphResourceBinding is the only body-free identity accepted by the
// permissioned graph projection. GraphObjectID is projection-scoped and maps
// to one exact serving handle.
type GraphResourceBinding struct {
	Version       int            `json:"version"`
	GraphObjectID GraphObjectID  `json:"graph_object_id"`
	Resource      ResourceHandle `json:"resource"`
}

func NewGraphResourceBinding(resource ResourceHandle) (GraphResourceBinding, error) {
	if err := resource.Validate(); err != nil {
		return GraphResourceBinding{}, err
	}
	graphObjectID, err := NewGraphObjectID(resource.Versions.Projection, resource.ResourceID)
	if err != nil {
		return GraphResourceBinding{}, err
	}
	binding := GraphResourceBinding{
		Version: GraphBindingContractVersion, GraphObjectID: graphObjectID, Resource: resource,
	}
	return binding, binding.Validate()
}

func (b GraphResourceBinding) Validate() error {
	if b.Version != GraphBindingContractVersion {
		return fmt.Errorf("graph binding version must be %d", GraphBindingContractVersion)
	}
	if err := b.GraphObjectID.Validate(); err != nil {
		return err
	}
	if err := b.Resource.Validate(); err != nil {
		return fmt.Errorf("resource: %w", err)
	}
	expected, err := NewGraphObjectID(b.Resource.Versions.Projection, b.Resource.ResourceID)
	if err != nil {
		return err
	}
	if b.GraphObjectID != expected {
		return fmt.Errorf("graph_object_id does not match the exact serving resource projection")
	}
	return nil
}

// ClaimTripleBinding carries only opaque graph identities. PredicateKey is a
// digest-derived key, never a user supplied relation label or property name.
type ClaimTripleBinding struct {
	Version        int               `json:"version"`
	Claim          GraphObjectID     `json:"claim"`
	Subject        GraphObjectID     `json:"subject"`
	PredicateKey   ClaimPredicateKey `json:"predicate_key"`
	Object         GraphObjectID     `json:"object"`
	SourceDocument GraphObjectID     `json:"source_document"`
	Derivation     DerivationMode    `json:"derivation"`
	Provenance     []GraphObjectID   `json:"provenance"`
}

func (b ClaimTripleBinding) Validate() error {
	if b.Version != GraphBindingContractVersion {
		return fmt.Errorf("claim binding version must be %d", GraphBindingContractVersion)
	}
	for name, id := range map[string]GraphObjectID{
		"claim": b.Claim, "subject": b.Subject, "object": b.Object, "source_document": b.SourceDocument,
	} {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := b.PredicateKey.Validate(); err != nil {
		return err
	}
	if b.Derivation != DerivationAnySupport && b.Derivation != DerivationAllRequired {
		return fmt.Errorf("unsupported claim derivation %q", b.Derivation)
	}
	if len(b.Provenance) == 0 {
		return fmt.Errorf("claim binding provenance is required")
	}
	for index, id := range b.Provenance {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("provenance %d: %w", index, err)
		}
		if index > 0 && b.Provenance[index-1] >= id {
			return fmt.Errorf("claim binding provenance must be unique and sorted")
		}
	}
	return nil
}

func ValidateGraphResourceBindings(bindings []GraphResourceBinding) error {
	if len(bindings) == 0 {
		return fmt.Errorf("at least one graph resource binding is required")
	}
	seenResources := make(map[ResourceID]struct{}, len(bindings))
	seenGraphObjects := make(map[GraphObjectID]struct{}, len(bindings))
	resources := make(map[ResourceID]ResourceHandle, len(bindings))
	baseline := bindings[0].Resource
	for index, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("graph binding %d: %w", index, err)
		}
		if index > 0 && bindings[index-1].GraphObjectID >= binding.GraphObjectID {
			return fmt.Errorf("graph resource bindings must be unique and sorted by graph_object_id")
		}
		if _, duplicate := seenResources[binding.Resource.ResourceID]; duplicate {
			return fmt.Errorf("duplicate graph binding resource %s", binding.Resource.ResourceID)
		}
		if _, duplicate := seenGraphObjects[binding.GraphObjectID]; duplicate {
			return fmt.Errorf("duplicate graph_object_id %s", binding.GraphObjectID)
		}
		seenResources[binding.Resource.ResourceID] = struct{}{}
		seenGraphObjects[binding.GraphObjectID] = struct{}{}
		resources[binding.Resource.ResourceID] = binding.Resource
		if err := validateGraphBindingProjection(baseline, binding.Resource); err != nil {
			return fmt.Errorf("graph binding %d: %w", index, err)
		}
	}
	for _, binding := range bindings {
		if binding.Resource.Type != ResourceChunk {
			continue
		}
		parent, ok := resources[binding.Resource.AuthorizationResourceID]
		if !ok || parent.Type != ResourceDocument {
			return fmt.Errorf("chunk %s authorization boundary is not a graph-bound document", binding.Resource.ResourceID)
		}
		if parent.AuthorizationID != binding.Resource.AuthorizationID {
			return fmt.Errorf("chunk %s authorization object does not match its parent document", binding.Resource.ResourceID)
		}
	}
	return nil
}

func ValidateClaimTripleBindings(resources []GraphResourceBinding, claims []ClaimTripleBinding) error {
	if err := ValidateGraphResourceBindings(resources); err != nil {
		return err
	}
	byGraphObject := make(map[GraphObjectID]ResourceHandle, len(resources))
	for _, binding := range resources {
		byGraphObject[binding.GraphObjectID] = binding.Resource
	}
	seenClaims := make(map[GraphObjectID]struct{}, len(claims))
	for index, claim := range claims {
		if err := claim.Validate(); err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if index > 0 && claims[index-1].Claim >= claim.Claim {
			return fmt.Errorf("claim bindings must be unique and sorted by claim")
		}
		if _, duplicate := seenClaims[claim.Claim]; duplicate {
			return fmt.Errorf("duplicate claim binding %s", claim.Claim)
		}
		seenClaims[claim.Claim] = struct{}{}
		claimResource, err := requireBoundGraphResource(byGraphObject, claim.Claim, ResourceClaim, "claim")
		if err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if _, err := requireBoundGraphResource(byGraphObject, claim.Subject, ResourceEntity, "subject"); err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if _, err := requireBoundGraphResource(byGraphObject, claim.Object, ResourceEntity, "object"); err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		source, err := requireBoundGraphResource(byGraphObject, claim.SourceDocument, ResourceDocument, "source_document")
		if err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		for supportIndex, supportID := range claim.Provenance {
			support, ok := byGraphObject[supportID]
			if !ok {
				return fmt.Errorf("claim binding %d provenance %d is not graph-bound", index, supportIndex)
			}
			if support.Type != ResourceDocument && support.Type != ResourceChunk {
				return fmt.Errorf("claim binding %d provenance %d is not source evidence", index, supportIndex)
			}
			if support.ResourceID != source.ResourceID && support.AuthorizationResourceID != source.ResourceID {
				return fmt.Errorf("claim binding %d provenance %d is outside source document %s", index, supportIndex, source.ResourceID)
			}
		}
		if claimResource.TenantID != source.TenantID || claimResource.KnowledgeBaseID != source.KnowledgeBaseID {
			return fmt.Errorf("claim binding %d crosses source scope", index)
		}
	}
	return nil
}

func SortGraphResourceBindings(bindings []GraphResourceBinding) {
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].GraphObjectID < bindings[j].GraphObjectID })
}

func SortClaimTripleBindings(bindings []ClaimTripleBinding) {
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Claim < bindings[j].Claim })
}

func validateGraphBindingProjection(expected, actual ResourceHandle) error {
	if actual.TenantID != expected.TenantID || actual.KnowledgeBaseID != expected.KnowledgeBaseID {
		return fmt.Errorf("graph binding crosses tenant or knowledge-base scope")
	}
	versions := []struct {
		name     string
		expected string
		actual   string
	}{
		{"source", expected.Versions.Source, actual.Versions.Source},
		{"acl", expected.Versions.ACL, actual.Versions.ACL},
		{"index", expected.Versions.Index, actual.Versions.Index},
		{"graph", expected.Versions.Graph, actual.Versions.Graph},
		{"projection", expected.Versions.Projection, actual.Versions.Projection},
	}
	for _, version := range versions {
		if version.actual != version.expected {
			return fmt.Errorf("resource %s %s version %q does not match serving projection %q", actual.ResourceID, version.name, version.actual, version.expected)
		}
	}
	return nil
}

func requireBoundGraphResource(
	resources map[GraphObjectID]ResourceHandle,
	id GraphObjectID,
	want ResourceType,
	field string,
) (ResourceHandle, error) {
	resource, ok := resources[id]
	if !ok {
		return ResourceHandle{}, fmt.Errorf("%s %s is not graph-bound", field, id)
	}
	if resource.Type != want {
		return ResourceHandle{}, fmt.Errorf("%s %s must reference a %s resource", field, id, want)
	}
	return resource, nil
}
