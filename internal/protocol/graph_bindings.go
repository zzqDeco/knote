package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	GraphBindingContractVersionV1 = 1
	GraphBindingContractVersion   = 2
)

const (
	GraphBindingsArtifactPath = "graph_bindings.jsonl"
	ClaimBindingsArtifactPath = "claim_bindings.jsonl"
)

type GraphObjectID string

func NewGraphObjectID(projectionVersion string, resourceID ResourceID) (GraphObjectID, error) {
	return newGraphObjectID(GraphBindingContractVersion, projectionVersion, resourceID)
}

func newGraphObjectID(contractVersion int, projectionVersion string, resourceID ResourceID) (GraphObjectID, error) {
	if !IsSupportedGraphBindingContractVersion(contractVersion) {
		return "", fmt.Errorf("unsupported graph binding contract version")
	}
	if err := validateToken("projection_version", projectionVersion); err != nil {
		return "", err
	}
	if err := resourceID.Validate(); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", contractVersion, projectionVersion, resourceID)))
	return GraphObjectID("kg_" + hex.EncodeToString(digest[:16])), nil
}

func IsSupportedGraphBindingContractVersion(version int) bool {
	return version == GraphBindingContractVersionV1 || version == GraphBindingContractVersion
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
	if !isSupportedClaimPredicateSourceKey(ClaimPredicateSourceKey(sourceIdentity)) {
		return "", fmt.Errorf("unsupported predicate source identity")
	}
	return claimPredicateKeyForSource(sourceIdentity), nil
}

func claimPredicateKeyForSource(sourceIdentity string) ClaimPredicateKey {
	digest := sha256.Sum256([]byte(sourceIdentity))
	return ClaimPredicateKey("pred_" + hex.EncodeToString(digest[:16]))
}

func (key ClaimPredicateKey) Validate() error {
	if err := key.validateOpaque(); err != nil {
		return err
	}
	if !isSupportedClaimPredicateKey(key) {
		return fmt.Errorf("predicate_key is not declared by the active allowlist")
	}
	return nil
}

func (key ClaimPredicateKey) validateOpaque() error {
	value := string(key)
	if !strings.HasPrefix(value, "pred_") || len(value) != len("pred_")+32 {
		return fmt.Errorf("predicate_key must be an opaque pred_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "pred_")); err != nil {
		return fmt.Errorf("predicate_key must be hexadecimal: %w", err)
	}
	return nil
}

type ClaimSupportKey string

func NewClaimSupportKey(sourceIdentity string) (ClaimSupportKey, error) {
	if err := validateToken("claim support source identity", sourceIdentity); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(sourceIdentity))
	return ClaimSupportKey("sup_" + hex.EncodeToString(digest[:16])), nil
}

func (key ClaimSupportKey) Validate() error {
	value := string(key)
	if !strings.HasPrefix(value, "sup_") || len(value) != len("sup_")+32 {
		return fmt.Errorf("support_key must be an opaque sup_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "sup_")); err != nil {
		return fmt.Errorf("support_key must be hexadecimal: %w", err)
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
	if !IsSupportedGraphBindingContractVersion(b.Version) {
		return fmt.Errorf("unsupported graph binding version")
	}
	if err := b.GraphObjectID.Validate(); err != nil {
		return err
	}
	if err := b.Resource.Validate(); err != nil {
		return fmt.Errorf("resource: %w", err)
	}
	expected, err := newGraphObjectID(b.Version, b.Resource.Versions.Projection, b.Resource.ResourceID)
	if err != nil {
		return err
	}
	if b.GraphObjectID != expected {
		return fmt.Errorf("graph_object_id does not match the exact serving resource projection")
	}
	return nil
}

// ClaimTripleBinding retains projection-scoped graph identities alongside the
// stable body-free resource identities needed to reconcile source-backed
// Claims. PredicateKey is never a user supplied relation label or property.
type ClaimSupportBinding struct {
	SupportKey            ClaimSupportKey `json:"support_key"`
	Provenance            []GraphObjectID `json:"provenance"`
	ProvenanceResourceIDs []ResourceID    `json:"provenance_resource_ids"`
}

func (b ClaimSupportBinding) Validate() error {
	if err := b.SupportKey.Validate(); err != nil {
		return err
	}
	if len(b.Provenance) == 0 || len(b.ProvenanceResourceIDs) == 0 {
		return fmt.Errorf("claim support provenance is required")
	}
	if len(b.Provenance) != len(b.ProvenanceResourceIDs) {
		return fmt.Errorf("claim support graph and stable provenance counts differ")
	}
	for index, id := range b.Provenance {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("support provenance %d: %w", index, err)
		}
		if index > 0 && b.Provenance[index-1] >= id {
			return fmt.Errorf("claim support provenance must be unique and sorted")
		}
	}
	for index, id := range b.ProvenanceResourceIDs {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("support provenance_resource_ids %d: %w", index, err)
		}
		if index > 0 && b.ProvenanceResourceIDs[index-1] >= id {
			return fmt.Errorf("claim support provenance_resource_ids must be unique and sorted")
		}
	}
	return nil
}

type ClaimTripleBinding struct {
	Version                  int                   `json:"version"`
	Claim                    GraphObjectID         `json:"claim"`
	Subject                  GraphObjectID         `json:"subject"`
	PredicateKey             ClaimPredicateKey     `json:"predicate_key"`
	Object                   GraphObjectID         `json:"object"`
	SourceDocument           GraphObjectID         `json:"source_document"`
	Derivation               DerivationMode        `json:"derivation"`
	Provenance               []GraphObjectID       `json:"provenance"`
	SubjectResourceID        ResourceID            `json:"subject_resource_id,omitempty"`
	ObjectResourceID         ResourceID            `json:"object_resource_id,omitempty"`
	SourceDocumentResourceID ResourceID            `json:"source_document_resource_id,omitempty"`
	SourceVersion            string                `json:"source_version,omitempty"`
	ProvenanceResourceIDs    []ResourceID          `json:"provenance_resource_ids,omitempty"`
	Supports                 []ClaimSupportBinding `json:"supports,omitempty"`
}

func (b ClaimTripleBinding) Validate() error {
	if !IsSupportedGraphBindingContractVersion(b.Version) {
		return fmt.Errorf("unsupported claim binding version")
	}
	for name, id := range map[string]GraphObjectID{
		"claim": b.Claim, "subject": b.Subject, "object": b.Object, "source_document": b.SourceDocument,
	} {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	predicateErr := b.PredicateKey.Validate()
	if b.Version == GraphBindingContractVersionV1 {
		predicateErr = b.PredicateKey.validateOpaque()
	}
	if predicateErr != nil {
		return predicateErr
	}
	if b.Derivation != DerivationAnySupport && b.Derivation != DerivationAllRequired {
		return fmt.Errorf("unsupported claim derivation %q", b.Derivation)
	}
	if len(b.Provenance) == 0 {
		return fmt.Errorf("claim binding provenance is required")
	}
	if b.Version == GraphBindingContractVersionV1 {
		if b.SubjectResourceID != "" || b.ObjectResourceID != "" ||
			b.SourceDocumentResourceID != "" || b.SourceVersion != "" ||
			len(b.ProvenanceResourceIDs) != 0 || len(b.Supports) != 0 {
			return fmt.Errorf("claim binding v1 contains v2 identity or support fields")
		}
	} else {
		for name, id := range map[string]ResourceID{
			"subject_resource_id":         b.SubjectResourceID,
			"object_resource_id":          b.ObjectResourceID,
			"source_document_resource_id": b.SourceDocumentResourceID,
		} {
			if err := id.Validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		if err := validateToken("source_version", b.SourceVersion); err != nil {
			return err
		}
		if len(b.ProvenanceResourceIDs) == 0 {
			return fmt.Errorf("claim binding stable provenance is required")
		}
		if len(b.Supports) == 0 {
			return fmt.Errorf("claim binding grouped provenance is required")
		}
	}
	for index, id := range b.Provenance {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("provenance %d: %w", index, err)
		}
		if index > 0 && b.Provenance[index-1] >= id {
			return fmt.Errorf("claim binding provenance must be unique and sorted")
		}
	}
	if b.Version == GraphBindingContractVersion {
		for index, id := range b.ProvenanceResourceIDs {
			if err := id.Validate(); err != nil {
				return fmt.Errorf("provenance_resource_ids %d: %w", index, err)
			}
			if index > 0 && b.ProvenanceResourceIDs[index-1] >= id {
				return fmt.Errorf("claim binding provenance_resource_ids must be unique and sorted")
			}
		}
		groupedGraph := make([]GraphObjectID, 0)
		groupedStable := make([]ResourceID, 0)
		for index, support := range b.Supports {
			if err := support.Validate(); err != nil {
				return fmt.Errorf("claim support %d: %w", index, err)
			}
			if index > 0 && b.Supports[index-1].SupportKey >= support.SupportKey {
				return fmt.Errorf("claim supports must be unique and sorted by support_key")
			}
			groupedGraph = append(groupedGraph, support.Provenance...)
			groupedStable = append(groupedStable, support.ProvenanceResourceIDs...)
		}
		if !graphObjectIDSlicesEqual(b.Provenance, canonicalGraphObjectIDs(groupedGraph)) ||
			!resourceIDSlicesEqual(b.ProvenanceResourceIDs, canonicalResourceIDs(groupedStable)) {
			return fmt.Errorf("claim support groups do not match flattened provenance")
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
	contractVersion := bindings[0].Version
	for index, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("graph binding %d: %w", index, err)
		}
		if binding.Version != contractVersion {
			return fmt.Errorf("graph resource bindings mix contract versions")
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
	contractVersion := resources[0].Version
	byGraphObject := make(map[GraphObjectID]ResourceHandle, len(resources))
	for _, binding := range resources {
		byGraphObject[binding.GraphObjectID] = binding.Resource
	}
	seenClaims := make(map[GraphObjectID]struct{}, len(claims))
	for index, claim := range claims {
		if err := claim.Validate(); err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if claim.Version != contractVersion {
			return fmt.Errorf("claim binding %d does not match graph binding contract version", index)
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
		subject, err := requireBoundGraphResource(byGraphObject, claim.Subject, ResourceEntity, "subject")
		if err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if claim.Version == GraphBindingContractVersion && subject.ResourceID != claim.SubjectResourceID {
			return fmt.Errorf("claim binding %d subject resource identity does not match its graph binding", index)
		}
		object, err := requireBoundGraphResource(byGraphObject, claim.Object, ResourceEntity, "object")
		if err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if claim.Version == GraphBindingContractVersion && object.ResourceID != claim.ObjectResourceID {
			return fmt.Errorf("claim binding %d object resource identity does not match its graph binding", index)
		}
		source, err := requireBoundGraphResource(byGraphObject, claim.SourceDocument, ResourceDocument, "source_document")
		if err != nil {
			return fmt.Errorf("claim binding %d: %w", index, err)
		}
		if claim.Version == GraphBindingContractVersion &&
			(source.ResourceID != claim.SourceDocumentResourceID || source.Versions.Source != claim.SourceVersion) {
			return fmt.Errorf("claim binding %d source identity or version does not match its graph binding", index)
		}
		validateProvenance := func(graphIDs []GraphObjectID, stableIDs []ResourceID, field string) error {
			provenanceResources := make(map[ResourceID]struct{}, len(graphIDs))
			for supportIndex, supportID := range graphIDs {
				support, ok := byGraphObject[supportID]
				if !ok {
					return fmt.Errorf("claim binding %d %s %d is not graph-bound", index, field, supportIndex)
				}
				if support.Type != ResourceDocument && support.Type != ResourceChunk {
					return fmt.Errorf("claim binding %d %s %d is not source evidence", index, field, supportIndex)
				}
				if support.ResourceID != source.ResourceID && support.AuthorizationResourceID != source.ResourceID {
					return fmt.Errorf("claim binding %d %s %d is outside source document %s", index, field, supportIndex, source.ResourceID)
				}
				provenanceResources[support.ResourceID] = struct{}{}
			}
			if stableIDs != nil {
				if len(provenanceResources) != len(stableIDs) {
					return fmt.Errorf("claim binding %d stable %s does not match its graph bindings", index, field)
				}
				for _, resourceID := range stableIDs {
					if _, ok := provenanceResources[resourceID]; !ok {
						return fmt.Errorf("claim binding %d stable %s does not match its graph bindings", index, field)
					}
				}
			}
			return nil
		}
		stableProvenance := claim.ProvenanceResourceIDs
		if claim.Version == GraphBindingContractVersionV1 {
			stableProvenance = nil
		}
		if err := validateProvenance(claim.Provenance, stableProvenance, "provenance"); err != nil {
			return err
		}
		if claim.Version == GraphBindingContractVersion {
			for supportIndex, support := range claim.Supports {
				if err := validateProvenance(support.Provenance, support.ProvenanceResourceIDs, fmt.Sprintf("support %d provenance", supportIndex)); err != nil {
					return err
				}
			}
		}
		if claimResource.TenantID != source.TenantID || claimResource.KnowledgeBaseID != source.KnowledgeBaseID {
			return fmt.Errorf("claim binding %d crosses source scope", index)
		}
	}
	return nil
}

// UpgradeGraphBindingContract converts a coherent v1 projection to v2. V1
// all_required provenance becomes one group, while any_support provenance
// becomes one independently sufficient group per evidence resource.
func UpgradeGraphBindingContract(
	resources []GraphResourceBinding,
	claims []ClaimTripleBinding,
) ([]GraphResourceBinding, []ClaimTripleBinding, error) {
	if err := ValidateClaimTripleBindings(resources, claims); err != nil {
		return nil, nil, err
	}
	if resources[0].Version == GraphBindingContractVersion {
		return cloneGraphResourceBindings(resources), cloneClaimTripleBindings(claims), nil
	}

	upgradedResources := make([]GraphResourceBinding, 0, len(resources))
	upgradedGraphIDs := make(map[GraphObjectID]GraphObjectID, len(resources))
	resourcesByGraphID := make(map[GraphObjectID]ResourceHandle, len(resources))
	for _, resource := range resources {
		upgraded, err := NewGraphResourceBinding(resource.Resource)
		if err != nil {
			return nil, nil, err
		}
		upgradedResources = append(upgradedResources, upgraded)
		upgradedGraphIDs[resource.GraphObjectID] = upgraded.GraphObjectID
		resourcesByGraphID[resource.GraphObjectID] = resource.Resource
	}
	SortGraphResourceBindings(upgradedResources)

	upgradedClaims := make([]ClaimTripleBinding, 0, len(claims))
	for _, claim := range claims {
		// V1 accepted opaque predicate digests before the checked-in allowlist.
		// Keep those bundles readable without promoting undeclared edges into v2.
		if !isSupportedClaimPredicateKey(claim.PredicateKey) {
			continue
		}
		upgraded := claim
		upgraded.Version = GraphBindingContractVersion
		upgraded.Claim = upgradedGraphIDs[claim.Claim]
		upgraded.Subject = upgradedGraphIDs[claim.Subject]
		upgraded.Object = upgradedGraphIDs[claim.Object]
		upgraded.SourceDocument = upgradedGraphIDs[claim.SourceDocument]
		upgraded.Provenance = make([]GraphObjectID, 0, len(claim.Provenance))
		for _, graphID := range claim.Provenance {
			upgraded.Provenance = append(upgraded.Provenance, upgradedGraphIDs[graphID])
		}
		upgraded.Provenance = canonicalGraphObjectIDs(upgraded.Provenance)
		upgraded.SubjectResourceID = resourcesByGraphID[claim.Subject].ResourceID
		upgraded.ObjectResourceID = resourcesByGraphID[claim.Object].ResourceID
		upgraded.SourceDocumentResourceID = resourcesByGraphID[claim.SourceDocument].ResourceID
		upgraded.SourceVersion = resourcesByGraphID[claim.SourceDocument].Versions.Source
		upgraded.ProvenanceResourceIDs = make([]ResourceID, 0, len(claim.Provenance))
		for _, graphID := range claim.Provenance {
			upgraded.ProvenanceResourceIDs = append(upgraded.ProvenanceResourceIDs, resourcesByGraphID[graphID].ResourceID)
		}
		upgraded.ProvenanceResourceIDs = canonicalResourceIDs(upgraded.ProvenanceResourceIDs)
		upgraded.Supports = nil

		claimResourceID := resourcesByGraphID[claim.Claim].ResourceID
		switch claim.Derivation {
		case DerivationAllRequired:
			key, err := derivedV1ClaimSupportKey(claimResourceID, claim.Derivation, upgraded.ProvenanceResourceIDs)
			if err != nil {
				return nil, nil, err
			}
			upgraded.Supports = []ClaimSupportBinding{{
				SupportKey: key, Provenance: append([]GraphObjectID(nil), upgraded.Provenance...),
				ProvenanceResourceIDs: append([]ResourceID(nil), upgraded.ProvenanceResourceIDs...),
			}}
		case DerivationAnySupport:
			for _, graphID := range claim.Provenance {
				resourceID := resourcesByGraphID[graphID].ResourceID
				key, err := derivedV1ClaimSupportKey(claimResourceID, claim.Derivation, []ResourceID{resourceID})
				if err != nil {
					return nil, nil, err
				}
				upgraded.Supports = append(upgraded.Supports, ClaimSupportBinding{
					SupportKey: key, Provenance: []GraphObjectID{upgradedGraphIDs[graphID]},
					ProvenanceResourceIDs: []ResourceID{resourceID},
				})
			}
			sort.Slice(upgraded.Supports, func(i, j int) bool {
				return upgraded.Supports[i].SupportKey < upgraded.Supports[j].SupportKey
			})
		}
		upgradedClaims = append(upgradedClaims, upgraded)
	}
	SortClaimTripleBindings(upgradedClaims)
	if err := ValidateClaimTripleBindings(upgradedResources, upgradedClaims); err != nil {
		return nil, nil, err
	}
	return upgradedResources, upgradedClaims, nil
}

func derivedV1ClaimSupportKey(
	claimResourceID ResourceID,
	derivation DerivationMode,
	provenanceResourceIDs []ResourceID,
) (ClaimSupportKey, error) {
	parts := make([]string, len(provenanceResourceIDs))
	for index, resourceID := range provenanceResourceIDs {
		parts[index] = string(resourceID)
	}
	return NewClaimSupportKey(fmt.Sprintf(
		"v1:%s:%s:%s",
		claimResourceID,
		derivation,
		strings.Join(parts, ","),
	))
}

func cloneGraphResourceBindings(bindings []GraphResourceBinding) []GraphResourceBinding {
	return append([]GraphResourceBinding(nil), bindings...)
}

func cloneClaimTripleBindings(bindings []ClaimTripleBinding) []ClaimTripleBinding {
	cloned := append([]ClaimTripleBinding(nil), bindings...)
	for index := range cloned {
		cloned[index].Provenance = append([]GraphObjectID(nil), bindings[index].Provenance...)
		cloned[index].ProvenanceResourceIDs = append([]ResourceID(nil), bindings[index].ProvenanceResourceIDs...)
		cloned[index].Supports = append([]ClaimSupportBinding(nil), bindings[index].Supports...)
		for supportIndex := range cloned[index].Supports {
			cloned[index].Supports[supportIndex].Provenance = append(
				[]GraphObjectID(nil), bindings[index].Supports[supportIndex].Provenance...,
			)
			cloned[index].Supports[supportIndex].ProvenanceResourceIDs = append(
				[]ResourceID(nil), bindings[index].Supports[supportIndex].ProvenanceResourceIDs...,
			)
		}
	}
	return cloned
}

func SortGraphResourceBindings(bindings []GraphResourceBinding) {
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].GraphObjectID < bindings[j].GraphObjectID })
}

func SortClaimTripleBindings(bindings []ClaimTripleBinding) {
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Claim < bindings[j].Claim })
}

func canonicalGraphObjectIDs(ids []GraphObjectID) []GraphObjectID {
	if len(ids) == 0 {
		return nil
	}
	canonical := append([]GraphObjectID(nil), ids...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	result := canonical[:0]
	for _, id := range canonical {
		if len(result) == 0 || result[len(result)-1] != id {
			result = append(result, id)
		}
	}
	return result
}

func graphObjectIDSlicesEqual(left, right []GraphObjectID) bool {
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

func canonicalResourceIDs(ids []ResourceID) []ResourceID {
	if len(ids) == 0 {
		return nil
	}
	canonical := append([]ResourceID(nil), ids...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	result := canonical[:0]
	for _, id := range canonical {
		if len(result) == 0 || result[len(result)-1] != id {
			result = append(result, id)
		}
	}
	return result
}

func resourceIDSlicesEqual(left, right []ResourceID) bool {
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
