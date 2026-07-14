package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

const (
	GraphQueryContractVersion         = 1
	ClaimPredicateAllowlistVersion    = 1
	GraphResourceKindAllowlistVersion = 1
	MaxGraphStartResources            = 64
	MaxGraphRequestedFields           = 9
	MaxGraphFilters                   = 5
	MaxGraphFilterValues              = 256
	MaxGraphOrderClauses              = 5
	MaxGraphTraversalDepth            = 8
	MaxGraphFrontierWidth             = 256
	MaxGraphCandidatesPerHop          = 512
	MaxGraphTotalResources            = 2048
	MaxGraphBatchChecks               = 128
	MaxGraphWallClockMilliseconds     = 30_000
)

type ClaimPredicateSourceKey string

const (
	ClaimPredicateContradicts ClaimPredicateSourceKey = "contradicts"
	ClaimPredicateCreatedBy   ClaimPredicateSourceKey = "created_by"
	ClaimPredicateDependsOn   ClaimPredicateSourceKey = "depends_on"
	ClaimPredicateDerivedFrom ClaimPredicateSourceKey = "derived_from"
	ClaimPredicateLocatedIn   ClaimPredicateSourceKey = "located_in"
	ClaimPredicateMemberOf    ClaimPredicateSourceKey = "member_of"
	ClaimPredicateOwnedBy     ClaimPredicateSourceKey = "owned_by"
	ClaimPredicatePartOf      ClaimPredicateSourceKey = "part_of"
	ClaimPredicateRelatedTo   ClaimPredicateSourceKey = "related_to"
	ClaimPredicateSupports    ClaimPredicateSourceKey = "supports"
)

var supportedClaimPredicateSourceKeys = []ClaimPredicateSourceKey{
	ClaimPredicateContradicts,
	ClaimPredicateCreatedBy,
	ClaimPredicateDependsOn,
	ClaimPredicateDerivedFrom,
	ClaimPredicateLocatedIn,
	ClaimPredicateMemberOf,
	ClaimPredicateOwnedBy,
	ClaimPredicatePartOf,
	ClaimPredicateRelatedTo,
	ClaimPredicateSupports,
}

func SupportedClaimPredicateSourceKeys() []ClaimPredicateSourceKey {
	return append([]ClaimPredicateSourceKey(nil), supportedClaimPredicateSourceKeys...)
}

func isSupportedClaimPredicateSourceKey(key ClaimPredicateSourceKey) bool {
	switch key {
	case ClaimPredicateContradicts,
		ClaimPredicateCreatedBy,
		ClaimPredicateDependsOn,
		ClaimPredicateDerivedFrom,
		ClaimPredicateLocatedIn,
		ClaimPredicateMemberOf,
		ClaimPredicateOwnedBy,
		ClaimPredicatePartOf,
		ClaimPredicateRelatedTo,
		ClaimPredicateSupports:
		return true
	default:
		return false
	}
}

func isSupportedClaimPredicateKey(key ClaimPredicateKey) bool {
	for _, sourceKey := range supportedClaimPredicateSourceKeys {
		if claimPredicateKeyForSource(string(sourceKey)) == key {
			return true
		}
	}
	return false
}

type GraphResourceKind string

const (
	GraphResourceChunk           GraphResourceKind = "chunk"
	GraphResourceClaim           GraphResourceKind = "claim"
	GraphResourceDerivedArtifact GraphResourceKind = "derived_artifact"
	GraphResourceDocument        GraphResourceKind = "document"
	GraphResourceEntity          GraphResourceKind = "entity"
)

var supportedGraphResourceKinds = []GraphResourceKind{
	GraphResourceChunk,
	GraphResourceClaim,
	GraphResourceDerivedArtifact,
	GraphResourceDocument,
	GraphResourceEntity,
}

func SupportedGraphResourceKinds() []GraphResourceKind {
	return append([]GraphResourceKind(nil), supportedGraphResourceKinds...)
}

func isSupportedGraphResourceKind(kind GraphResourceKind) bool {
	switch kind {
	case GraphResourceChunk,
		GraphResourceClaim,
		GraphResourceDerivedArtifact,
		GraphResourceDocument,
		GraphResourceEntity:
		return true
	default:
		return false
	}
}

type GraphOperation string

const GraphOperationTraverseClaims GraphOperation = "traverse_claims"

type TraversalDirection string

const (
	TraversalOutbound TraversalDirection = "outbound"
	TraversalInbound  TraversalDirection = "inbound"
	TraversalBoth     TraversalDirection = "both"
)

type GraphField string

const (
	GraphFieldClaimID          GraphField = "claim_id"
	GraphFieldDerivationMode   GraphField = "derivation_mode"
	GraphFieldObjectID         GraphField = "object_id"
	GraphFieldPredicateKey     GraphField = "predicate_key"
	GraphFieldProvenanceIDs    GraphField = "provenance_ids"
	GraphFieldResourceKind     GraphField = "resource_kind"
	GraphFieldSourceDocumentID GraphField = "source_document_id"
	GraphFieldSourceVersion    GraphField = "source_version"
	GraphFieldSubjectID        GraphField = "subject_id"
)

var requiredTraversalFields = []GraphField{
	GraphFieldClaimID,
	GraphFieldDerivationMode,
	GraphFieldObjectID,
	GraphFieldPredicateKey,
	GraphFieldProvenanceIDs,
	GraphFieldSourceDocumentID,
	GraphFieldSourceVersion,
	GraphFieldSubjectID,
}

func isSupportedGraphField(field GraphField) bool {
	switch field {
	case GraphFieldClaimID,
		GraphFieldDerivationMode,
		GraphFieldObjectID,
		GraphFieldPredicateKey,
		GraphFieldProvenanceIDs,
		GraphFieldResourceKind,
		GraphFieldSourceDocumentID,
		GraphFieldSourceVersion,
		GraphFieldSubjectID:
		return true
	default:
		return false
	}
}

type GraphFilterKind string

const (
	GraphFilterClaimIDIn          GraphFilterKind = "claim_id_in"
	GraphFilterDerivationIn       GraphFilterKind = "derivation_in"
	GraphFilterObjectIDIn         GraphFilterKind = "object_id_in"
	GraphFilterSourceDocumentIDIn GraphFilterKind = "source_document_id_in"
	GraphFilterSubjectIDIn        GraphFilterKind = "subject_id_in"
)

type GraphFilter struct {
	Kind        GraphFilterKind  `json:"kind"`
	ResourceIDs []ResourceID     `json:"resource_ids,omitempty"`
	Derivations []DerivationMode `json:"derivations,omitempty"`
}

func validGraphFilter(filter GraphFilter, requireNormalized bool) bool {
	switch filter.Kind {
	case GraphFilterClaimIDIn,
		GraphFilterObjectIDIn,
		GraphFilterSourceDocumentIDIn,
		GraphFilterSubjectIDIn:
		if len(filter.ResourceIDs) == 0 || len(filter.ResourceIDs) > MaxGraphFilterValues ||
			len(filter.Derivations) != 0 {
			return false
		}
		for _, resourceID := range filter.ResourceIDs {
			if resourceID.Validate() != nil {
				return false
			}
		}
		return !requireNormalized || isStrictlySortedStrings(filter.ResourceIDs)
	case GraphFilterDerivationIn:
		if len(filter.Derivations) == 0 || len(filter.Derivations) > 2 || len(filter.ResourceIDs) != 0 {
			return false
		}
		for _, derivation := range filter.Derivations {
			if derivation != DerivationAnySupport && derivation != DerivationAllRequired {
				return false
			}
		}
		return !requireNormalized || isStrictlySortedStrings(filter.Derivations)
	default:
		return false
	}
}

type GraphSortKey string

const (
	GraphSortClaimID          GraphSortKey = "claim_id"
	GraphSortObjectID         GraphSortKey = "object_id"
	GraphSortPredicateKey     GraphSortKey = "predicate_key"
	GraphSortSourceDocumentID GraphSortKey = "source_document_id"
	GraphSortSubjectID        GraphSortKey = "subject_id"
)

type GraphSortDirection string

const (
	GraphSortAscending  GraphSortDirection = "ascending"
	GraphSortDescending GraphSortDirection = "descending"
)

type GraphOrder struct {
	Key       GraphSortKey       `json:"key"`
	Direction GraphSortDirection `json:"direction"`
	Priority  int                `json:"priority"`
}

func validGraphOrder(order GraphOrder) bool {
	switch order.Key {
	case GraphSortClaimID,
		GraphSortObjectID,
		GraphSortPredicateKey,
		GraphSortSourceDocumentID,
		GraphSortSubjectID:
	default:
		return false
	}
	return (order.Direction == GraphSortAscending || order.Direction == GraphSortDescending) &&
		order.Priority >= 0 && order.Priority < MaxGraphOrderClauses
}

type TraversalLimits struct {
	MaxDepth            int `json:"max_depth"`
	MaxFrontierWidth    int `json:"max_frontier_width"`
	MaxCandidatesPerHop int `json:"max_candidates_per_hop"`
	MaxTotalResources   int `json:"max_total_resources"`
	MaxBatchChecks      int `json:"max_batch_checks"`
	MaxWallClockMillis  int `json:"max_wall_clock_millis"`
}

func (limits TraversalLimits) valid(startCount int) bool {
	return limits.MaxDepth >= 0 && limits.MaxDepth <= MaxGraphTraversalDepth &&
		limits.MaxFrontierWidth > 0 && limits.MaxFrontierWidth <= MaxGraphFrontierWidth &&
		limits.MaxCandidatesPerHop > 0 && limits.MaxCandidatesPerHop <= MaxGraphCandidatesPerHop &&
		limits.MaxTotalResources >= startCount && limits.MaxTotalResources <= MaxGraphTotalResources &&
		limits.MaxBatchChecks > 0 && limits.MaxBatchChecks <= MaxGraphBatchChecks &&
		limits.MaxWallClockMillis > 0 && limits.MaxWallClockMillis <= MaxGraphWallClockMilliseconds
}

type GraphQuery struct {
	Version           int                       `json:"version"`
	Operation         GraphOperation            `json:"operation"`
	ProjectionVersion string                    `json:"projection_version"`
	IdentityVersion   int                       `json:"identity_version"`
	StartResourceIDs  []ResourceID              `json:"start_resource_ids"`
	PredicateSources  []ClaimPredicateSourceKey `json:"predicate_sources"`
	ResourceKinds     []GraphResourceKind       `json:"resource_kinds"`
	Direction         TraversalDirection        `json:"direction"`
	Fields            []GraphField              `json:"fields,omitempty"`
	Filters           []GraphFilter             `json:"filters,omitempty"`
	Order             []GraphOrder              `json:"order,omitempty"`
	Limits            TraversalLimits           `json:"limits"`
}

func (query GraphQuery) Validate() error {
	if !validGraphQuery(query) {
		return newInvalidGraphPlanError(query.ProjectionVersion, query.IdentityVersion)
	}
	return nil
}

func validGraphQuery(query GraphQuery) bool {
	if query.Version != GraphQueryContractVersion || query.Operation != GraphOperationTraverseClaims {
		return false
	}
	if !validGraphProjectionVersion(query.ProjectionVersion) || query.IdentityVersion != GraphBindingContractVersion {
		return false
	}
	if len(query.StartResourceIDs) == 0 || len(query.StartResourceIDs) > MaxGraphStartResources {
		return false
	}
	uniqueStarts := make(map[ResourceID]struct{}, len(query.StartResourceIDs))
	for _, resourceID := range query.StartResourceIDs {
		if resourceID.Validate() != nil {
			return false
		}
		uniqueStarts[resourceID] = struct{}{}
	}
	if len(query.PredicateSources) == 0 || len(query.PredicateSources) > len(supportedClaimPredicateSourceKeys) {
		return false
	}
	for _, sourceKey := range query.PredicateSources {
		if !isSupportedClaimPredicateSourceKey(sourceKey) {
			return false
		}
	}
	if len(query.ResourceKinds) == 0 || len(query.ResourceKinds) > len(supportedGraphResourceKinds) {
		return false
	}
	for _, kind := range query.ResourceKinds {
		if !isSupportedGraphResourceKind(kind) {
			return false
		}
	}
	if query.Direction != TraversalOutbound && query.Direction != TraversalInbound && query.Direction != TraversalBoth {
		return false
	}
	if len(query.Fields) > MaxGraphRequestedFields {
		return false
	}
	for _, field := range query.Fields {
		if !isSupportedGraphField(field) {
			return false
		}
	}
	if len(query.Filters) > MaxGraphFilters {
		return false
	}
	seenFilters := make(map[GraphFilterKind]struct{}, len(query.Filters))
	for _, filter := range query.Filters {
		if !validGraphFilter(filter, false) {
			return false
		}
		if _, duplicate := seenFilters[filter.Kind]; duplicate {
			return false
		}
		seenFilters[filter.Kind] = struct{}{}
	}
	if len(query.Order) > MaxGraphOrderClauses {
		return false
	}
	seenSortKeys := make(map[GraphSortKey]struct{}, len(query.Order))
	seenSortPriorities := make(map[int]struct{}, len(query.Order))
	for _, order := range query.Order {
		if !validGraphOrder(order) {
			return false
		}
		if _, duplicate := seenSortKeys[order.Key]; duplicate {
			return false
		}
		seenSortKeys[order.Key] = struct{}{}
		if _, duplicate := seenSortPriorities[order.Priority]; duplicate {
			return false
		}
		seenSortPriorities[order.Priority] = struct{}{}
	}
	return query.Limits.valid(len(uniqueStarts))
}

func (query *GraphQuery) UnmarshalJSON(data []byte) error {
	type graphQueryWire GraphQuery
	var decoded graphQueryWire
	if err := decodeStrictJSON(data, &decoded); err != nil {
		return newInvalidGraphPlanError("", 0)
	}
	candidate := GraphQuery(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*query = candidate
	return nil
}

type TraversalPlan struct {
	Version                      int                 `json:"version"`
	PredicateAllowlistVersion    int                 `json:"predicate_allowlist_version"`
	ResourceKindAllowlistVersion int                 `json:"resource_kind_allowlist_version"`
	ProjectionVersion            string              `json:"projection_version"`
	IdentityVersion              int                 `json:"identity_version"`
	StartResourceIDs             []ResourceID        `json:"start_resource_ids"`
	PredicateKeys                []ClaimPredicateKey `json:"predicate_keys"`
	ResourceKinds                []GraphResourceKind `json:"resource_kinds"`
	Direction                    TraversalDirection  `json:"direction"`
	Fields                       []GraphField        `json:"fields"`
	Filters                      []GraphFilter       `json:"filters,omitempty"`
	Order                        []GraphOrder        `json:"order"`
	Limits                       TraversalLimits     `json:"limits"`
}

func (plan TraversalPlan) Validate() error {
	if !validTraversalPlan(plan) {
		return newInvalidGraphPlanError(plan.ProjectionVersion, plan.IdentityVersion)
	}
	return nil
}

func validTraversalPlan(plan TraversalPlan) bool {
	if plan.Version != GraphQueryContractVersion ||
		plan.PredicateAllowlistVersion != ClaimPredicateAllowlistVersion ||
		plan.ResourceKindAllowlistVersion != GraphResourceKindAllowlistVersion {
		return false
	}
	if !validGraphProjectionVersion(plan.ProjectionVersion) || plan.IdentityVersion != GraphBindingContractVersion {
		return false
	}
	if len(plan.StartResourceIDs) == 0 || len(plan.StartResourceIDs) > MaxGraphStartResources ||
		!isStrictlySortedStrings(plan.StartResourceIDs) {
		return false
	}
	for _, resourceID := range plan.StartResourceIDs {
		if resourceID.Validate() != nil {
			return false
		}
	}
	if len(plan.PredicateKeys) == 0 || len(plan.PredicateKeys) > len(supportedClaimPredicateSourceKeys) ||
		!isStrictlySortedStrings(plan.PredicateKeys) {
		return false
	}
	for _, predicateKey := range plan.PredicateKeys {
		if predicateKey.Validate() != nil {
			return false
		}
	}
	if len(plan.ResourceKinds) == 0 || len(plan.ResourceKinds) > len(supportedGraphResourceKinds) ||
		!isStrictlySortedStrings(plan.ResourceKinds) {
		return false
	}
	for _, kind := range plan.ResourceKinds {
		if !isSupportedGraphResourceKind(kind) {
			return false
		}
	}
	if plan.Direction != TraversalOutbound && plan.Direction != TraversalInbound && plan.Direction != TraversalBoth {
		return false
	}
	if len(plan.Fields) == 0 || len(plan.Fields) > MaxGraphRequestedFields ||
		!isStrictlySortedStrings(plan.Fields) {
		return false
	}
	for _, field := range plan.Fields {
		if !isSupportedGraphField(field) {
			return false
		}
	}
	for _, required := range requiredTraversalFields {
		if !containsSortedGraphField(plan.Fields, required) {
			return false
		}
	}
	if len(plan.Filters) > MaxGraphFilters || len(plan.Order) > MaxGraphOrderClauses ||
		!validNormalizedFilters(plan.Filters) || !validNormalizedOrder(plan.Order) {
		return false
	}
	return plan.Limits.valid(len(plan.StartResourceIDs))
}

func (plan *TraversalPlan) UnmarshalJSON(data []byte) error {
	type traversalPlanWire TraversalPlan
	var decoded traversalPlanWire
	if err := decodeStrictJSON(data, &decoded); err != nil {
		return newInvalidGraphPlanError("", 0)
	}
	candidate := TraversalPlan(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*plan = candidate
	return nil
}

type GraphOperationTemplate string

const GraphOperationTemplateClaimTraversalV1 GraphOperationTemplate = "claim_traversal_v1"

type GraphOperationDescriptor struct {
	Version    int                    `json:"version"`
	Template   GraphOperationTemplate `json:"template"`
	Parameters TraversalPlan          `json:"parameters"`
}

func (descriptor GraphOperationDescriptor) Validate() error {
	if descriptor.Version != GraphQueryContractVersion ||
		descriptor.Template != GraphOperationTemplateClaimTraversalV1 {
		return newInvalidGraphPlanError(
			descriptor.Parameters.ProjectionVersion,
			descriptor.Parameters.IdentityVersion,
		)
	}
	return descriptor.Parameters.Validate()
}

func (descriptor *GraphOperationDescriptor) UnmarshalJSON(data []byte) error {
	type graphOperationDescriptorWire GraphOperationDescriptor
	var decoded graphOperationDescriptorWire
	if err := decodeStrictJSON(data, &decoded); err != nil {
		return newInvalidGraphPlanError("", 0)
	}
	candidate := GraphOperationDescriptor(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*descriptor = candidate
	return nil
}

func CompileGraphQuery(query GraphQuery) (GraphOperationDescriptor, error) {
	if err := query.Validate(); err != nil {
		return GraphOperationDescriptor{}, err
	}

	plan := TraversalPlan{
		Version:                      GraphQueryContractVersion,
		PredicateAllowlistVersion:    ClaimPredicateAllowlistVersion,
		ResourceKindAllowlistVersion: GraphResourceKindAllowlistVersion,
		ProjectionVersion:            query.ProjectionVersion,
		IdentityVersion:              query.IdentityVersion,
		StartResourceIDs:             sortedUniqueStrings(query.StartResourceIDs),
		ResourceKinds:                sortedUniqueStrings(query.ResourceKinds),
		Direction:                    query.Direction,
		Fields:                       normalizeGraphFields(query.Fields),
		Filters:                      normalizeGraphFilters(query.Filters),
		Order:                        normalizeGraphOrder(query.Order),
		Limits:                       query.Limits,
	}
	for _, sourceKey := range sortedUniqueStrings(query.PredicateSources) {
		plan.PredicateKeys = append(plan.PredicateKeys, claimPredicateKeyForSource(string(sourceKey)))
	}
	sort.Slice(plan.PredicateKeys, func(i, j int) bool { return plan.PredicateKeys[i] < plan.PredicateKeys[j] })

	descriptor := GraphOperationDescriptor{
		Version:    GraphQueryContractVersion,
		Template:   GraphOperationTemplateClaimTraversalV1,
		Parameters: plan,
	}
	if err := descriptor.Validate(); err != nil {
		return GraphOperationDescriptor{}, err
	}
	return descriptor, nil
}

var (
	ErrInvalidGraphPlan  = errors.New("invalid graph plan")
	ErrGraphPlanNotFound = errors.New("graph plan not found")
)

type GraphPlanErrorCategory string

const (
	GraphPlanErrorInvalidPlan GraphPlanErrorCategory = "invalid_plan"
	GraphPlanErrorNotFound    GraphPlanErrorCategory = "not_found"
)

type GraphPlanVersionMetadata struct {
	ContractVersion              int    `json:"contract_version"`
	PredicateAllowlistVersion    int    `json:"predicate_allowlist_version"`
	ResourceKindAllowlistVersion int    `json:"resource_kind_allowlist_version"`
	ProjectionVersion            string `json:"projection_version,omitempty"`
	IdentityVersion              int    `json:"identity_version"`
}

type GraphPlanError struct {
	Category GraphPlanErrorCategory   `json:"category"`
	Versions GraphPlanVersionMetadata `json:"versions"`
}

func (err *GraphPlanError) Error() string {
	if err != nil && err.Category == GraphPlanErrorNotFound {
		return ErrGraphPlanNotFound.Error()
	}
	return ErrInvalidGraphPlan.Error()
}

func (err *GraphPlanError) Unwrap() error {
	if err != nil && err.Category == GraphPlanErrorNotFound {
		return ErrGraphPlanNotFound
	}
	return ErrInvalidGraphPlan
}

func NewGraphPlanNotFoundError(projectionVersion string, identityVersion int) *GraphPlanError {
	return &GraphPlanError{
		Category: GraphPlanErrorNotFound,
		Versions: graphPlanVersionMetadata(projectionVersion, identityVersion),
	}
}

func newInvalidGraphPlanError(projectionVersion string, identityVersion int) *GraphPlanError {
	return &GraphPlanError{
		Category: GraphPlanErrorInvalidPlan,
		Versions: graphPlanVersionMetadata(projectionVersion, identityVersion),
	}
}

func graphPlanVersionMetadata(projectionVersion string, identityVersion int) GraphPlanVersionMetadata {
	metadata := GraphPlanVersionMetadata{
		ContractVersion:              GraphQueryContractVersion,
		PredicateAllowlistVersion:    ClaimPredicateAllowlistVersion,
		ResourceKindAllowlistVersion: GraphResourceKindAllowlistVersion,
	}
	if validGraphProjectionVersion(projectionVersion) {
		metadata.ProjectionVersion = projectionVersion
	}
	if identityVersion == GraphBindingContractVersion {
		metadata.IdentityVersion = identityVersion
	}
	return metadata
}

func validGraphProjectionVersion(value string) bool {
	return validateProjectionID(value) == nil
}

func normalizeGraphFields(fields []GraphField) []GraphField {
	combined := append([]GraphField(nil), requiredTraversalFields...)
	combined = append(combined, fields...)
	return sortedUniqueStrings(combined)
}

func normalizeGraphFilters(filters []GraphFilter) []GraphFilter {
	normalized := make([]GraphFilter, len(filters))
	for index, filter := range filters {
		normalized[index] = filter
		normalized[index].ResourceIDs = sortedUniqueStrings(filter.ResourceIDs)
		normalized[index].Derivations = sortedUniqueStrings(filter.Derivations)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Kind < normalized[j].Kind })
	return normalized
}

func validNormalizedFilters(filters []GraphFilter) bool {
	for index, filter := range filters {
		if !validGraphFilter(filter, true) {
			return false
		}
		if index > 0 && filters[index-1].Kind >= filter.Kind {
			return false
		}
	}
	return true
}

func normalizeGraphOrder(order []GraphOrder) []GraphOrder {
	if len(order) == 0 {
		order = []GraphOrder{
			{Key: GraphSortPredicateKey, Direction: GraphSortAscending, Priority: 0},
			{Key: GraphSortObjectID, Direction: GraphSortAscending, Priority: 1},
			{Key: GraphSortClaimID, Direction: GraphSortAscending, Priority: 2},
		}
	} else {
		order = append([]GraphOrder(nil), order...)
		claimIDPresent := false
		maxPriority := -1
		for _, item := range order {
			if item.Priority > maxPriority {
				maxPriority = item.Priority
			}
			if item.Key == GraphSortClaimID {
				claimIDPresent = true
				break
			}
		}
		if !claimIDPresent {
			order = append(order, GraphOrder{
				Key: GraphSortClaimID, Direction: GraphSortAscending, Priority: maxPriority + 1,
			})
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].Priority != order[j].Priority {
			return order[i].Priority < order[j].Priority
		}
		return order[i].Key < order[j].Key
	})
	for index := range order {
		order[index].Priority = index
	}
	return order
}

func validNormalizedOrder(order []GraphOrder) bool {
	if len(order) == 0 {
		return false
	}
	claimIDPresent := false
	seenKeys := make(map[GraphSortKey]struct{}, len(order))
	for index, item := range order {
		if !validGraphOrder(item) {
			return false
		}
		if item.Priority != index {
			return false
		}
		if _, duplicate := seenKeys[item.Key]; duplicate {
			return false
		}
		seenKeys[item.Key] = struct{}{}
		if item.Key == GraphSortClaimID {
			claimIDPresent = true
		}
	}
	return claimIDPresent
}

func containsSortedGraphField(fields []GraphField, target GraphField) bool {
	index := sort.Search(len(fields), func(index int) bool { return fields[index] >= target })
	return index < len(fields) && fields[index] == target
}

func sortedUniqueStrings[T ~string](values []T) []T {
	if len(values) == 0 {
		return nil
	}
	normalized := append([]T(nil), values...)
	sort.Slice(normalized, func(i, j int) bool { return normalized[i] < normalized[j] })
	writeIndex := 1
	for readIndex := 1; readIndex < len(normalized); readIndex++ {
		if normalized[readIndex] == normalized[writeIndex-1] {
			continue
		}
		normalized[writeIndex] = normalized[readIndex]
		writeIndex++
	}
	return normalized[:writeIndex]
}

func isStrictlySortedStrings[T ~string](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
