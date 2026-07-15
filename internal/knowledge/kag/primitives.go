package kag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	ErrorCodeUnsupportedPrimitive     = "unsupported_primitive"
	ErrorCodeInvalidGraphBinding      = "invalid_graph_binding"
	ErrorCodePrimitiveUnavailable     = "primitive_unavailable"
	ErrorCodeInvalidPrimitiveResponse = "invalid_primitive_response"
	maxPrimitiveItems                 = 100
	maxPrimitiveTextBytes             = 1 << 20
)

var (
	ErrUnsupportedPrimitive     = errors.New("KAG primitive is unsupported")
	ErrInvalidGraphBinding      = errors.New("KAG graph binding is invalid")
	ErrPrimitiveUnavailable     = errors.New("KAG permissioned primitive provider is unavailable")
	ErrInvalidPrimitiveResponse = errors.New("KAG permissioned primitive response is invalid")
)

// PrimitiveBackend is the controlled KAG boundary used by authorized retrieval.
// It deliberately excludes the opaque solver-backed Query and Explain methods.
type PrimitiveBackend interface {
	Discover(context.Context, DiscoverRequest) (DiscoverResult, error)
	Retrieve(context.Context, RetrieveRequest) (RetrieveResult, error)
	Expand(context.Context, ExpandRequest) (ExpandResult, error)
	Generate(context.Context, GenerateRequest) (GenerateResult, error)
}

type CandidateHandle struct {
	Resource protocol.ResourceHandle `json:"resource"`
	Score    float64                 `json:"score"`
}

func (h CandidateHandle) Validate() error {
	if err := h.Resource.Validate(); err != nil {
		return err
	}
	if math.IsNaN(h.Score) || math.IsInf(h.Score, 0) {
		return fmt.Errorf("candidate score must be finite")
	}
	if h.Score < 0 || h.Score > 1 {
		return fmt.Errorf("candidate score must be between 0 and 1")
	}
	return nil
}

// DiscoverRequest asks the trusted adapter for a complete, body-free catalog
// of graph handles before any relevance provider is invoked.
type DiscoverRequest struct {
	Authorization protocol.AuthorizationContext `json:"authorization"`
	ResourceTypes []protocol.ResourceType       `json:"resource_types"`
	Limit         int                           `json:"limit"`
}

func (r DiscoverRequest) Validate() error {
	if err := r.Authorization.Validate(); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if r.Limit != maxPrimitiveItems {
		return fmt.Errorf("limit must equal the full discovery scan limit of %d", maxPrimitiveItems)
	}
	if len(r.ResourceTypes) == 0 || len(r.ResourceTypes) > 5 {
		return fmt.Errorf("resource_types must contain between 1 and 5 values")
	}
	for index, resourceType := range r.ResourceTypes {
		switch resourceType {
		case protocol.ResourceDocument, protocol.ResourceChunk, protocol.ResourceEntity,
			protocol.ResourceClaim, protocol.ResourceDerivedArtifact:
		default:
			return fmt.Errorf("resource_types[%d] is unsupported", index)
		}
		if index > 0 && resourceType <= r.ResourceTypes[index-1] {
			return fmt.Errorf("resource_types must be strictly sorted and unique")
		}
	}
	return nil
}

type DiscoverResult struct {
	Mode      string                    `json:"mode"`
	Resources []protocol.ResourceHandle `json:"resources"`
	Complete  bool                      `json:"complete"`
}

func (r DiscoverResult) ValidateFor(req DiscoverRequest) error {
	if err := req.Validate(); err != nil {
		return fmt.Errorf("discover request: %w", err)
	}
	if err := validatePrimitiveMode(r.Mode); err != nil {
		return fmt.Errorf("discover mode: %w", err)
	}
	if len(r.Resources) > req.Limit {
		return fmt.Errorf("discovered resource count exceeds requested limit")
	}
	if !r.Complete && len(r.Resources) != req.Limit {
		return fmt.Errorf("incomplete discovery must fill the requested limit")
	}
	projection := ""
	for index, resource := range r.Resources {
		if err := validateResourceForAuthorization(resource, req.Authorization); err != nil {
			return fmt.Errorf("resource %d: %w", index, err)
		}
		if !containsResourceType(req.ResourceTypes, resource.Type) {
			return fmt.Errorf("resource %d has a type outside the discovery request", index)
		}
		if projection == "" {
			projection = resource.Versions.Projection
		} else if resource.Versions.Projection != projection {
			return fmt.Errorf("resource %d projection does not match the discovered resource set", index)
		}
		if index > 0 && resource.ResourceID <= r.Resources[index-1].ResourceID {
			return fmt.Errorf("discovered resources must be strictly sorted and unique")
		}
	}
	return nil
}

type RetrieveRequest struct {
	Authorization    protocol.AuthorizationContext `json:"authorization"`
	Query            string                        `json:"query"`
	AllowedResources []protocol.ResourceHandle     `json:"allowed_resources"`
	Limit            int                           `json:"limit"`
}

func (r RetrieveRequest) Validate() error {
	if err := r.Authorization.Validate(); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if strings.TrimSpace(r.Query) == "" {
		return fmt.Errorf("query is required")
	}
	if len(r.Query) > maxPrimitiveTextBytes {
		return fmt.Errorf("query exceeds the primitive text limit")
	}
	if err := validatePrimitiveLimit(r.Limit); err != nil {
		return err
	}
	if len(r.AllowedResources) == 0 || len(r.AllowedResources) > maxPrimitiveItems {
		return fmt.Errorf("allowed_resources must contain between 1 and %d handles", maxPrimitiveItems)
	}
	projection := ""
	for index, resource := range r.AllowedResources {
		if err := validateResourceForAuthorization(resource, r.Authorization); err != nil {
			return fmt.Errorf("allowed resource %d: %w", index, err)
		}
		if projection == "" {
			projection = resource.Versions.Projection
		} else if resource.Versions.Projection != projection {
			return fmt.Errorf("allowed resource %d projection does not match the allowed resource set", index)
		}
		if index > 0 && resource.ResourceID <= r.AllowedResources[index-1].ResourceID {
			return fmt.Errorf("allowed_resources must be strictly sorted and unique")
		}
	}
	return nil
}

type RetrieveResult struct {
	Mode       string            `json:"mode"`
	Candidates []CandidateHandle `json:"candidates"`
}

func (r RetrieveResult) ValidateFor(req RetrieveRequest) error {
	if err := req.Validate(); err != nil {
		return fmt.Errorf("retrieve request: %w", err)
	}
	if err := validatePrimitiveMode(r.Mode); err != nil {
		return fmt.Errorf("retrieve mode: %w", err)
	}
	if err := validateCandidatesForAuthorization(r.Candidates, req.Limit, req.Authorization); err != nil {
		return err
	}
	allowed := make(map[protocol.ResourceID]protocol.ResourceHandle, len(req.AllowedResources))
	for _, resource := range req.AllowedResources {
		allowed[resource.ResourceID] = resource
	}
	for index, candidate := range r.Candidates {
		resource, ok := allowed[candidate.Resource.ResourceID]
		if !ok || resource != candidate.Resource {
			return fmt.Errorf("candidate %d is outside the exact authorized retrieval scope", index)
		}
	}
	return nil
}

type ExpandPhase string

const (
	ExpandPhaseEntityToClaim ExpandPhase = "entity_to_claim"
	ExpandPhaseClaimToObject ExpandPhase = "claim_to_object"
)

func (p ExpandPhase) Validate() error {
	switch p {
	case ExpandPhaseEntityToClaim, ExpandPhaseClaimToObject:
		return nil
	default:
		return fmt.Errorf("unsupported expand phase")
	}
}

type ExpandRequest struct {
	Authorization protocol.AuthorizationContext     `json:"authorization"`
	Operation     protocol.GraphOperationDescriptor `json:"operation"`
	Phase         ExpandPhase                       `json:"phase"`
	Frontier      []CandidateHandle                 `json:"frontier"`
	Limit         int                               `json:"limit"`
}

func (r ExpandRequest) Validate() error {
	if err := r.Authorization.Validate(); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if err := r.Operation.Validate(); err != nil {
		return fmt.Errorf("operation: %w", err)
	}
	if err := r.Phase.Validate(); err != nil {
		return err
	}
	plan := r.Operation.Parameters
	if plan.Direction != protocol.TraversalOutbound {
		return fmt.Errorf("expand operation direction is unsupported")
	}
	if plan.IdentityVersion != protocol.GraphBindingContractVersion {
		return fmt.Errorf("expand operation identity version is unsupported")
	}
	if plan.Limits.MaxDepth < 1 {
		return fmt.Errorf("expand operation max depth must be positive")
	}
	if plan.Limits.MaxFrontierWidth > maxPrimitiveItems {
		return fmt.Errorf("expand operation max frontier width exceeds provider limit")
	}
	if plan.Limits.MaxCandidatesPerHop > maxPrimitiveItems {
		return fmt.Errorf("expand operation max candidates per hop exceeds provider limit")
	}
	for _, kind := range plan.ResourceKinds {
		if kind != protocol.GraphResourceEntity && kind != protocol.GraphResourceClaim {
			return fmt.Errorf("expand operation resource kind is unsupported")
		}
	}
	if len(r.Frontier) == 0 {
		return fmt.Errorf("authorized frontier is required")
	}
	if len(r.Frontier) > plan.Limits.MaxFrontierWidth {
		return fmt.Errorf("authorized frontier exceeds the operation max frontier width")
	}
	if r.Limit != maxPrimitiveItems {
		return fmt.Errorf("expand limit must equal the full provider scan limit of %d", maxPrimitiveItems)
	}
	if err := validateCandidatesForAuthorization(r.Frontier, len(r.Frontier), r.Authorization); err != nil {
		return err
	}
	for index, candidate := range r.Frontier {
		if candidate.Resource.Versions.Projection != plan.ProjectionVersion {
			return fmt.Errorf("frontier candidate %d does not match the operation projection", index)
		}
		expectedType := protocol.ResourceEntity
		if r.Phase == ExpandPhaseClaimToObject {
			expectedType = protocol.ResourceClaim
		}
		if candidate.Resource.Type != expectedType {
			return fmt.Errorf("frontier candidate %d has an unsupported resource kind for phase", index)
		}
	}
	return nil
}

type ExpansionHandle struct {
	FromResourceID  protocol.ResourceID        `json:"from_resource_id"`
	ToResourceID    protocol.ResourceID        `json:"to_resource_id"`
	ClaimResourceID protocol.ResourceID        `json:"claim_resource_id"`
	PredicateKey    protocol.ClaimPredicateKey `json:"predicate_key"`
	Hop             int                        `json:"hop"`
}

func (h ExpansionHandle) Validate() error {
	if err := h.FromResourceID.Validate(); err != nil {
		return fmt.Errorf("expansion source: %w", err)
	}
	if err := h.ToResourceID.Validate(); err != nil {
		return fmt.Errorf("expansion target: %w", err)
	}
	if err := h.ClaimResourceID.Validate(); err != nil {
		return fmt.Errorf("expansion claim: %w", err)
	}
	if err := h.PredicateKey.Validate(); err != nil {
		return fmt.Errorf("expansion predicate: %w", err)
	}
	if h.FromResourceID == h.ToResourceID {
		return fmt.Errorf("expansion source and target must differ")
	}
	if h.Hop < 1 {
		return fmt.Errorf("expansion hop must be positive")
	}
	return nil
}

type ExpandResult struct {
	Mode       string            `json:"mode"`
	Candidates []CandidateHandle `json:"candidates"`
	Expansions []ExpansionHandle `json:"expansions"`
}

func (r ExpandResult) ValidateFor(req ExpandRequest) error {
	if err := req.Validate(); err != nil {
		return fmt.Errorf("expand request: %w", err)
	}
	if err := validatePrimitiveMode(r.Mode); err != nil {
		return fmt.Errorf("expand mode: %w", err)
	}
	if err := validateCandidatesForAuthorization(r.Candidates, req.Limit, req.Authorization); err != nil {
		return err
	}
	for index, candidate := range r.Candidates {
		if candidate.Resource.Versions.Projection != req.Operation.Parameters.ProjectionVersion {
			return fmt.Errorf("candidate %d does not match the operation projection", index)
		}
		if req.Phase == ExpandPhaseEntityToClaim {
			if candidate.Resource.Type != protocol.ResourceClaim {
				return fmt.Errorf("candidate %d is not a Claim for entity_to_claim", index)
			}
		} else {
			if candidate.Resource.Type != protocol.ResourceEntity ||
				!containsGraphResourceKind(req.Operation.Parameters.ResourceKinds, protocol.GraphResourceEntity) {
				return fmt.Errorf("candidate %d has an unsupported object resource kind", index)
			}
		}
	}
	frontier := make(map[protocol.ResourceID]protocol.ResourceHandle, len(req.Frontier))
	for _, candidate := range req.Frontier {
		frontier[candidate.Resource.ResourceID] = candidate.Resource
	}
	targets := make(map[protocol.ResourceID]protocol.ResourceHandle, len(r.Candidates))
	for _, candidate := range r.Candidates {
		targets[candidate.Resource.ResourceID] = candidate.Resource
	}
	seenEdges := make(map[string]struct{}, len(r.Expansions))
	seenClaims := make(map[protocol.ResourceID]ExpansionHandle, len(r.Expansions))
	referencedTargets := make(map[protocol.ResourceID]struct{}, len(r.Expansions))
	for index, expansion := range r.Expansions {
		if err := expansion.Validate(); err != nil {
			return fmt.Errorf("expansion %d: %w", index, err)
		}
		if _, ok := frontier[expansion.FromResourceID]; !ok {
			return fmt.Errorf("expansion source %s was not in the authorized frontier", expansion.FromResourceID)
		}
		if _, ok := targets[expansion.ToResourceID]; !ok {
			return fmt.Errorf("expansion target %s has no candidate handle", expansion.ToResourceID)
		}
		if expansion.Hop != 1 {
			return fmt.Errorf("expansion %d is not one primitive hop", index)
		}
		if !containsClaimPredicateKey(req.Operation.Parameters.PredicateKeys, expansion.PredicateKey) {
			return fmt.Errorf("expansion %d predicate is outside the operation allowlist", index)
		}
		source := frontier[expansion.FromResourceID]
		target := targets[expansion.ToResourceID]
		if target.Versions.Projection != source.Versions.Projection {
			return fmt.Errorf(
				"expansion target %s projection %q does not match authorized frontier source %s projection %q",
				expansion.ToResourceID,
				target.Versions.Projection,
				expansion.FromResourceID,
				source.Versions.Projection,
			)
		}
		if req.Phase == ExpandPhaseEntityToClaim {
			if source.Type != protocol.ResourceEntity || target.Type != protocol.ResourceClaim ||
				expansion.ClaimResourceID != expansion.ToResourceID {
				return fmt.Errorf("expansion %d has an unsupported entity_to_claim edge shape", index)
			}
		} else if source.Type != protocol.ResourceClaim || target.Type != protocol.ResourceEntity ||
			expansion.ClaimResourceID != expansion.FromResourceID {
			return fmt.Errorf("expansion %d has an unsupported claim_to_object edge shape", index)
		}
		key := fmt.Sprintf(
			"%s\x00%d\x00%s\x00%s\x00%s",
			expansion.FromResourceID,
			expansion.Hop,
			expansion.ToResourceID,
			expansion.ClaimResourceID,
			expansion.PredicateKey,
		)
		if _, duplicate := seenEdges[key]; duplicate {
			return fmt.Errorf("duplicate expansion %s", key)
		}
		seenEdges[key] = struct{}{}
		if previous, duplicate := seenClaims[expansion.ClaimResourceID]; duplicate {
			return fmt.Errorf(
				"claim %s is bound to multiple expansion edges (%s and %s)",
				expansion.ClaimResourceID,
				previous.ToResourceID,
				expansion.ToResourceID,
			)
		}
		seenClaims[expansion.ClaimResourceID] = expansion
		referencedTargets[expansion.ToResourceID] = struct{}{}
		if index > 0 && expansionLess(expansion, r.Expansions[index-1]) {
			return fmt.Errorf("expansions are not deterministically sorted")
		}
	}
	for resourceID := range targets {
		if _, ok := referencedTargets[resourceID]; !ok {
			return fmt.Errorf("candidate %s is not bound to an expansion", resourceID)
		}
	}
	return nil
}

type AuthorizedEvidence struct {
	Resource       protocol.ResourceHandle `json:"resource"`
	Content        string                  `json:"content"`
	CitationHandle string                  `json:"citation_handle"`
}

func (e AuthorizedEvidence) Validate() error {
	if err := e.Resource.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(e.Content) == "" {
		return fmt.Errorf("authorized evidence content is required")
	}
	if len(e.Content) > maxPrimitiveTextBytes {
		return fmt.Errorf("authorized evidence content exceeds the primitive text limit")
	}
	if protocol.NewContentDigest(e.Content) != e.Resource.ContentDigest {
		return fmt.Errorf("authorized evidence content does not match the resource handle")
	}
	if strings.TrimSpace(e.CitationHandle) == "" {
		return fmt.Errorf("citation_handle is required")
	}
	return nil
}

// GeneratePathClaimBinding binds one entity -> Claim -> entity segment in a
// body-free generator path.
type GeneratePathClaimBinding struct {
	ParentResourceID protocol.ResourceID        `json:"parent_resource_id"`
	ClaimResourceID  protocol.ResourceID        `json:"claim_resource_id"`
	ObjectResourceID protocol.ResourceID        `json:"object_resource_id"`
	PredicateKey     protocol.ClaimPredicateKey `json:"predicate_key"`
}

func (b GeneratePathClaimBinding) Validate() error {
	if err := b.ParentResourceID.Validate(); err != nil {
		return fmt.Errorf("parent_resource_id: %w", err)
	}
	if err := b.ClaimResourceID.Validate(); err != nil {
		return fmt.Errorf("claim_resource_id: %w", err)
	}
	if err := b.ObjectResourceID.Validate(); err != nil {
		return fmt.Errorf("object_resource_id: %w", err)
	}
	if err := b.PredicateKey.Validate(); err != nil {
		return fmt.Errorf("predicate_key: %w", err)
	}
	if b.ParentResourceID == b.ClaimResourceID ||
		b.ParentResourceID == b.ObjectResourceID ||
		b.ClaimResourceID == b.ObjectResourceID {
		return fmt.Errorf("path Claim binding resources must be distinct")
	}
	return nil
}

// GeneratePath is the complete, body-free authorized traversal path paired
// with one terminal evidence item.
type GeneratePath struct {
	Resources     []protocol.ResourceHandle  `json:"resources"`
	ClaimBindings []GeneratePathClaimBinding `json:"claim_bindings"`
}

func (p GeneratePath) Validate() error {
	if p.Resources == nil || len(p.Resources) == 0 {
		return fmt.Errorf("resources must be a non-empty list")
	}
	if len(p.Resources) > maxPrimitiveItems {
		return fmt.Errorf("resources exceed the primitive item limit")
	}
	if p.ClaimBindings == nil {
		return fmt.Errorf("claim_bindings must be a list")
	}
	if len(p.ClaimBindings) > maxPrimitiveItems {
		return fmt.Errorf("claim_bindings exceed the primitive item limit")
	}
	if len(p.Resources) != 2*len(p.ClaimBindings)+1 {
		return fmt.Errorf("path must contain complete entity/Claim/entity segments")
	}

	projection := ""
	seenResources := make(map[protocol.ResourceID]struct{}, len(p.Resources))
	for index, resource := range p.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("resource %d: %w", index, err)
		}
		expectedType := protocol.ResourceEntity
		if index%2 == 1 {
			expectedType = protocol.ResourceClaim
		}
		if resource.Type != expectedType {
			return fmt.Errorf("resource %d does not match the entity/Claim/entity path shape", index)
		}
		if projection == "" {
			projection = resource.Versions.Projection
		} else if resource.Versions.Projection != projection {
			return fmt.Errorf("resource %d projection does not match the path projection", index)
		}
		if _, duplicate := seenResources[resource.ResourceID]; duplicate {
			return fmt.Errorf("path contains duplicate resource %s", resource.ResourceID)
		}
		seenResources[resource.ResourceID] = struct{}{}
	}

	seenBindings := make(map[string]struct{}, len(p.ClaimBindings))
	for index, binding := range p.ClaimBindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("claim_binding %d: %w", index, err)
		}
		parent := p.Resources[index*2]
		claim := p.Resources[index*2+1]
		object := p.Resources[index*2+2]
		if binding.ParentResourceID != parent.ResourceID ||
			binding.ClaimResourceID != claim.ResourceID ||
			binding.ObjectResourceID != object.ResourceID {
			return fmt.Errorf("claim_binding %d does not match the resource sequence", index)
		}
		key := strings.Join([]string{
			string(binding.ParentResourceID),
			string(binding.ClaimResourceID),
			string(binding.ObjectResourceID),
			string(binding.PredicateKey),
		}, "\x00")
		if _, duplicate := seenBindings[key]; duplicate {
			return fmt.Errorf("path contains duplicate Claim binding")
		}
		seenBindings[key] = struct{}{}
	}
	return nil
}

func (p GeneratePath) Clone() GeneratePath {
	clone := p
	if p.Resources != nil {
		clone.Resources = make([]protocol.ResourceHandle, len(p.Resources))
		copy(clone.Resources, p.Resources)
	}
	if p.ClaimBindings != nil {
		clone.ClaimBindings = make([]GeneratePathClaimBinding, len(p.ClaimBindings))
		copy(clone.ClaimBindings, p.ClaimBindings)
	}
	return clone
}

type GenerateRequest struct {
	Authorization protocol.AuthorizationContext `json:"authorization"`
	Question      string                        `json:"question"`
	Evidence      []AuthorizedEvidence          `json:"evidence"`
	Paths         []GeneratePath                `json:"paths,omitempty"`
}

func (r GenerateRequest) Validate() error {
	if err := r.Authorization.Validate(); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if strings.TrimSpace(r.Question) == "" {
		return fmt.Errorf("question is required")
	}
	if len(r.Question) > maxPrimitiveTextBytes {
		return fmt.Errorf("question exceeds the primitive text limit")
	}
	if len(r.Evidence) == 0 {
		return fmt.Errorf("authorized evidence is required")
	}
	if len(r.Evidence) > maxPrimitiveItems {
		return fmt.Errorf("authorized evidence exceeds the primitive item limit")
	}
	seen := make(map[protocol.ResourceID]struct{}, len(r.Evidence))
	seenCitations := make(map[string]struct{}, len(r.Evidence))
	projection := ""
	for index, evidence := range r.Evidence {
		if err := evidence.Validate(); err != nil {
			return fmt.Errorf("evidence %d: %w", index, err)
		}
		if err := validateResourceForAuthorization(evidence.Resource, r.Authorization); err != nil {
			return fmt.Errorf("evidence %d: %w", index, err)
		}
		if projection == "" {
			projection = evidence.Resource.Versions.Projection
		} else if evidence.Resource.Versions.Projection != projection {
			return fmt.Errorf("evidence %d projection %q does not match request projection %q", index, evidence.Resource.Versions.Projection, projection)
		}
		if _, duplicate := seen[evidence.Resource.ResourceID]; duplicate {
			return fmt.Errorf("duplicate evidence resource %s", evidence.Resource.ResourceID)
		}
		seen[evidence.Resource.ResourceID] = struct{}{}
		if _, duplicate := seenCitations[evidence.CitationHandle]; duplicate {
			return fmt.Errorf("duplicate citation_handle %q", evidence.CitationHandle)
		}
		seenCitations[evidence.CitationHandle] = struct{}{}
	}
	if r.Paths == nil {
		return nil
	}
	if len(r.Paths) != len(r.Evidence) {
		return fmt.Errorf("paths must contain exactly one complete path per evidence item")
	}
	seenPaths := make(map[string]struct{}, len(r.Paths))
	for index, path := range r.Paths {
		if err := path.validateFor(r.Authorization, r.Evidence[index]); err != nil {
			return fmt.Errorf("path %d: %w", index, err)
		}
		key := generatePathKey(path)
		if _, duplicate := seenPaths[key]; duplicate {
			return fmt.Errorf("duplicate path %d", index)
		}
		seenPaths[key] = struct{}{}
	}
	return nil
}

func (r GenerateRequest) Clone() GenerateRequest {
	clone := r
	if r.Evidence != nil {
		clone.Evidence = append([]AuthorizedEvidence(nil), r.Evidence...)
	}
	if r.Paths != nil {
		clone.Paths = make([]GeneratePath, len(r.Paths))
		for index, path := range r.Paths {
			clone.Paths[index] = path.Clone()
		}
	}
	return clone
}

func (p GeneratePath) validateFor(
	authorization protocol.AuthorizationContext,
	evidence AuthorizedEvidence,
) error {
	if err := p.Validate(); err != nil {
		return err
	}
	projection := evidence.Resource.Versions.Projection
	for index, resource := range p.Resources {
		if err := validateResourceForAuthorization(resource, authorization); err != nil {
			return fmt.Errorf("resource %d: %w", index, err)
		}
		if resource.Versions.Projection != projection {
			return fmt.Errorf("resource %d does not match the evidence projection", index)
		}
	}
	if p.Resources[len(p.Resources)-1] != evidence.Resource {
		return fmt.Errorf("terminal resource does not exactly match the paired evidence")
	}
	return nil
}

func generatePathKey(path GeneratePath) string {
	parts := make([]string, 0, len(path.Resources)+len(path.ClaimBindings))
	for _, resource := range path.Resources {
		parts = append(parts, string(resource.ResourceID))
	}
	for _, binding := range path.ClaimBindings {
		parts = append(parts, strings.Join([]string{
			string(binding.ParentResourceID),
			string(binding.ClaimResourceID),
			string(binding.ObjectResourceID),
			string(binding.PredicateKey),
		}, "\x01"))
	}
	return strings.Join(parts, "\x00")
}

type CitationHandle struct {
	Handle     string              `json:"handle"`
	ResourceID protocol.ResourceID `json:"resource_id"`
}

type GenerationTrace struct {
	ResourceIDs []protocol.ResourceID `json:"resource_ids"`
	Count       int                   `json:"count"`
}

type GenerateResult struct {
	Mode                string                `json:"mode"`
	Answer              string                `json:"answer"`
	Citations           []CitationHandle      `json:"citations"`
	EvidenceResourceIDs []protocol.ResourceID `json:"evidence_resource_ids"`
	Trace               GenerationTrace       `json:"trace"`
}

func (r GenerateResult) ValidateFor(req GenerateRequest) error {
	if err := req.Validate(); err != nil {
		return fmt.Errorf("generate request: %w", err)
	}
	if err := validatePrimitiveMode(r.Mode); err != nil {
		return fmt.Errorf("generate mode: %w", err)
	}
	if strings.TrimSpace(r.Answer) == "" {
		return fmt.Errorf("generated answer is required")
	}
	if len(r.Answer) > maxPrimitiveTextBytes {
		return fmt.Errorf("generated answer exceeds the primitive text limit")
	}
	allowed := make(map[protocol.ResourceID]AuthorizedEvidence, len(req.Evidence))
	for _, evidence := range req.Evidence {
		allowed[evidence.Resource.ResourceID] = evidence
	}
	cited := make(map[protocol.ResourceID]struct{}, len(r.Citations))
	for index, citation := range r.Citations {
		evidence, ok := allowed[citation.ResourceID]
		if !ok {
			return fmt.Errorf("citation %d references evidence outside the request", index)
		}
		if citation.Handle != evidence.CitationHandle {
			return fmt.Errorf("citation %d handle does not match the requested evidence", index)
		}
		if _, duplicate := cited[citation.ResourceID]; duplicate {
			return fmt.Errorf("duplicate citation for resource %s", citation.ResourceID)
		}
		cited[citation.ResourceID] = struct{}{}
	}
	used, err := validatedResourceIDSet("evidence_resource_ids", r.EvidenceResourceIDs, allowed)
	if err != nil {
		return err
	}
	traced, err := validatedResourceIDSet("trace.resource_ids", r.Trace.ResourceIDs, allowed)
	if err != nil {
		return err
	}
	if r.Trace.Count != len(r.Trace.ResourceIDs) {
		return fmt.Errorf("trace count does not match resource_ids")
	}
	if len(used) == 0 || !sameResourceIDSet(used, traced) || !sameResourceIDSet(used, cited) {
		return fmt.Errorf("generation evidence, citations, and trace must reference the same authorized resources")
	}
	return nil
}

func (c Client) Discover(ctx context.Context, req DiscoverRequest) (DiscoverResult, error) {
	if err := req.Validate(); err != nil {
		return DiscoverResult{}, err
	}
	params, err := structParams(req)
	if err != nil {
		return DiscoverResult{}, err
	}
	response, err := c.call(ctx, "kag.discover", c.params(params))
	if err != nil {
		return DiscoverResult{}, err
	}
	result, err := decodePrimitive[DiscoverResult](response)
	if err != nil {
		return DiscoverResult{}, err
	}
	return result, result.ValidateFor(req)
}

func (c Client) Retrieve(ctx context.Context, req RetrieveRequest) (RetrieveResult, error) {
	if err := req.Validate(); err != nil {
		return RetrieveResult{}, err
	}
	params, err := structParams(req)
	if err != nil {
		return RetrieveResult{}, err
	}
	response, err := c.call(ctx, "kag.retrieve", c.params(params))
	if err != nil {
		return RetrieveResult{}, err
	}
	result, err := decodePrimitive[RetrieveResult](response)
	if err != nil {
		return RetrieveResult{}, err
	}
	return result, result.ValidateFor(req)
}

func (c Client) Expand(ctx context.Context, req ExpandRequest) (ExpandResult, error) {
	if err := req.Validate(); err != nil {
		return ExpandResult{}, err
	}
	params, err := structParams(req)
	if err != nil {
		return ExpandResult{}, err
	}
	response, err := c.call(ctx, "kag.expand", c.params(params))
	if err != nil {
		return ExpandResult{}, err
	}
	result, err := decodePrimitive[ExpandResult](response)
	if err != nil {
		return ExpandResult{}, err
	}
	return result, result.ValidateFor(req)
}

func (c Client) Generate(ctx context.Context, req GenerateRequest) (GenerateResult, error) {
	if err := req.Validate(); err != nil {
		return GenerateResult{}, err
	}
	params, err := structParams(req)
	if err != nil {
		return GenerateResult{}, err
	}
	response, err := c.call(ctx, "kag.generate", c.params(params))
	if err != nil {
		return GenerateResult{}, err
	}
	result, err := decodePrimitive[GenerateResult](response)
	if err != nil {
		return GenerateResult{}, err
	}
	return result, result.ValidateFor(req)
}

type primitiveResponse[T any] struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
	Data    T      `json:"data"`
}

func decodePrimitive[T any](response Response) (T, error) {
	var value T
	if response.Type != "result" {
		return value, fmt.Errorf("primitive response must be a result frame")
	}
	if len(response.raw) > 0 {
		var frame primitiveResponse[T]
		decoder := json.NewDecoder(bytes.NewReader(response.raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&frame); err != nil {
			return value, err
		}
		if err := requireJSONEOF(decoder); err != nil {
			return value, err
		}
		if frame.Type != "result" {
			return value, fmt.Errorf("primitive response must be a result frame")
		}
		if frame.Message != "" {
			return value, fmt.Errorf("primitive result frame contains a non-empty message")
		}
		return frame.Data, nil
	}
	if response.Code != "" || response.Message != "" || response.Error != "" {
		return value, fmt.Errorf("primitive result frame contains non-data fields")
	}
	data, err := json.Marshal(response.Data)
	if err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return value, err
	}
	return value, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("primitive response contains trailing JSON")
		}
		return err
	}
	return nil
}

func structParams(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var params map[string]any
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, err
	}
	return params, nil
}

func validateCandidates(candidates []CandidateHandle, limit int) error {
	if len(candidates) > limit {
		return fmt.Errorf("candidate count exceeds requested limit")
	}
	seen := make(map[protocol.ResourceID]struct{}, len(candidates))
	for index, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("candidate %d: %w", index, err)
		}
		resourceID := candidate.Resource.ResourceID
		if _, duplicate := seen[resourceID]; duplicate {
			return fmt.Errorf("duplicate candidate resource %s", resourceID)
		}
		seen[resourceID] = struct{}{}
		if index > 0 && candidateLess(candidate, candidates[index-1]) {
			return fmt.Errorf("candidates are not deterministically sorted")
		}
	}
	return nil
}

func validateCandidatesForAuthorization(
	candidates []CandidateHandle,
	limit int,
	authorization protocol.AuthorizationContext,
) error {
	if err := validateCandidates(candidates, limit); err != nil {
		return err
	}
	projection := ""
	for index, candidate := range candidates {
		if err := validateResourceForAuthorization(candidate.Resource, authorization); err != nil {
			return fmt.Errorf("candidate %d: %w", index, err)
		}
		if projection == "" {
			projection = candidate.Resource.Versions.Projection
		} else if candidate.Resource.Versions.Projection != projection {
			return fmt.Errorf("candidate %d projection %q does not match candidate set projection %q", index, candidate.Resource.Versions.Projection, projection)
		}
	}
	return nil
}

func validateResourceForAuthorization(
	resource protocol.ResourceHandle,
	authorization protocol.AuthorizationContext,
) error {
	if resource.TenantID != authorization.TenantID {
		return fmt.Errorf(
			"resource %s tenant %q is outside authorized tenant %q",
			resource.ResourceID,
			resource.TenantID,
			authorization.TenantID,
		)
	}
	if resource.KnowledgeBaseID != authorization.KnowledgeBaseID {
		return fmt.Errorf(
			"resource %s knowledge base %q is outside authorized knowledge base %q",
			resource.ResourceID,
			resource.KnowledgeBaseID,
			authorization.KnowledgeBaseID,
		)
	}
	return nil
}

func candidateLess(left, right CandidateHandle) bool {
	if left.Score != right.Score {
		return left.Score > right.Score
	}
	return left.Resource.ResourceID < right.Resource.ResourceID
}

func expansionLess(left, right ExpansionHandle) bool {
	if left.Hop != right.Hop {
		return left.Hop < right.Hop
	}
	if left.FromResourceID != right.FromResourceID {
		return left.FromResourceID < right.FromResourceID
	}
	if left.ToResourceID != right.ToResourceID {
		return left.ToResourceID < right.ToResourceID
	}
	if left.ClaimResourceID != right.ClaimResourceID {
		return left.ClaimResourceID < right.ClaimResourceID
	}
	return left.PredicateKey < right.PredicateKey
}

func containsGraphResourceKind(kinds []protocol.GraphResourceKind, target protocol.GraphResourceKind) bool {
	for _, kind := range kinds {
		if kind == target {
			return true
		}
	}
	return false
}

func containsClaimPredicateKey(keys []protocol.ClaimPredicateKey, target protocol.ClaimPredicateKey) bool {
	for _, key := range keys {
		if key == target {
			return true
		}
	}
	return false
}

func containsResourceType(types []protocol.ResourceType, target protocol.ResourceType) bool {
	for _, resourceType := range types {
		if resourceType == target {
			return true
		}
	}
	return false
}

func validatedResourceIDSet(
	name string,
	resourceIDs []protocol.ResourceID,
	allowed map[protocol.ResourceID]AuthorizedEvidence,
) (map[protocol.ResourceID]struct{}, error) {
	result := make(map[protocol.ResourceID]struct{}, len(resourceIDs))
	for index, resourceID := range resourceIDs {
		if err := resourceID.Validate(); err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, index, err)
		}
		if _, ok := allowed[resourceID]; !ok {
			return nil, fmt.Errorf("%s[%d] is outside the authorized request evidence", name, index)
		}
		if _, duplicate := result[resourceID]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate resource %s", name, resourceID)
		}
		result[resourceID] = struct{}{}
	}
	return result, nil
}

func sameResourceIDSet(left, right map[protocol.ResourceID]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for resourceID := range left {
		if _, ok := right[resourceID]; !ok {
			return false
		}
	}
	return true
}

func validatePrimitiveLimit(limit int) error {
	if limit < 1 || limit > 100 {
		return fmt.Errorf("limit must be between 1 and 100")
	}
	return nil
}

func validatePrimitiveMode(mode string) error {
	if strings.TrimSpace(mode) == "" {
		return fmt.Errorf("is required")
	}
	return nil
}

var _ PrimitiveBackend = Client{}
