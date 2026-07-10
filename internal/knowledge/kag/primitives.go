package kag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/zzqDeco/knote/internal/protocol"
)

const ErrorCodeUnsupportedPrimitive = "unsupported_primitive"

var ErrUnsupportedPrimitive = errors.New("KAG primitive is unsupported")

// PrimitiveBackend is the controlled KAG boundary used by authorized retrieval.
// It deliberately excludes the opaque solver-backed Query and Explain methods.
type PrimitiveBackend interface {
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

type RetrieveRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

func (r RetrieveRequest) Validate() error {
	if strings.TrimSpace(r.Query) == "" {
		return fmt.Errorf("query is required")
	}
	return validatePrimitiveLimit(r.Limit)
}

type RetrieveResult struct {
	Mode       string            `json:"mode"`
	Candidates []CandidateHandle `json:"candidates"`
}

func (r RetrieveResult) ValidateFor(req RetrieveRequest) error {
	if strings.TrimSpace(r.Mode) == "" {
		return fmt.Errorf("retrieve mode is required")
	}
	return validateCandidates(r.Candidates, req.Limit)
}

type ExpandRequest struct {
	Frontier []CandidateHandle `json:"frontier"`
	Limit    int               `json:"limit"`
}

func (r ExpandRequest) Validate() error {
	if len(r.Frontier) == 0 {
		return fmt.Errorf("authorized frontier is required")
	}
	if err := validatePrimitiveLimit(r.Limit); err != nil {
		return err
	}
	return validateCandidates(r.Frontier, len(r.Frontier))
}

type ExpansionHandle struct {
	FromResourceID protocol.ResourceID `json:"from_resource_id"`
	ToResourceID   protocol.ResourceID `json:"to_resource_id"`
	Hop            int                 `json:"hop"`
}

func (h ExpansionHandle) Validate() error {
	if err := h.FromResourceID.Validate(); err != nil {
		return fmt.Errorf("expansion source: %w", err)
	}
	if err := h.ToResourceID.Validate(); err != nil {
		return fmt.Errorf("expansion target: %w", err)
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
	if strings.TrimSpace(r.Mode) == "" {
		return fmt.Errorf("expand mode is required")
	}
	if err := validateCandidates(r.Candidates, req.Limit); err != nil {
		return err
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
		key := fmt.Sprintf("%s\x00%d\x00%s", expansion.FromResourceID, expansion.Hop, expansion.ToResourceID)
		if _, duplicate := seenEdges[key]; duplicate {
			return fmt.Errorf("duplicate expansion %s", key)
		}
		seenEdges[key] = struct{}{}
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
	if protocol.NewContentDigest(e.Content) != e.Resource.ContentDigest {
		return fmt.Errorf("authorized evidence content does not match the resource handle")
	}
	if strings.TrimSpace(e.CitationHandle) == "" {
		return fmt.Errorf("citation_handle is required")
	}
	return nil
}

type GenerateRequest struct {
	Question string               `json:"question"`
	Evidence []AuthorizedEvidence `json:"evidence"`
}

func (r GenerateRequest) Validate() error {
	if strings.TrimSpace(r.Question) == "" {
		return fmt.Errorf("question is required")
	}
	if len(r.Evidence) == 0 {
		return fmt.Errorf("authorized evidence is required")
	}
	seen := make(map[protocol.ResourceID]struct{}, len(r.Evidence))
	seenCitations := make(map[string]struct{}, len(r.Evidence))
	for index, evidence := range r.Evidence {
		if err := evidence.Validate(); err != nil {
			return fmt.Errorf("evidence %d: %w", index, err)
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
	return nil
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
	if strings.TrimSpace(r.Mode) == "" {
		return fmt.Errorf("generate mode is required")
	}
	if strings.TrimSpace(r.Answer) == "" {
		return fmt.Errorf("generated answer is required")
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

func (c Client) Retrieve(ctx context.Context, req RetrieveRequest) (RetrieveResult, error) {
	if err := req.Validate(); err != nil {
		return RetrieveResult{}, err
	}
	response, err := c.call(ctx, "kag.retrieve", c.params(map[string]any{"query": req.Query, "limit": req.Limit}))
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

func decodePrimitive[T any](response Response) (T, error) {
	var value T
	data, err := json.Marshal(response.Data)
	if err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	return value, nil
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
	return left.ToResourceID < right.ToResourceID
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

var _ PrimitiveBackend = Client{}
