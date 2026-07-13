package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const ProtectedContentBindingVersion = "v1"

const protectedBlockIDPrefix = "block_"

// ProtectedResourceBinding records only exact resource and authorization
// boundary handles. It deliberately contains no title, body, answer, or query.
type ProtectedResourceBinding struct {
	Resource              ResourceHandle `json:"resource"`
	AuthorizationResource ResourceHandle `json:"authorization_resource"`
}

func (b ProtectedResourceBinding) Validate() error {
	if err := b.Resource.Validate(); err != nil {
		return fmt.Errorf("protected resource: %w", err)
	}
	if err := b.AuthorizationResource.Validate(); err != nil {
		return fmt.Errorf("protected authorization resource: %w", err)
	}
	decision := AuthorizationDecision{
		Resource:              b.Resource,
		AuthorizationResource: b.AuthorizationResource,
	}
	if err := decision.validateAuthorizationBoundary(); err != nil {
		return fmt.Errorf("protected authorization boundary: %w", err)
	}
	return nil
}

func (b ProtectedResourceBinding) ValidateFor(auth AuthorizationContext) error {
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	if err := b.Resource.ValidateFor(auth); err != nil {
		return err
	}
	if err := b.AuthorizationResource.ValidateFor(auth); err != nil {
		return fmt.Errorf("protected authorization resource: %w", err)
	}
	return nil
}

// ProtectedContentBinding binds every content-bearing event produced by one
// permissioned query turn to the same fail-closed replay block.
type ProtectedContentBinding struct {
	Version   string                     `json:"version"`
	BlockID   string                     `json:"block_id"`
	SessionID string                     `json:"session_id"`
	RequestID string                     `json:"request_id"`
	Resources []ProtectedResourceBinding `json:"resources"`
}

// UnmarshalJSON rejects unknown fields and non-canonical bindings at the
// persistence boundary. Callers cannot accidentally replay metadata that only
// becomes invalid after it has already been trusted.
func (b *ProtectedContentBinding) UnmarshalJSON(data []byte) error {
	type encodedBinding ProtectedContentBinding
	var decoded encodedBinding
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decode protected content binding: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode protected content binding: trailing JSON")
		}
		return fmt.Errorf("decode protected content binding: %w", err)
	}
	validated := ProtectedContentBinding(decoded)
	if err := validated.Validate(); err != nil {
		return err
	}
	*b = validated
	return nil
}

// NewProtectedContentBinding builds one deterministic binding from all
// evidence packages used during a turn.
func NewProtectedContentBinding(auth AuthorizationContext, packages ...EvidencePackage) (ProtectedContentBinding, error) {
	if err := auth.Validate(); err != nil {
		return ProtectedContentBinding{}, err
	}
	if len(packages) == 0 {
		return ProtectedContentBinding{}, fmt.Errorf("protected content requires at least one evidence package")
	}
	resources := make([]ProtectedResourceBinding, 0)
	for index, evidencePackage := range packages {
		if err := evidencePackage.ValidateFor(auth); err != nil {
			return ProtectedContentBinding{}, fmt.Errorf("protected evidence package %d: %w", index, err)
		}
		for _, decision := range evidencePackage.Decisions {
			resources = append(resources, ProtectedResourceBinding{
				Resource:              decision.Resource,
				AuthorizationResource: decision.AuthorizationResource,
			})
		}
	}
	return NewProtectedContentBindingFromResources(auth.SessionID, auth.RequestID, resources)
}

// NewProtectedContentBindingFromResources canonicalizes exact handles before
// deriving the stable block ID.
func NewProtectedContentBindingFromResources(
	sessionID string,
	requestID string,
	resources []ProtectedResourceBinding,
) (ProtectedContentBinding, error) {
	if err := validateToken("protected session_id", sessionID); err != nil {
		return ProtectedContentBinding{}, err
	}
	if err := validateToken("protected request_id", requestID); err != nil {
		return ProtectedContentBinding{}, err
	}
	if len(resources) == 0 {
		return ProtectedContentBinding{}, fmt.Errorf("protected content requires at least one resource")
	}

	canonical := append([]ProtectedResourceBinding(nil), resources...)
	for index, resource := range canonical {
		if err := resource.Validate(); err != nil {
			return ProtectedContentBinding{}, fmt.Errorf("protected resource binding %d: %w", index, err)
		}
	}
	sort.Slice(canonical, func(i, j int) bool {
		return protectedResourceSortKey(canonical[i]) < protectedResourceSortKey(canonical[j])
	})
	deduplicated := canonical[:0]
	for _, resource := range canonical {
		if len(deduplicated) == 0 || protectedResourceSortKey(deduplicated[len(deduplicated)-1]) != protectedResourceSortKey(resource) {
			deduplicated = append(deduplicated, resource)
			continue
		}
	}
	for index := 1; index < len(deduplicated); index++ {
		if deduplicated[index-1].Resource.ResourceID == deduplicated[index].Resource.ResourceID {
			return ProtectedContentBinding{}, fmt.Errorf("protected resource %s has conflicting exact handles", deduplicated[index].Resource.ResourceID)
		}
	}

	binding := ProtectedContentBinding{
		Version:   ProtectedContentBindingVersion,
		SessionID: sessionID,
		RequestID: requestID,
		Resources: append([]ProtectedResourceBinding(nil), deduplicated...),
	}
	binding.BlockID = protectedContentBlockID(binding)
	if err := binding.Validate(); err != nil {
		return ProtectedContentBinding{}, err
	}
	return binding, nil
}

func (b ProtectedContentBinding) Validate() error {
	if b.Version != ProtectedContentBindingVersion {
		return fmt.Errorf("unsupported protected content binding version %q", b.Version)
	}
	if err := validateProtectedBlockID(b.BlockID); err != nil {
		return err
	}
	if err := validateToken("protected session_id", b.SessionID); err != nil {
		return err
	}
	if err := validateToken("protected request_id", b.RequestID); err != nil {
		return err
	}
	if len(b.Resources) == 0 {
		return fmt.Errorf("protected content binding has no resources")
	}
	previousKey := ""
	seenIDs := make(map[ResourceID]struct{}, len(b.Resources))
	for index, resource := range b.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("protected resource binding %d: %w", index, err)
		}
		key := protectedResourceSortKey(resource)
		if index > 0 && key <= previousKey {
			return fmt.Errorf("protected resource bindings must be sorted and unique")
		}
		previousKey = key
		if _, duplicate := seenIDs[resource.Resource.ResourceID]; duplicate {
			return fmt.Errorf("protected resource %s has conflicting exact handles", resource.Resource.ResourceID)
		}
		seenIDs[resource.Resource.ResourceID] = struct{}{}
	}
	if expected := protectedContentBlockID(b); b.BlockID != expected {
		return fmt.Errorf("protected content block_id does not match its metadata")
	}
	return nil
}

func (b ProtectedContentBinding) ValidateFor(auth AuthorizationContext) error {
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	if b.SessionID != auth.SessionID {
		return fmt.Errorf("protected content session does not match authorization context")
	}
	for index, resource := range b.Resources {
		if err := resource.ValidateFor(auth); err != nil {
			return fmt.Errorf("protected resource binding %d: %w", index, err)
		}
	}
	return nil
}

func protectedResourceSortKey(resource ProtectedResourceBinding) string {
	encoded, _ := json.Marshal(resource)
	return string(encoded)
}

func protectedContentBlockID(binding ProtectedContentBinding) string {
	metadata := struct {
		Version   string                     `json:"version"`
		SessionID string                     `json:"session_id"`
		RequestID string                     `json:"request_id"`
		Resources []ProtectedResourceBinding `json:"resources"`
	}{
		Version: binding.Version, SessionID: binding.SessionID,
		RequestID: binding.RequestID, Resources: binding.Resources,
	}
	encoded, _ := json.Marshal(metadata)
	sum := sha256.Sum256(encoded)
	return protectedBlockIDPrefix + hex.EncodeToString(sum[:16])
}

func validateProtectedBlockID(value string) error {
	if !strings.HasPrefix(value, protectedBlockIDPrefix) || len(value) != len(protectedBlockIDPrefix)+32 {
		return fmt.Errorf("protected block_id must be an opaque block_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, protectedBlockIDPrefix)); err != nil {
		return fmt.Errorf("protected block_id must be hexadecimal: %w", err)
	}
	return nil
}
