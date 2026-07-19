package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type ToolReturnObligation string

// ToolAuthorizationContractVersion versions the invocation/result records that
// gained explicit return obligations. Enterprise v1 remains accepted for the
// legacy record shape without this field.
const ToolAuthorizationContractVersion = "v2"

const (
	ToolReturnNone      ToolReturnObligation = "none"
	ToolReturnEvidence  ToolReturnObligation = "evidence_package"
	ToolReturnResources ToolReturnObligation = "resource_handles"
)

func (o ToolReturnObligation) Validate() error {
	switch o {
	case ToolReturnNone, ToolReturnEvidence, ToolReturnResources:
		return nil
	default:
		return fmt.Errorf("unsupported tool return obligation %q", o)
	}
}

// ToolAuthorizationManifest is trusted startup configuration. Tool arguments
// cannot select or override any field in this record.
type ToolAuthorizationManifest struct {
	Version          string               `json:"version"`
	ToolName         string               `json:"tool_name"`
	Action           string               `json:"action"`
	Relation         string               `json:"relation"`
	SideEffect       bool                 `json:"side_effect"`
	ReturnObligation ToolReturnObligation `json:"return_obligation"`
}

func (m ToolAuthorizationManifest) Validate() error {
	if m.Version != ToolAuthorizationContractVersion {
		return fmt.Errorf("unsupported tool authorization manifest version %q", m.Version)
	}
	if err := validateAuthorizationName("tool_name", m.ToolName); err != nil {
		return err
	}
	if err := validateAuthorizationName("action", m.Action); err != nil {
		return err
	}
	if err := validateAuthorizationName("relation", m.Relation); err != nil {
		return err
	}
	return m.ReturnObligation.Validate()
}

func (m ToolAuthorizationManifest) InvocationRequest() (ToolInvocationRequest, error) {
	if err := m.Validate(); err != nil {
		return ToolInvocationRequest{}, err
	}
	return ToolInvocationRequest{
		Version:          ToolAuthorizationContractVersion,
		ToolName:         m.ToolName,
		Action:           m.Action,
		Relation:         m.Relation,
		SideEffect:       m.SideEffect,
		ReturnObligation: m.ReturnObligation,
	}, nil
}

type ToolManifestRegistry struct {
	manifests []ToolAuthorizationManifest
	byName    map[string]ToolAuthorizationManifest
	digest    string
}

type ToolAuthorizationEnvelope struct {
	Version        string                      `json:"version"`
	ManifestDigest string                      `json:"manifest_digest"`
	Invocation     ToolInvocationAuthorization `json:"invocation"`
	Result         ToolResultAuthorization     `json:"result"`
}

func (e ToolAuthorizationEnvelope) ValidateFor(
	auth AuthorizationContext,
	manifest ToolAuthorizationManifest,
) error {
	if e.Version != ToolAuthorizationContractVersion {
		return fmt.Errorf("unsupported tool authorization envelope version %q", e.Version)
	}
	if err := validateToolManifestDigest(e.ManifestDigest); err != nil {
		return err
	}
	request, err := manifest.InvocationRequest()
	if err != nil {
		return err
	}
	if err := e.Invocation.ValidateFor(auth, request); err != nil {
		return err
	}
	return e.Result.ValidateFor(auth, e.Invocation, request)
}

func NewToolManifestRegistry(manifests []ToolAuthorizationManifest) (*ToolManifestRegistry, error) {
	if len(manifests) == 0 {
		return nil, fmt.Errorf("tool manifest registry requires at least one manifest")
	}
	sorted := append([]ToolAuthorizationManifest(nil), manifests...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ToolName < sorted[j].ToolName })
	byName := make(map[string]ToolAuthorizationManifest, len(sorted))
	parts := make([]string, 0, len(sorted)*6)
	for index, manifest := range sorted {
		if err := manifest.Validate(); err != nil {
			return nil, fmt.Errorf("tool manifest %d: %w", index, err)
		}
		if _, duplicate := byName[manifest.ToolName]; duplicate {
			return nil, fmt.Errorf("duplicate tool manifest %q", manifest.ToolName)
		}
		byName[manifest.ToolName] = manifest
		parts = append(parts,
			manifest.Version,
			manifest.ToolName,
			manifest.Action,
			manifest.Relation,
			fmt.Sprintf("%t", manifest.SideEffect),
			string(manifest.ReturnObligation),
		)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return &ToolManifestRegistry{
		manifests: sorted,
		byName:    byName,
		digest:    "tool_manifest_" + hex.EncodeToString(sum[:16]),
	}, nil
}

func (r *ToolManifestRegistry) Lookup(toolName string) (ToolAuthorizationManifest, bool) {
	if r == nil {
		return ToolAuthorizationManifest{}, false
	}
	manifest, ok := r.byName[toolName]
	return manifest, ok
}

func (r *ToolManifestRegistry) Manifests() []ToolAuthorizationManifest {
	if r == nil {
		return nil
	}
	return append([]ToolAuthorizationManifest(nil), r.manifests...)
}

func (r *ToolManifestRegistry) Digest() string {
	if r == nil {
		return ""
	}
	return r.digest
}

func (r *ToolManifestRegistry) ValidateEnvelope(
	auth AuthorizationContext,
	envelope ToolAuthorizationEnvelope,
) error {
	if r == nil {
		return fmt.Errorf("tool manifest registry is unavailable")
	}
	if envelope.ManifestDigest != r.digest {
		return fmt.Errorf("tool authorization envelope manifest digest does not match the registry")
	}
	manifest, ok := r.Lookup(envelope.Invocation.ToolName)
	if !ok {
		return fmt.Errorf("tool authorization envelope references an unregistered tool")
	}
	return envelope.ValidateFor(auth, manifest)
}

func validateToolManifestDigest(value string) error {
	const prefix = "tool_manifest_"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+32 {
		return fmt.Errorf("tool manifest digest must be an opaque tool_manifest_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, prefix)); err != nil {
		return fmt.Errorf("tool manifest digest must be hexadecimal: %w", err)
	}
	return nil
}
