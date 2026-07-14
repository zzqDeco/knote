package protocol

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

const ArtifactBundleManifestVersion = 2

// ArtifactSourceSnapshot binds a serving artifact bundle to the exact source
// snapshot from which it was derived.
type ArtifactSourceSnapshot struct {
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	DocumentCount int    `json:"document_count"`
}

// ArtifactBundleFile describes one immutable file in a serving bundle.
type ArtifactBundleFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Count     int    `json:"count"`
	SizeBytes int64  `json:"size_bytes"`
}

// ArtifactBundleManifest is the canonical v2 serving-build contract. The
// legacy manifest remains embedded only to make v1 compatibility exports
// reproducible from the same projection.
type ArtifactBundleManifest struct {
	Version                     int                    `json:"version"`
	ProjectionID                string                 `json:"projection_id"`
	ProjectionVersion           string                 `json:"projection_version"`
	Namespace                   string                 `json:"namespace"`
	AuthorizationObject         string                 `json:"authz_object"`
	AuthorizationVersion        string                 `json:"authz_version"`
	GraphBindingContractVersion int                    `json:"graph_binding_contract_version,omitempty"`
	SourceSnapshot              ArtifactSourceSnapshot `json:"source_snapshot"`
	GeneratedAt                 time.Time              `json:"generated_at"`
	Files                       []ArtifactBundleFile   `json:"files"`
	Compatibility               ArtifactManifest       `json:"v1_compatibility"`
}

// ArtifactCurrentPointer is the only serving pointer for local artifacts.
// Its manifest digest prevents a pointer from silently selecting a modified
// bundle.
type ArtifactCurrentPointer struct {
	Version           int    `json:"version"`
	ProjectionID      string `json:"projection_id"`
	ProjectionVersion string `json:"projection_version"`
	ManifestSHA256    string `json:"manifest_sha256"`
}

func (m ArtifactBundleManifest) Validate() error {
	if m.Version != ArtifactBundleManifestVersion {
		return fmt.Errorf("artifact bundle manifest version must be %d", ArtifactBundleManifestVersion)
	}
	if err := validateProjectionID(m.ProjectionID); err != nil {
		return err
	}
	if m.ProjectionVersion != m.ProjectionID {
		return fmt.Errorf("artifact projection version must match projection id")
	}
	if err := validatePathToken("namespace", m.Namespace); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"authz_object": m.AuthorizationObject, "authz_version": m.AuthorizationVersion,
		"source_snapshot_version": m.SourceSnapshot.Version,
	} {
		if err := validateToken(name, value); err != nil {
			return err
		}
	}
	if err := validateSHA256("source snapshot digest", m.SourceSnapshot.Digest); err != nil {
		return err
	}
	if m.SourceSnapshot.DocumentCount < 0 {
		return fmt.Errorf("source snapshot document count must be non-negative")
	}
	if m.GeneratedAt.IsZero() {
		return fmt.Errorf("generated_at is required")
	}
	if m.Compatibility.Version != 1 {
		return fmt.Errorf("v1 compatibility manifest must have version 1")
	}
	if !m.Compatibility.GeneratedAt.Equal(m.GeneratedAt) {
		return fmt.Errorf("v1 compatibility manifest generated_at does not match bundle")
	}
	if m.Compatibility.SourceCount != m.SourceSnapshot.DocumentCount {
		return fmt.Errorf("v1 compatibility source count does not match source snapshot")
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("artifact bundle files are required")
	}
	paths := make([]string, len(m.Files))
	required := map[string]bool{
		"documents.jsonl": false, "chunks.jsonl": false, "entities.jsonl": false,
		"relations.jsonl": false, "claims.jsonl": false, "summaries.jsonl": false,
		"schema.yaml": false, "build_report.md": false, "projection.json": false,
	}
	switch m.GraphBindingContractVersion {
	case 0:
	case GraphBindingContractVersion:
		required[GraphBindingsArtifactPath] = false
		required[ClaimBindingsArtifactPath] = false
	default:
		return fmt.Errorf("unsupported graph binding contract version %d", m.GraphBindingContractVersion)
	}
	for i, file := range m.Files {
		if strings.TrimSpace(file.Path) == "" || file.Path != strings.TrimSpace(file.Path) ||
			strings.Contains(file.Path, "\\") || strings.Contains(file.Path, "/") || file.Path == "." || file.Path == ".." {
			return fmt.Errorf("artifact bundle file %d has invalid path %q", i, file.Path)
		}
		if err := validateSHA256("artifact file digest", file.SHA256); err != nil {
			return fmt.Errorf("artifact bundle file %q: %w", file.Path, err)
		}
		if file.Count < 0 || file.SizeBytes < 0 {
			return fmt.Errorf("artifact bundle file %q has negative count or size", file.Path)
		}
		paths[i] = file.Path
		if _, ok := required[file.Path]; ok {
			required[file.Path] = true
		}
	}
	if !sort.StringsAreSorted(paths) {
		return fmt.Errorf("artifact bundle files must be sorted by path")
	}
	for i := 1; i < len(paths); i++ {
		if paths[i-1] == paths[i] {
			return fmt.Errorf("artifact bundle file %q is duplicated", paths[i])
		}
	}
	for path, present := range required {
		if !present {
			return fmt.Errorf("artifact bundle is missing required file %q", path)
		}
	}
	if m.GraphBindingContractVersion == 0 {
		for _, path := range paths {
			if path == GraphBindingsArtifactPath || path == ClaimBindingsArtifactPath {
				return fmt.Errorf("artifact bundle graph bindings require a declared graph binding contract version")
			}
		}
	}
	return nil
}

func (p ArtifactCurrentPointer) Validate() error {
	if p.Version != ArtifactBundleManifestVersion {
		return fmt.Errorf("artifact current pointer version must be %d", ArtifactBundleManifestVersion)
	}
	if err := validateProjectionID(p.ProjectionID); err != nil {
		return err
	}
	if p.ProjectionVersion != p.ProjectionID {
		return fmt.Errorf("artifact current pointer projection version must match projection id")
	}
	return validateSHA256("artifact manifest digest", p.ManifestSHA256)
}

func validateProjectionID(value string) error {
	if !strings.HasPrefix(value, "prj_") || len(value) != len("prj_")+32 {
		return fmt.Errorf("projection_id must be prj_ followed by 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "prj_")); err != nil {
		return fmt.Errorf("projection_id must be hexadecimal: %w", err)
	}
	return nil
}

func validateSHA256(name, value string) error {
	if len(value) != 64 {
		return fmt.Errorf("%s must be a 64-character SHA-256 digest", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be hexadecimal: %w", name, err)
	}
	return nil
}

func validatePathToken(name, value string) error {
	if err := validateToken(name, value); err != nil {
		return err
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return fmt.Errorf("%s is not a path-safe token", name)
		}
	}
	return nil
}
