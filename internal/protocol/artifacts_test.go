package protocol

import (
	"sort"
	"strings"
	"testing"
	"time"
)

func TestArtifactBundleManifestRejectsUnsafeNamespace(t *testing.T) {
	for _, namespace := range []string{".", "..", "../evil", "parent/child", `parent\child`, "C:evil", "name*"} {
		t.Run(namespace, func(t *testing.T) {
			manifest := validArtifactBundleManifest()
			manifest.Namespace = namespace
			if err := manifest.Validate(); err == nil {
				t.Fatalf("unsafe namespace %q was accepted", namespace)
			}
		})
	}
}

func TestArtifactBundleManifestRequiresVersionedGraphBindingPair(t *testing.T) {
	manifest := validArtifactBundleManifest()
	manifest.GraphBindingContractVersion = GraphBindingContractVersion
	manifest.Files = append(manifest.Files,
		ArtifactBundleFile{Path: ClaimBindingsArtifactPath, SHA256: strings.Repeat("c", 64)},
		ArtifactBundleFile{Path: GraphBindingsArtifactPath, SHA256: strings.Repeat("d", 64)},
	)
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	legacy := manifest
	legacy.GraphBindingContractVersion = GraphBindingContractVersionV1
	if err := legacy.Validate(); err != nil {
		t.Fatalf("valid v1 graph binding manifest was rejected: %v", err)
	}

	missing := manifest
	missing.Files = append([]ArtifactBundleFile(nil), manifest.Files...)
	for index, file := range missing.Files {
		if file.Path == ClaimBindingsArtifactPath {
			missing.Files = append(missing.Files[:index], missing.Files[index+1:]...)
			break
		}
	}
	if err := missing.Validate(); err == nil {
		t.Fatal("manifest accepted an incomplete graph binding file pair")
	}

	undeclared := manifest
	undeclared.GraphBindingContractVersion = 0
	if err := undeclared.Validate(); err == nil {
		t.Fatal("manifest accepted graph bindings without a declared contract version")
	}
}

func validArtifactBundleManifest() ArtifactBundleManifest {
	generatedAt := time.Unix(42, 0).UTC()
	paths := []string{
		"build_report.md", "chunks.jsonl", "claims.jsonl", "documents.jsonl", "entities.jsonl",
		"projection.json", "relations.jsonl", "schema.yaml", "summaries.jsonl",
	}
	files := make([]ArtifactBundleFile, len(paths))
	for i, path := range paths {
		files[i] = ArtifactBundleFile{Path: path, SHA256: strings.Repeat("a", 64)}
	}
	compatibility := ArtifactManifest{Version: 1, GeneratedAt: generatedAt, SourceCount: 1}
	return ArtifactBundleManifest{
		Version:      ArtifactBundleManifestVersion,
		ProjectionID: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ProjectionVersion: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Namespace:           "KnoteKB__prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AuthorizationObject: "knowledge-base:test", AuthorizationVersion: "authz_0123456789abcdef01234567",
		SourceSnapshot: ArtifactSourceSnapshot{
			Version: "src_0123456789abcdef01234567", Digest: strings.Repeat("b", 64), DocumentCount: 1,
		},
		GeneratedAt: generatedAt, Files: files, Compatibility: compatibility,
	}
}
