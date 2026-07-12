package protocol

import (
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
