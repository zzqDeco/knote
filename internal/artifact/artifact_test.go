package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildWritesDeterministicArtifacts(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sources", "a.md"), []byte("# A\n\nA claim."), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Builder{Workspace: workspace}.Build()
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.DocumentCount != 1 || result.Manifest.ChunkCount != 1 {
		t.Fatalf("unexpected manifest: %+v", result.Manifest)
	}
	if err := result.Write(workspace); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"documents.jsonl", "chunks.jsonl", "entities.jsonl", "claims.jsonl", "summaries.jsonl", "manifest.json", "schema.yaml", "build_report.md"} {
		if _, err := os.Stat(filepath.Join(workspace, "artifacts", name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}
