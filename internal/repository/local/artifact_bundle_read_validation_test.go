package local

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCurrentArtifactManifestValidatesExactRegularBundleContents(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, bundleDir string)
		wantErr string
	}{
		{
			name: "valid",
		},
		{
			name: "extra file",
			mutate: func(t *testing.T, bundleDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bundleDir, "unlisted.json"), []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "contents differ",
		},
		{
			name: "missing file",
			mutate: func(t *testing.T, bundleDir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(bundleDir, "summaries.jsonl")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "contents differ",
		},
		{
			name: "corrupt file",
			mutate: func(t *testing.T, bundleDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bundleDir, "summaries.jsonl"), []byte("corrupt\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "differs from projection",
		},
		{
			name: "listed symlink",
			mutate: func(t *testing.T, bundleDir string) {
				t.Helper()
				path := filepath.Join(bundleDir, "summaries.jsonl")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), "summaries.jsonl")
				if err := os.WriteFile(target, data, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
			wantErr: "non-regular file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			store := New(workspace)
			set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
			if err := store.WriteArtifacts(context.Background(), set); err != nil {
				t.Fatal(err)
			}
			bundleDir := filepath.Join(workspace, "artifacts", "bundles", set.BundleManifest.ProjectionID)
			if test.mutate != nil {
				test.mutate(t, bundleDir)
			}

			manifest, err := store.ReadCurrentArtifactManifest(context.Background())
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("valid bundle read failed: %v", err)
				}
				if manifest.ProjectionID != set.BundleManifest.ProjectionID {
					t.Fatalf("read projection %q, want %q", manifest.ProjectionID, set.BundleManifest.ProjectionID)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("read error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}
