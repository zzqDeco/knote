package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
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
			name: "corrupt graph binding",
			mutate: func(t *testing.T, bundleDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bundleDir, "graph_bindings.jsonl"), []byte("corrupt\n"), 0o644); err != nil {
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

func TestReadCurrentArtifactManifestRejectsDigestValidGraphProjectionMismatch(t *testing.T) {
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	if err := store.WriteArtifacts(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(workspace, "artifacts", "bundles", set.BundleManifest.ProjectionID)
	graphPath := filepath.Join(bundleDir, protocol.GraphBindingsArtifactPath)
	if err := os.WriteFile(graphPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(bundleDir, bundleManifestName)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest protocol.ArtifactBundleManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	emptySum := sha256.Sum256(nil)
	for index := range manifest.Files {
		if manifest.Files[index].Path == protocol.GraphBindingsArtifactPath {
			manifest.Files[index].SHA256 = hex.EncodeToString(emptySum[:])
			manifest.Files[index].Count = 0
			manifest.Files[index].SizeBytes = 0
		}
	}
	manifestData, err = marshalIndentedJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
	pointerPath := filepath.Join(workspace, "artifacts", "current.json")
	pointerData, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	var pointer protocol.ArtifactCurrentPointer
	if err := json.Unmarshal(pointerData, &pointer); err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestData)
	pointer.ManifestSHA256 = hex.EncodeToString(manifestSum[:])
	pointerData, err = marshalIndentedJSON(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointerPath, pointerData, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = store.ReadCurrentArtifactManifest(context.Background())
	if !errors.Is(err, repository.ErrArtifactProjectionMismatch) ||
		err.Error() != repository.ErrArtifactProjectionMismatch.Error() {
		t.Fatalf("digest-valid graph mismatch error = %v, want generic projection mismatch", err)
	}
}

func TestReadCurrentArtifactBundleReturnsVerifiedIndependentSnapshot(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "selected")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.ReadCurrentArtifactBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	if snapshot.Manifest.ProjectionID != set.BundleManifest.ProjectionID || len(snapshot.Files) != len(set.BundleManifest.Files) {
		t.Fatalf("unexpected selected snapshot: %+v", snapshot.Manifest)
	}

	snapshot.Files["summaries.jsonl"][0] ^= 0xff
	fresh, err := store.ReadCurrentArtifactBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Validate(); err != nil {
		t.Fatalf("caller mutation changed store-owned selected bytes: %v", err)
	}
}

func TestReadCurrentArtifactMetadataDoesNotReadEvidencePayloads(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "selected")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(workspace, "artifacts", "bundles", set.BundleManifest.ProjectionID)
	if err := os.WriteFile(filepath.Join(bundleDir, "summaries.jsonl"), []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	metadata, err := store.ReadCurrentArtifactMetadata(ctx)
	if err != nil {
		t.Fatalf("authorization metadata read evidence bytes: %v", err)
	}
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	metadata.ProjectionJSON[0] ^= 0xff
	fresh, err := store.ReadCurrentArtifactMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Validate(); err != nil {
		t.Fatalf("caller mutation changed store-owned authorization metadata: %v", err)
	}
	if _, err := store.ReadCurrentArtifactBundle(ctx); err == nil {
		t.Fatal("post-authorization bundle load accepted corrupt evidence")
	}
}
