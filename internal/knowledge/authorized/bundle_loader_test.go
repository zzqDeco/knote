package authorized_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestBundleEvidenceLoaderUsesOnlyExactSelectedContent(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := local.New(workspace)
	service := versioned.New(versioned.Options{
		Workspace: workspace, Repo: store, Backend: bundleLoaderBackend{}, Mode: versioned.ModeFake,
	})
	if _, err := service.Build(ctx); err != nil {
		t.Fatal(err)
	}

	loader, err := authorized.NewBundleEvidenceLoader(store)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := loader.CurrentAuthorizationScope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if scope.TenantID != "local" || scope.KnowledgeBaseID == "" || scope.ACLWatermark == "" || scope.ProjectionVersion == "" {
		t.Fatalf("unexpected selected authorization scope: %+v", scope)
	}

	snapshot, err := store.ReadCurrentArtifactBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var projection catalog.Projection
	if err := json.Unmarshal(snapshot.Files["projection.json"], &projection); err != nil {
		t.Fatal(err)
	}
	handles := make(map[protocol.ResourceType]protocol.ResourceHandle)
	for _, metadata := range projection.Resources {
		handle, err := metadata.ServingHandle()
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := handles[handle.Type]; !exists {
			handles[handle.Type] = handle
		}
	}
	requested := []protocol.ResourceHandle{
		handles[protocol.ResourceChunk],
		handles[protocol.ResourceClaim],
		handles[protocol.ResourceEntity],
	}
	items, err := loader.Load(ctx, requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != len(requested) {
		t.Fatalf("loaded %d items, want %d", len(items), len(requested))
	}
	for index, item := range items {
		if item.Resource != requested[index] || protocol.NewContentDigest(item.Content) != requested[index].ContentDigest {
			t.Fatalf("loaded item %d does not match exact handle: %+v", index, item)
		}
		if len(item.Supports) == 0 {
			t.Fatalf("loaded item %d has no provenance", index)
		}
	}
	entity := items[2]
	for _, support := range entity.Supports {
		if support.Resource.Type != protocol.ResourceDocument || len(support.Evidence) != 1 ||
			support.Evidence[0].Type != protocol.ResourceChunk ||
			support.Evidence[0].AuthorizationResourceID != support.Resource.ResourceID {
			t.Fatalf("entity support does not bind chunk evidence to its parent document: %+v", support)
		}
	}

	stale := requested[0]
	stale.ContentDigest = protocol.NewContentDigest("stale")
	if _, err := loader.Load(ctx, []protocol.ResourceHandle{stale}); err == nil {
		t.Fatal("loader accepted a stale exact handle")
	}
	if _, err := loader.Load(ctx, []protocol.ResourceHandle{handles[protocol.ResourceDocument]}); err == nil {
		t.Fatal("loader accepted document metadata without selected bundle content")
	}
}

func TestBundleEvidenceLoaderRejectsTamperedSnapshot(t *testing.T) {
	snapshot := buildSelectedSnapshot(t)
	handle := selectedHandle(t, snapshot, protocol.ResourceEntity)
	snapshot.Files["entities.jsonl"] = append(snapshot.Files["entities.jsonl"], []byte("tampered")...)
	loader, err := authorized.NewBundleEvidenceLoader(staticSelectedReader{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loader.Load(context.Background(), []protocol.ResourceHandle{handle}); err == nil {
		t.Fatal("loader accepted a digest-invalid selected snapshot")
	}
}

func TestBundleEvidenceLoaderAuthorizationScopeDoesNotReadEvidence(t *testing.T) {
	snapshot := buildSelectedSnapshot(t)
	bundleReads := 0
	loader, err := authorized.NewBundleEvidenceLoader(staticSelectedReader{
		snapshot: snapshot, bundleReads: &bundleReads,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loader.CurrentAuthorizationScope(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bundleReads != 0 {
		t.Fatalf("authorization scope read %d evidence bundles before authorization", bundleReads)
	}
}

func buildSelectedSnapshot(t *testing.T) repository.SelectedArtifactBundle {
	t.Helper()
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := local.New(workspace)
	service := versioned.New(versioned.Options{
		Workspace: workspace, Repo: store, Backend: bundleLoaderBackend{}, Mode: versioned.ModeFake,
	})
	if _, err := service.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadCurrentArtifactBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

type staticSelectedReader struct {
	snapshot    repository.SelectedArtifactBundle
	bundleReads *int
}

func (r staticSelectedReader) ReadCurrentArtifactMetadata(context.Context) (repository.SelectedArtifactMetadata, error) {
	return repository.SelectedArtifactMetadata{
		Manifest:       r.snapshot.Manifest,
		ProjectionJSON: append([]byte(nil), r.snapshot.Files["projection.json"]...),
	}.Clone(), nil
}

func (r staticSelectedReader) ReadCurrentArtifactBundle(context.Context) (repository.SelectedArtifactBundle, error) {
	if r.bundleReads != nil {
		(*r.bundleReads)++
	}
	return r.snapshot.Clone(), nil
}

func selectedHandle(
	t *testing.T,
	snapshot repository.SelectedArtifactBundle,
	resourceType protocol.ResourceType,
) protocol.ResourceHandle {
	t.Helper()
	var projection catalog.Projection
	if err := json.Unmarshal(snapshot.Files["projection.json"], &projection); err != nil {
		t.Fatal(err)
	}
	for _, metadata := range projection.Resources {
		if metadata.Type != resourceType || !metadata.IsServing() {
			continue
		}
		handle, err := metadata.ServingHandle()
		if err != nil {
			t.Fatal(err)
		}
		return handle
	}
	t.Fatalf("selected projection has no serving %s", resourceType)
	return protocol.ResourceHandle{}
}

type bundleLoaderBackend struct{}

func (bundleLoaderBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "fake"}}, nil
}

func (bundleLoaderBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "fake", "mode": "fake"}}, nil
}

func (bundleLoaderBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "fake", "mode": "fake"}}, nil
}

func (b bundleLoaderBackend) BuildInNamespace(ctx context.Context, _, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b bundleLoaderBackend) BuildInNamespaceWithCorpus(ctx context.Context, _, _ string, _ []kag.CorpusRecord) (kag.Response, error) {
	return b.Build(ctx)
}

func (b bundleLoaderBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b bundleLoaderBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}
