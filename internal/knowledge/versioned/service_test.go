package versioned

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestServiceBuildQueryAndEvalWithFakeBackend(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "# Intro\n\nknote is local-first.\n"
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	build, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if build.Manifest.DocumentCount != 1 || build.Manifest.ChunkCount != 1 {
		t.Fatalf("unexpected build manifest: %+v", build.Manifest)
	}
	if repo.artifacts.Manifest.DocumentCount != 1 {
		t.Fatalf("artifacts were not written: %+v", repo.artifacts.Manifest)
	}

	answer, err := svc.Query(ctx, "what is knote?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer.Answer, "Fake KAG answer") {
		t.Fatalf("unexpected answer: %+v", answer)
	}

	report, err := svc.Eval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 1 || report.AdapterErrors != 0 || report.KnowledgeHash != repo.hash {
		t.Fatalf("unexpected eval report: %+v", report)
	}
	if len(repo.eval.Results) != 1 || repo.eval.Results[0].KnowledgeHash != repo.hash {
		t.Fatalf("eval results were not persisted with current hash: %+v", repo.eval.Results)
	}
}

func TestServiceQueryFallsBackToArtifacts(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "hello\n"
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   failingBackend{},
		Mode:      ModeFake,
	})
	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}
	answer, err := svc.Query(ctx, "what is here?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer.Answer, "artifacts fallback") || answer.AdapterError == "" {
		t.Fatalf("expected fallback answer with adapter error, got %+v", answer)
	}
}

func TestServiceBuildFailsBeforeWritingArtifactsWhenBackendFails(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "# Intro\n\nknote is local-first.\n"
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   buildFailingBackend{},
		Mode:      ModeReal,
	})

	build, err := svc.Build(ctx)
	if err == nil {
		t.Fatal("expected build to fail when backend build fails")
	}
	if build.AdapterError == "" {
		t.Fatalf("expected adapter error in build result: %+v", build)
	}
	if repo.writeArtifactsCalls != 0 {
		t.Fatalf("backend failure wrote artifacts %d time(s)", repo.writeArtifactsCalls)
	}
}

func TestServiceBuildArtifactsAreStableAndEntityIsPerDocument(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sourceModTimes["sources/long.md"] = time.Unix(42, 0).UTC()
	repo.sources["sources/long.md"] = "# Long\n\n" + strings.Repeat("hello world ", 120)
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstManifest, err := json.Marshal(first.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	repo.sourceModTimes["sources/long.md"] = time.Unix(99, 0).UTC()
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := json.Marshal(second.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstManifest) != string(secondManifest) {
		t.Fatalf("manifest changed on no-op rebuild:\nfirst=%s\nsecond=%s", firstManifest, secondManifest)
	}
	firstBundle, err := json.Marshal(first.BundleManifest)
	if err != nil {
		t.Fatal(err)
	}
	secondBundle, err := json.Marshal(second.BundleManifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBundle) != string(secondBundle) {
		t.Fatalf("v2 bundle manifest changed on no-op rebuild:\nfirst=%s\nsecond=%s", firstBundle, secondBundle)
	}
	if !first.Manifest.GeneratedAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("generated_at must exclude source mtimes, got %s", first.Manifest.GeneratedAt)
	}
	if len(repo.artifacts.Chunks) < 2 {
		t.Fatalf("test source did not split into multiple chunks: %+v", repo.artifacts.Chunks)
	}
	if len(repo.artifacts.Entities) != 1 {
		t.Fatalf("expected one document entity, got %d: %+v", len(repo.artifacts.Entities), repo.artifacts.Entities)
	}
	if got, want := len(repo.artifacts.Entities[0].EvidenceChunkIDs), len(repo.artifacts.Chunks); got != want {
		t.Fatalf("document entity evidence chunk count = %d, want %d", got, want)
	}
}

func TestServiceBuildUsesProjectionIsolatedKAGNamespaceAndMetadata(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "Team Knowledge"
	repo.sources["sources/intro.md"] = "first\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if backend.buildNamespace != first.BundleManifest.Namespace {
		t.Fatalf("KAG build namespace = %q, want %q", backend.buildNamespace, first.BundleManifest.Namespace)
	}
	if !strings.HasPrefix(first.BundleManifest.Namespace, "Team_Knowledge__prj_") {
		t.Fatalf("namespace was not canonical and projection isolated: %q", first.BundleManifest.Namespace)
	}
	if first.BundleManifest.ProjectionVersion != first.BundleManifest.ProjectionID ||
		first.BundleManifest.AuthorizationVersion == "" {
		t.Fatalf("projection/authz metadata is inconsistent: %+v", first.BundleManifest)
	}
	answer, err := svc.Query(ctx, "what is here?")
	if err != nil {
		t.Fatal(err)
	}
	if backend.queryNamespace != first.BundleManifest.Namespace ||
		answer.ProjectionVersion != first.BundleManifest.ProjectionVersion || answer.Namespace != first.BundleManifest.Namespace ||
		answer.AuthorizationObject != first.BundleManifest.AuthorizationObject ||
		answer.AuthorizationVersion != first.BundleManifest.AuthorizationVersion {
		t.Fatalf("retrieval metadata does not match serving build: answer=%+v manifest=%+v", answer, first.BundleManifest)
	}

	repo.sources["sources/intro.md"] = "second\n"
	firstDocumentID := repo.artifacts.Documents[0].DocumentID
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.BundleManifest.ProjectionID == first.BundleManifest.ProjectionID ||
		second.BundleManifest.Namespace == first.BundleManifest.Namespace ||
		second.BundleManifest.AuthorizationObject != first.BundleManifest.AuthorizationObject ||
		second.BundleManifest.AuthorizationVersion != first.BundleManifest.AuthorizationVersion {
		t.Fatalf("content-only projection change altered identity isolation or ACL version:\nfirst=%+v\nsecond=%+v", first.BundleManifest, second.BundleManifest)
	}
	if backend.buildNamespace != second.BundleManifest.Namespace {
		t.Fatalf("second KAG build namespace = %q, want %q", backend.buildNamespace, second.BundleManifest.Namespace)
	}
	if repo.artifacts.Documents[0].DocumentID != firstDocumentID {
		t.Fatalf("content update changed stable document identity: first=%s second=%s", firstDocumentID, repo.artifacts.Documents[0].DocumentID)
	}
}

func TestProjectionIdentityExcludesAbsoluteWorkspacePaths(t *testing.T) {
	ctx := context.Background()
	build := func(workspace string) BuildResult {
		repo := newMemoryRepo()
		repo.config.Workspace = workspace
		repo.config.KAG.Namespace = "PortableKB"
		repo.sources["sources/intro.md"] = "portable\n"
		result, err := New(Options{Workspace: workspace, Repo: repo, Backend: fakeBackend{}, Mode: ModeFake}).Build(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(repo.artifacts.ProjectionJSON), workspace) {
			t.Fatalf("public projection contains absolute workspace path %q", workspace)
		}
		return result
	}
	first := build("/private/checkout/one")
	second := build("/different/checkout/two")
	if first.BundleManifest.ProjectionVersion != second.BundleManifest.ProjectionVersion ||
		first.BundleManifest.Namespace != second.BundleManifest.Namespace {
		t.Fatalf("absolute workspace path changed projection identity: first=%+v second=%+v", first.BundleManifest, second.BundleManifest)
	}
}

func TestServiceFailedProjectionLeavesCatalogAndArtifactPointersServingPriorVersion(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "FailureTest"
	repo.sources["sources/intro.md"] = "first\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})
	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend.buildErr = errFakeUnavailable
	repo.sources["sources/intro.md"] = "second\n"
	failed, err := svc.Build(ctx)
	if err == nil || failed.AdapterError == "" {
		t.Fatalf("expected projection KAG failure, result=%+v err=%v", failed, err)
	}
	if repo.artifacts.BundleManifest.ProjectionVersion != first.BundleManifest.ProjectionVersion {
		t.Fatalf("failed projection replaced artifact pointer: got=%s want=%s",
			repo.artifacts.BundleManifest.ProjectionVersion, first.BundleManifest.ProjectionVersion)
	}
	store, err := catalog.NewProjectionStore(filepath.Join(repo.projectionRoot, "by-base", "projection-empty"))
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := store.ServingPointer()
	if err != nil {
		t.Fatal(err)
	}
	if pointer.ProjectionVersion != first.BundleManifest.ProjectionVersion {
		t.Fatalf("failed projection advanced catalog pointer: got=%s want=%s", pointer.ProjectionVersion, first.BundleManifest.ProjectionVersion)
	}
}

func TestServiceRetriesFailedProjectionWithoutSourceChanges(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "RetryTest"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{buildErr: errFakeUnavailable}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	failed, err := svc.Build(ctx)
	if err == nil || failed.AdapterError == "" {
		t.Fatalf("expected initial KAG failure, result=%+v err=%v", failed, err)
	}
	backend.buildErr = nil
	recovered, err := svc.Build(ctx)
	if err != nil {
		t.Fatalf("retry unchanged failed projection: %v", err)
	}
	if backend.buildCalls != 2 {
		t.Fatalf("KAG build calls = %d, want 2 across failed attempt and retry", backend.buildCalls)
	}
	if recovered.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion ||
		repo.artifacts.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion {
		t.Fatalf("retry did not publish the failed projection identity: failed=%s recovered=%s current=%s",
			failed.BundleManifest.ProjectionVersion, recovered.BundleManifest.ProjectionVersion,
			repo.artifacts.BundleManifest.ProjectionVersion)
	}
}

func TestServiceKAGConfigurationChangeCreatesNewProjection(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "ConfigTest"
	repo.config.KAG.Language = "en"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.config.KAG.Language = "zh"
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.BundleManifest.ProjectionVersion == first.BundleManifest.ProjectionVersion ||
		second.BundleManifest.Namespace == first.BundleManifest.Namespace {
		t.Fatalf("KAG configuration change reused projection identity: first=%+v second=%+v",
			first.BundleManifest, second.BundleManifest)
	}
	if backend.buildCalls != 2 {
		t.Fatalf("KAG build calls = %d, want 2 after configuration change", backend.buildCalls)
	}
}

func TestServiceRetryRecoversArtifactPointerAfterCatalogCAS(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "RecoveryTest"
	repo.sources["sources/intro.md"] = "first\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})
	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.sources["sources/intro.md"] = "second\n"
	repo.publishErr = errors.New("injected public pointer failure")
	failed, err := svc.Build(ctx)
	if err == nil || !strings.Contains(err.Error(), "injected public pointer failure") {
		t.Fatalf("expected public pointer failure, result=%+v err=%v", failed, err)
	}
	if repo.artifacts.BundleManifest.ProjectionVersion != first.BundleManifest.ProjectionVersion {
		t.Fatal("failed public pointer publication changed selected artifacts")
	}
	callsAfterCAS := backend.buildCalls
	repo.publishErr = nil
	recovered, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion ||
		repo.artifacts.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion {
		t.Fatalf("retry did not finish the catalog-selected projection: failed=%s recovered=%s current=%s",
			failed.BundleManifest.ProjectionVersion, recovered.BundleManifest.ProjectionVersion,
			repo.artifacts.BundleManifest.ProjectionVersion)
	}
	if backend.buildCalls != callsAfterCAS {
		t.Fatalf("artifact pointer recovery reran KAG: before=%d after=%d", callsAfterCAS, backend.buildCalls)
	}
}

func TestServiceBuildUsesUTF8SafeChunksAndClaims(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/中文.md"] = "# 中文\n\n" + strings.Repeat("知识", 700)
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}
	if len(repo.artifacts.Chunks) < 2 {
		t.Fatalf("test source did not split into multiple chunks: %+v", repo.artifacts.Chunks)
	}
	for _, chunk := range repo.artifacts.Chunks {
		if !utf8.ValidString(chunk.Text) || strings.Contains(chunk.Text, "\ufffd") {
			t.Fatalf("chunk contains invalid UTF-8 or replacement rune: %+v", chunk)
		}
	}
	for _, claim := range repo.artifacts.Claims {
		if !utf8.ValidString(claim.Text) || strings.Contains(claim.Text, "\ufffd") {
			t.Fatalf("claim contains invalid UTF-8 or replacement rune: %+v", claim)
		}
	}
}

func TestVersionedServiceDelegatesVersionOperations(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.status = repository.Status{Branch: "dev", Raw: "clean"}
	repo.diff = "diff output"
	repo.versions = []repository.Version{{Hash: "abcdef", ShortHash: "abcdef", Subject: "initial", Current: true}}
	repo.commitResult = repository.CommitResult{Hash: "123456", Summary: "committed"}
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Versions:  repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	status, err := svc.Status(ctx)
	if err != nil || status.Branch != "dev" {
		t.Fatalf("unexpected status: status=%+v err=%v", status, err)
	}
	diff, err := svc.Diff(ctx, "HEAD~1")
	if err != nil || diff != "diff output" || repo.diffRef != "HEAD~1" {
		t.Fatalf("unexpected diff: diff=%q ref=%q err=%v", diff, repo.diffRef, err)
	}
	versions, err := svc.Versions(ctx, 20)
	if err != nil || len(versions) != 1 || versions[0].ShortHash != "abcdef" {
		t.Fatalf("unexpected versions: versions=%+v err=%v", versions, err)
	}
	commit, err := svc.Commit(ctx, "knowledge update")
	if err != nil || commit.Hash != "123456" || repo.commitMessage != "knowledge update" {
		t.Fatalf("unexpected commit: commit=%+v message=%q err=%v", commit, repo.commitMessage, err)
	}
	if err := svc.Release(ctx, "v0.1.1"); err != nil || repo.tagged != "v0.1.1" {
		t.Fatalf("unexpected release: tag=%q err=%v", repo.tagged, err)
	}
	if err := svc.Checkout(ctx, "main", repository.CheckoutOptions{AllowDirty: true}); err != nil {
		t.Fatalf("checkout failed: %v", err)
	}
	if repo.checkoutRef != "main" || !repo.checkoutOpts.AllowDirty {
		t.Fatalf("unexpected checkout call: ref=%q opts=%+v", repo.checkoutRef, repo.checkoutOpts)
	}
}

func TestVersionedPackageImportBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list versioned imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/runtime",
		"/internal/tui",
		"/internal/repository/local",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("knowledge imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

type memoryRepo struct {
	config              repository.Config
	sources             map[string]string
	sourceModTimes      map[string]time.Time
	artifacts           repository.ArtifactSet
	stagedArtifacts     repository.ArtifactSet
	writeArtifactsCalls int
	publishErr          error
	eval                repository.EvalReport
	hash                string
	status              repository.Status
	diff                string
	diffRef             string
	versions            []repository.Version
	commitResult        repository.CommitResult
	commitMessage       string
	tagged              string
	checkoutRef         string
	checkoutOpts        repository.CheckoutOptions
	projectionRoot      string
}

func newMemoryRepo() *memoryRepo {
	projectionRoot, err := os.MkdirTemp("", "knote-versioned-projections-")
	if err != nil {
		panic(err)
	}
	return &memoryRepo{
		config:         repository.Config{Workspace: "/memory"},
		sources:        map[string]string{},
		sourceModTimes: map[string]time.Time{},
		hash:           "current-knowledge-hash",
		projectionRoot: projectionRoot,
	}
}

func (r *memoryRepo) Config(context.Context) (repository.Config, error) {
	return r.config, nil
}

func (r *memoryRepo) SaveConfig(_ context.Context, cfg repository.Config) error {
	r.config = cfg
	return nil
}

func (r *memoryRepo) ListSources(context.Context) ([]repository.Source, error) {
	out := make([]repository.Source, 0, len(r.sources))
	for path, content := range r.sources {
		modTime := time.Unix(1, 0).UTC()
		if configured := r.sourceModTimes[path]; !configured.IsZero() {
			modTime = configured.UTC()
		}
		out = append(out, repository.Source{
			Path:    path,
			Size:    int64(len(content)),
			ModTime: modTime,
		})
	}
	return out, nil
}

func (r *memoryRepo) ReadSource(_ context.Context, path string) ([]byte, error) {
	return []byte(r.sources[path]), nil
}

func (r *memoryRepo) WriteArtifacts(_ context.Context, set repository.ArtifactSet) error {
	r.writeArtifactsCalls++
	r.artifacts = set
	return nil
}

func (r *memoryRepo) StageArtifacts(_ context.Context, set repository.ArtifactSet) error {
	r.writeArtifactsCalls++
	r.stagedArtifacts = set
	return nil
}

func (r *memoryRepo) PublishArtifacts(context.Context, protocol.ArtifactBundleManifest) error {
	if r.publishErr != nil {
		return r.publishErr
	}
	r.artifacts = r.stagedArtifacts
	return nil
}

func (r *memoryRepo) ReadCurrentProjection(context.Context) ([]byte, error) {
	if len(r.artifacts.ProjectionJSON) == 0 {
		return nil, repository.ErrArtifactCurrentNotFound
	}
	return append([]byte(nil), r.artifacts.ProjectionJSON...), nil
}

func (r *memoryRepo) ProjectionStoreRoot() string { return r.projectionRoot }

func (r *memoryRepo) ReadManifest(context.Context) (protocol.ArtifactManifest, error) {
	return r.artifacts.Manifest, nil
}

func (r *memoryRepo) ReadCurrentArtifactManifest(context.Context) (protocol.ArtifactBundleManifest, error) {
	if r.artifacts.BundleManifest.Version == 0 {
		return protocol.ArtifactBundleManifest{}, repository.ErrArtifactCurrentNotFound
	}
	return r.artifacts.BundleManifest, nil
}

func (r *memoryRepo) ReadSummaries(context.Context) ([]protocol.Summary, error) {
	return r.artifacts.Summaries, nil
}

func (r *memoryRepo) LoadQuestions(context.Context) ([]repository.EvalQuestion, error) {
	return []repository.EvalQuestion{{ID: "smoke", Question: "What does this knowledge base contain?"}}, nil
}

func (r *memoryRepo) WriteEval(_ context.Context, report repository.EvalReport) error {
	r.eval = report
	return nil
}

func (r *memoryRepo) EvalGate(context.Context) error {
	return nil
}

func (r *memoryRepo) KnowledgeHash(context.Context) (string, error) {
	return r.hash, nil
}

func (r *memoryRepo) Status(context.Context) (repository.Status, error) {
	return r.status, nil
}

func (r *memoryRepo) Diff(_ context.Context, ref string) (string, error) {
	r.diffRef = ref
	return r.diff, nil
}

func (r *memoryRepo) Versions(context.Context, int) ([]repository.Version, error) {
	return append([]repository.Version(nil), r.versions...), nil
}

func (r *memoryRepo) Commit(_ context.Context, message string) (repository.CommitResult, error) {
	r.commitMessage = message
	return r.commitResult, nil
}

func (r *memoryRepo) Tag(_ context.Context, tag string) error {
	r.tagged = tag
	return nil
}

func (r *memoryRepo) Checkout(_ context.Context, ref string, opts repository.CheckoutOptions) error {
	r.checkoutRef = ref
	r.checkoutOpts = opts
	return nil
}

type fakeBackend struct{}

func (fakeBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "fake"}}, nil
}

func (fakeBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "Fake KAG answer", "mode": "fake"}}, nil
}

func (fakeBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "Fake KAG answer", "explanation": "because", "mode": "fake"}}, nil
}

func (b fakeBackend) BuildInNamespace(ctx context.Context, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b fakeBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b fakeBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}

type recordingNamespacedBackend struct {
	buildNamespace   string
	queryNamespace   string
	explainNamespace string
	buildErr         error
	buildCalls       int
}

func (b *recordingNamespacedBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "legacy"}}, nil
}

func (b *recordingNamespacedBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "legacy"}}, nil
}

func (b *recordingNamespacedBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "legacy"}}, nil
}

func (b *recordingNamespacedBackend) BuildInNamespace(_ context.Context, namespace string) (kag.Response, error) {
	b.buildNamespace = namespace
	b.buildCalls++
	if b.buildErr != nil {
		return kag.Response{}, b.buildErr
	}
	return kag.Response{Data: map[string]any{"mode": "namespaced", "namespace": namespace}}, nil
}

func (b *recordingNamespacedBackend) QueryInNamespace(_ context.Context, namespace, _ string) (kag.Response, error) {
	b.queryNamespace = namespace
	return kag.Response{Data: map[string]any{"answer": "namespaced", "namespace": namespace}}, nil
}

func (b *recordingNamespacedBackend) ExplainInNamespace(_ context.Context, namespace, _ string) (kag.Response, error) {
	b.explainNamespace = namespace
	return kag.Response{Data: map[string]any{"answer": "namespaced", "namespace": namespace}}, nil
}

type failingBackend struct{}

func (failingBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{}, nil
}

func (failingBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (failingBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (b failingBackend) BuildInNamespace(ctx context.Context, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b failingBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b failingBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}

var errFakeUnavailable = &fakeError{"fake unavailable"}

type buildFailingBackend struct{}

func (buildFailingBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (buildFailingBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (buildFailingBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (b buildFailingBackend) BuildInNamespace(ctx context.Context, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b buildFailingBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b buildFailingBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}

type fakeError struct {
	message string
}

func (e *fakeError) Error() string {
	return e.message
}
