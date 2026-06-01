package knowledge

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/kag"
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

func TestKnowledgePackageImportBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list knowledge imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/tui",
		"/internal/runtime",
		"/internal/repository/local",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("knowledge imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

type memoryRepo struct {
	config    repository.Config
	sources   map[string]string
	artifacts repository.ArtifactSet
	eval      repository.EvalReport
	hash      string
}

func newMemoryRepo() *memoryRepo {
	return &memoryRepo{
		config:  repository.Config{Workspace: "/memory"},
		sources: map[string]string{},
		hash:    "current-knowledge-hash",
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
		out = append(out, repository.Source{
			Path:    path,
			Size:    int64(len(content)),
			ModTime: time.Unix(1, 0).UTC(),
		})
	}
	return out, nil
}

func (r *memoryRepo) ReadSource(_ context.Context, path string) ([]byte, error) {
	return []byte(r.sources[path]), nil
}

func (r *memoryRepo) WriteArtifacts(_ context.Context, set repository.ArtifactSet) error {
	r.artifacts = set
	return nil
}

func (r *memoryRepo) ReadManifest(context.Context) (protocol.ArtifactManifest, error) {
	return r.artifacts.Manifest, nil
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

var errFakeUnavailable = &fakeError{"fake unavailable"}

type fakeError struct {
	message string
}

func (e *fakeError) Error() string {
	return e.message
}
