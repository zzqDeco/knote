package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestStoreImplementsRepositoryContracts(t *testing.T) {
	var _ repository.Workspace = Store{}
	var _ repository.Sessions = Store{}
	var _ repository.Versions = Store{}
}

func TestConfigSourcesAndSafeRead(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)

	cfg := repository.Config{
		Workspace: workspace,
		Permissions: repository.PermissionConfig{
			BuildDefault: "confirm",
			GitDefault:   "allow-once",
		},
		KAG: repository.KAGConfig{
			AdapterPath: "adapters/kag/knote_kag_adapter.py",
			Host:        "http://127.0.0.1:8887",
			Fake:        true,
			ProjectID:   "1",
			Namespace:   "KnoteKB",
			Language:    "en",
			RuntimeDir:  ".knote/kag-runtime",
		},
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}
	if err := store.SaveConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Workspace != workspace || loaded.KAG.Host != cfg.KAG.Host || !loaded.KAG.Fake {
		t.Fatalf("config round trip lost fields: %+v", loaded)
	}

	mustWrite(t, filepath.Join(workspace, "sources", "b.txt"), "second\n")
	mustWrite(t, filepath.Join(workspace, "sources", "a.md"), "first\n")
	mustWrite(t, filepath.Join(workspace, "sources", "ignored.pdf"), "ignored\n")
	sources, err := store.ListSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := sourcePaths(sources); strings.Join(got, ",") != "sources/a.md,sources/b.txt" {
		t.Fatalf("unexpected sources: %+v", sources)
	}
	data, err := store.ReadSource(ctx, "sources/a.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\n" {
		t.Fatalf("unexpected source content: %q", data)
	}
	if _, err := store.ReadSource(ctx, "../outside.md"); err == nil {
		t.Fatal("path traversal should be rejected")
	}
	if _, err := store.ReadSource(ctx, ".knote/config.yaml"); err == nil {
		t.Fatal("non-source workspace files should be rejected")
	}
	outside := filepath.Join(t.TempDir(), "outside.md")
	mustWrite(t, outside, "secret\n")
	if err := os.Symlink(outside, filepath.Join(workspace, "sources", "linked.md")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.ReadSource(ctx, "sources/linked.md"); err == nil {
		t.Fatal("source symlink resolving outside the workspace should be rejected")
	}
}

func TestSessionsAppendLoadAndList(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir())
	event := protocol.NewEvent(protocol.EventUserMessage, "sess_one", "hello", nil)

	if err := store.Append(ctx, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx, "sess_one")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Message != "hello" {
		t.Fatalf("unexpected loaded events: %+v", loaded)
	}
	summaries, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].ID != "sess_one" || summaries[0].EventCount != 1 {
		t.Fatalf("unexpected session summaries: %+v", summaries)
	}
}

func TestArtifactsEvalAndGate(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "stable\n")

	manifest := protocol.ArtifactManifest{
		Version:      1,
		Workspace:    workspace,
		GeneratedAt:  time.Now().UTC(),
		SourceCount:  1,
		SummaryCount: 1,
	}
	if err := store.WriteArtifacts(ctx, repository.ArtifactSet{
		Manifest: manifest,
		Summaries: []protocol.Summary{
			{SummaryID: "b", Text: "second"},
			{SummaryID: "a", Text: "first"},
		},
		SchemaYAML:  "version: 1\n",
		BuildReport: "# report\n",
	}); err != nil {
		t.Fatal(err)
	}
	readManifest, err := store.ReadManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if readManifest.SourceCount != 1 || readManifest.SummaryCount != 1 {
		t.Fatalf("unexpected manifest: %+v", readManifest)
	}
	summaries, err := store.ReadSummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 || summaries[0].SummaryID != "a" {
		t.Fatalf("summaries should be sorted and readable: %+v", summaries)
	}

	if err := store.WriteEval(ctx, repository.EvalReport{
		Results: []repository.EvalResult{
			{ID: "smoke", Question: "What is here?", Answer: "stable", KnowledgeHash: "stale-hash"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.EvalGate(ctx); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "changed\n")
	if err := store.EvalGate(ctx); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale eval should block release gate, got %v", err)
	}
}

func TestVersionsContract(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "initial\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	status, err := store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Branch == "" || status.Dirty {
		t.Fatalf("unexpected clean status: %+v", status)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "updated\n")
	diff, err := store.Diff(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "sources/intro.md") {
		t.Fatalf("diff missing knowledge path:\n%s", diff)
	}
	commit, err := store.Commit(ctx, "knowledge update")
	if err != nil {
		t.Fatal(err)
	}
	if commit.Hash == "" || !strings.Contains(commit.Summary, "knowledge update") {
		t.Fatalf("unexpected commit result: %+v", commit)
	}
	versions, err := store.Versions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Subject != "knowledge update" || !versions[0].Current {
		t.Fatalf("unexpected versions: %+v", versions)
	}
	if err := store.Tag(ctx, "v0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkout(ctx, "HEAD", repository.CheckoutOptions{}); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "dirty\n")
	if err := store.Checkout(ctx, "HEAD", repository.CheckoutOptions{}); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("dirty checkout should require confirmation, got %v", err)
	}
}

func sourcePaths(sources []repository.Source) []string {
	paths := make([]string, 0, len(sources))
	for _, source := range sources {
		paths = append(paths, source.Path)
	}
	return paths
}

func initRepo(t *testing.T) string {
	t.Helper()
	workspace := t.TempDir()
	runGit(t, workspace, "init")
	runGit(t, workspace, "config", "user.email", "knote@example.com")
	runGit(t, workspace, "config", "user.name", "knote")
	mustWrite(t, filepath.Join(workspace, ".gitignore"), ".knote/sessions/\n")
	return workspace
}

func mustWrite(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}
