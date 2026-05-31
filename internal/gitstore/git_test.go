package gitstore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionsIncludeCurrentAndTags(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial knowledge")
	runGit(t, workspace, "tag", "-a", "v0.0.1", "-m", "release: v0.0.1")

	versions, err := (Store{Workspace: workspace}).Versions(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected 1 version, got %+v", versions)
	}
	if !versions[0].Current || versions[0].Subject != "initial knowledge" {
		t.Fatalf("unexpected version metadata: %+v", versions[0])
	}
	if len(versions[0].Tags) != 1 || versions[0].Tags[0] != "v0.0.1" {
		t.Fatalf("tag was not parsed from decorations: %+v", versions[0])
	}
}

func TestDiffShowsTrackedAndUntrackedKnowledgeFiles(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "old\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "new\n")
	mustWrite(t, filepath.Join(workspace, "evals", "results.jsonl"), "{}\n")
	out, err := (Store{Workspace: workspace}).Diff(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "sources/intro.md") {
		t.Fatalf("diff missing tracked knowledge change:\n%s", out)
	}
	if !strings.Contains(out, "Untracked knote files") || !strings.Contains(out, "evals/results.jsonl") {
		t.Fatalf("diff missing untracked knowledge files:\n%s", out)
	}
}

func TestCommitOnlyIncludesKnowledgePaths(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "intro\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: changed\n")
	mustWrite(t, filepath.Join(workspace, "evals", "results.jsonl"), "{}\n")
	mustWrite(t, filepath.Join(workspace, "unrelated.txt"), "do not commit\n")
	runGit(t, workspace, "add", "unrelated.txt")

	if _, err := (Store{Workspace: workspace}).Commit(context.Background(), "knowledge update"); err != nil {
		t.Fatal(err)
	}
	show := runGit(t, workspace, "show", "--name-only", "--format=", "HEAD")
	if !strings.Contains(show, ".knote/config.yaml") || !strings.Contains(show, "evals/results.jsonl") {
		t.Fatalf("commit did not include knowledge paths:\n%s", show)
	}
	if strings.Contains(show, "unrelated.txt") {
		t.Fatalf("commit included unrelated staged file:\n%s", show)
	}
	cached := runGit(t, workspace, "diff", "--cached", "--name-only")
	if strings.TrimSpace(cached) != "unrelated.txt" {
		t.Fatalf("unrelated staged file should remain staged, got %q", cached)
	}
}

func TestTagRequiresCleanWorkspace(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "intro\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	if _, err := (Store{Workspace: workspace}).Tag(context.Background(), "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "dirty\n")
	if _, err := (Store{Workspace: workspace}).Tag(context.Background(), "v0.1.1"); err == nil || !strings.Contains(err.Error(), "clean workspace") {
		t.Fatalf("dirty tag should be rejected, got %v", err)
	}
}

func TestCheckoutDirtyGuard(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "intro\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "dirty\n")

	store := Store{Workspace: workspace}
	if _, err := store.Checkout(context.Background(), "HEAD", false); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("dirty checkout should require confirmation, got %v", err)
	}
	if _, err := store.Checkout(context.Background(), "HEAD", true); err != nil {
		t.Fatalf("confirmed dirty checkout should be delegated to git: %v", err)
	}
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
