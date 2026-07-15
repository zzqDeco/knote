package local

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestCommitIncludesOnlySelectedArtifactBundle(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "README.md"), "initial\n")
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	store := New(workspace)
	selected := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "selected-content")
	if err := store.WriteArtifacts(ctx, selected); err != nil {
		t.Fatal(err)
	}
	if _, err := (gitClient{workspace: workspace}).Commit(ctx, "selected"); err != nil {
		t.Fatal(err)
	}
	assertGitTreeContains(t, workspace, selected.BundleManifest.ProjectionID)

	failed := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "failed-secret-content")
	if err := store.StageArtifacts(ctx, failed); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "next.md"), "committable source\n")
	if _, err := (gitClient{workspace: workspace}).Commit(ctx, "source only"); err != nil {
		t.Fatal(err)
	}
	if (gitClient{workspace: workspace}).Dirty(ctx) {
		t.Fatal("failed staged bundle should not leave the committed workspace dirty")
	}
	assertGitTreeContains(t, workspace, selected.BundleManifest.ProjectionID)
	assertGitTreeOmits(t, workspace, failed.BundleManifest.ProjectionID, "failed-secret-content")
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "bundles", failed.BundleManifest.ProjectionID)); !os.IsNotExist(err) {
		t.Fatalf("failed candidate remained after commit: %v", err)
	}

	successor := testBundleArtifactSet(t, "prj_cccccccccccccccccccccccccccccccc", "successor-content")
	if err := store.WriteArtifacts(ctx, successor); err != nil {
		t.Fatal(err)
	}
	if _, err := (gitClient{workspace: workspace}).Commit(ctx, "successor"); err != nil {
		t.Fatal(err)
	}
	if (gitClient{workspace: workspace}).Dirty(ctx) {
		t.Fatal("prior selected bundles should not leave the committed workspace dirty")
	}
	assertGitTreeContains(t, workspace, successor.BundleManifest.ProjectionID)
	assertGitTreeOmits(t, workspace, selected.BundleManifest.ProjectionID, "selected-content")
	assertGitTreeOmits(t, workspace, failed.BundleManifest.ProjectionID, "failed-secret-content")

	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != successor.BundleManifest.ProjectionID {
		t.Fatalf("current projection = %q, want %q", current.ProjectionID, successor.BundleManifest.ProjectionID)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "bundles", selected.BundleManifest.ProjectionID)); !os.IsNotExist(err) {
		t.Fatalf("prior selected bundle remained after successor commit: %v", err)
	}
}

func TestCommitPrunesUnpublishedFirstArtifactBundleWithoutCurrentPointer(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "initial\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	store := New(workspace)
	candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "unpublished-secret-content")
	if err := store.StageArtifacts(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "updated\n")
	if _, err := store.Commit(ctx, "source update"); err != nil {
		t.Fatal(err)
	}
	if (gitClient{workspace: workspace}).Dirty(ctx) {
		t.Fatal("unpublished first bundle left the committed workspace dirty")
	}
	if _, err := store.ReadCurrentArtifactManifest(ctx); !errors.Is(err, repository.ErrArtifactCurrentNotFound) {
		t.Fatalf("current artifact manifest error = %v, want ErrArtifactCurrentNotFound", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "bundles", candidate.BundleManifest.ProjectionID)); !os.IsNotExist(err) {
		t.Fatalf("unpublished candidate remained after commit: %v", err)
	}
	show := runGit(t, workspace, "show", "--name-only", "--format=", "HEAD")
	if !strings.Contains(show, "sources/intro.md") {
		t.Fatalf("source update was not committed:\n%s", show)
	}
	assertGitTreeOmits(t, workspace, candidate.BundleManifest.ProjectionID, "unpublished-secret-content")
}

func TestCommitPreservesLegacyArtifactsWhilePruningUnpublishedBundle(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "initial\n")

	manifest := protocol.ArtifactManifest{Version: 1, Workspace: "legacy", SummaryCount: 1}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	summaryData, err := json.Marshal(protocol.Summary{
		SummaryID:        "legacy-summary",
		Text:             "legacy-visible-content",
		EvidenceChunkIDs: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "artifacts", "manifest.json"), string(manifestData)+"\n")
	mustWrite(t, filepath.Join(workspace, "artifacts", "summaries.jsonl"), string(summaryData)+"\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "legacy artifacts")

	store := New(workspace)
	candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "unpublished-secret-content")
	if err := store.StageArtifacts(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "updated\n")
	if _, err := store.Commit(ctx, "source update"); err != nil {
		t.Fatal(err)
	}

	tree := runGit(t, workspace, "ls-tree", "-r", "--name-only", "HEAD")
	for _, path := range []string{"artifacts/manifest.json", "artifacts/summaries.jsonl"} {
		if !strings.Contains(tree, path) {
			t.Fatalf("Git tree dropped legacy artifact %q:\n%s", path, tree)
		}
	}
	assertGitTreeOmits(t, workspace, candidate.BundleManifest.ProjectionID, "unpublished-secret-content")
	if (gitClient{workspace: workspace}).Dirty(ctx) {
		t.Fatal("preserved legacy artifacts left the committed workspace dirty")
	}
	readManifest, err := store.ReadManifest(ctx)
	if err != nil || readManifest.Workspace != "legacy" {
		t.Fatalf("legacy manifest unavailable after commit: manifest=%+v err=%v", readManifest, err)
	}
	summaries, err := store.ReadSummaries(ctx)
	if err != nil || len(summaries) != 1 || summaries[0].Text != "legacy-visible-content" {
		t.Fatalf("legacy summaries unavailable after commit: summaries=%+v err=%v", summaries, err)
	}
}

func assertGitTreeContains(t *testing.T, workspace, projectionID string) {
	t.Helper()
	tree := runGit(t, workspace, "ls-tree", "-r", "--name-only", "HEAD")
	want := "artifacts/bundles/" + projectionID + "/manifest.json"
	if !strings.Contains(tree, want) {
		t.Fatalf("Git tree does not contain selected bundle %q:\n%s", want, tree)
	}
}

func assertGitTreeOmits(t *testing.T, workspace, projectionID, protectedContent string) {
	t.Helper()
	tree := runGit(t, workspace, "ls-tree", "-r", "--name-only", "HEAD")
	if strings.Contains(tree, projectionID) {
		t.Fatalf("Git tree contains stale bundle %q:\n%s", projectionID, tree)
	}
	cmd := exec.Command("git", "grep", "-I", "-n", "-e", protectedContent, "HEAD", "--", "artifacts")
	cmd.Dir = workspace
	contents, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Git tree exposes protected content %q:\n%s", protectedContent, contents)
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("inspect protected Git content: %v: %s", err, contents)
	}
}
