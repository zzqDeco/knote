package local

import (
	"context"
	"path/filepath"
	"testing"
)

func TestGitClientDirtyIgnoresUntrackedProjectionJournals(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "README.md"), "initial\n")
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, ".knote", "projections", "runs", "run-1", "plan.json"), "{}\n")
	if gitClientDirty(t, gitClient{workspace: workspace}, context.Background()) {
		t.Fatal("projection journals should not make the workspace dirty")
	}
}

func TestGitClientDirtyStillReportsRelevantChangesWithProjectionJournals(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "README.md"), "initial\n")
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, ".knote", "projections", "serving.json"), "{}\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "dirty\n")
	if !gitClientDirty(t, gitClient{workspace: workspace}, context.Background()) {
		t.Fatal("knowledge changes should remain dirty when projection journals are present")
	}
}

func TestGitClientDirtyDoesNotIgnoreProjectionPrefixLookalikes(t *testing.T) {
	workspace := initRepo(t)
	mustWrite(t, filepath.Join(workspace, "README.md"), "initial\n")
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, ".knote", "projections-backup", "serving.json"), "{}\n")
	if !gitClientDirty(t, gitClient{workspace: workspace}, context.Background()) {
		t.Fatal("similarly named non-runtime paths should make the workspace dirty")
	}
}
