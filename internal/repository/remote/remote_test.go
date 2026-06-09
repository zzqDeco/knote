package remote

import (
	"context"
	"errors"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestStoreImplementsRepositoryContracts(t *testing.T) {
	var _ repository.Workspace = Store{}
	var _ repository.Sessions = Store{}
	var _ repository.Versions = Store{}
}

func TestRemoteStoreReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	store := New(Config{
		Provider:       ProviderGitHub,
		BaseURL:        "https://github.com",
		Owner:          "zzqDeco",
		Repository:     "knote",
		DefaultBaseRef: "main",
		AuthRef:        "env:GITHUB_TOKEN",
	})

	checks := []struct {
		name string
		run  func() error
	}{
		{name: "Config", run: func() error { _, err := store.Config(ctx); return err }},
		{name: "SaveConfig", run: func() error { return store.SaveConfig(ctx, repository.Config{}) }},
		{name: "ListSources", run: func() error { _, err := store.ListSources(ctx); return err }},
		{name: "ReadSource", run: func() error { _, err := store.ReadSource(ctx, "sources/a.md"); return err }},
		{name: "WriteArtifacts", run: func() error { return store.WriteArtifacts(ctx, repository.ArtifactSet{}) }},
		{name: "ReadManifest", run: func() error { _, err := store.ReadManifest(ctx); return err }},
		{name: "ReadSummaries", run: func() error { _, err := store.ReadSummaries(ctx); return err }},
		{name: "LoadQuestions", run: func() error { _, err := store.LoadQuestions(ctx); return err }},
		{name: "WriteEval", run: func() error { return store.WriteEval(ctx, repository.EvalReport{}) }},
		{name: "EvalGate", run: func() error { return store.EvalGate(ctx) }},
		{name: "Append", run: func() error { return store.Append(ctx, protocol.Event{}) }},
		{name: "Load", run: func() error { _, err := store.Load(ctx, "sess"); return err }},
		{name: "List", run: func() error { _, err := store.List(ctx, 10); return err }},
		{name: "Status", run: func() error { _, err := store.Status(ctx); return err }},
		{name: "Diff", run: func() error { _, err := store.Diff(ctx, "main"); return err }},
		{name: "Versions", run: func() error { _, err := store.Versions(ctx, 10); return err }},
		{name: "Commit", run: func() error { _, err := store.Commit(ctx, "message"); return err }},
		{name: "Tag", run: func() error { return store.Tag(ctx, "v0.1.0") }},
		{name: "Checkout", run: func() error { return store.Checkout(ctx, "main", repository.CheckoutOptions{}) }},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, repository.ErrRemoteNotImplemented) {
				t.Fatalf("expected ErrRemoteNotImplemented, got %v", err)
			}
		})
	}
}

func TestRemoteDomainTypesModelExplicitDraftFlow(t *testing.T) {
	base := Ref{Name: "main", SHA: "abc123"}
	draft := DraftTree{
		ID:      "draft-1",
		BaseRef: base,
		Files: []DraftFile{{
			Path:        "sources/intro.md",
			ContentHash: "sha256:doc",
			Operation:   DraftUpsert,
		}},
	}
	proposal := CommitProposal{
		Branch:  "feature/kb-update",
		Message: "knowledge update",
		Tree:    draft,
	}
	request := MergeRequest{
		ID:        "42",
		URL:       "https://example.test/pulls/42",
		SourceRef: Ref{Name: proposal.Branch, SHA: "def456"},
		TargetRef: base,
		State:     MergeRequestDraft,
	}
	release := Release{
		Tag:       "v0.1.0",
		TargetRef: request.TargetRef,
		Name:      "v0.1.0",
		URL:       "https://example.test/releases/v0.1.0",
	}

	if proposal.Tree.BaseRef != base {
		t.Fatalf("draft tree lost base ref: %+v", proposal)
	}
	if request.TargetRef.Name != "main" || request.State != MergeRequestDraft {
		t.Fatalf("merge request does not model a draft PR flow: %+v", request)
	}
	if release.TargetRef != base || release.Tag == "" {
		t.Fatalf("release does not target an explicit ref: %+v", release)
	}
}
