package versioned

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestDerivedSummaryMaterializationPreservesLocalCompatibility(t *testing.T) {
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "# Intro\n\nLocal summary content.\n"
	service := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: fakeBackend{}, Mode: ModeFake})

	if _, err := service.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	projection, metadata, summary := derivedMaterializationResult(t, repo)
	if got, want := metadata.ContentDigest, protocol.NewContentDigest(summary.Text); got != want {
		t.Fatalf("summary content digest = %s, want %s", got, want)
	}
	record := metadata.DerivedArtifactSecurity
	if record == nil || record.PrincipalID != "local" || record.AuthorizationModelID != "local-model-v1" ||
		record.IdentityWatermark != "local-identity-v1" || record.ACLWatermark != metadata.Versions.ACL ||
		record.ProjectionWatermark != projection.Version {
		t.Fatalf("nonpermissioned derived security changed compatibility: %#v", record)
	}
}

func TestDerivedSummaryMaterializationUsesTrustedAuthorizationContext(t *testing.T) {
	permissionedRepo := newMemoryRepo()
	permissionedRepo.sources["sources/intro.md"] = "# Intro\n\nPermissioned summary content.\n"
	scope, aclVersion := derivedMaterializationScope(t, permissionedRepo)
	authorization := derivedMaterializationAuthorization(scope, aclVersion)
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	service := New(Options{
		Workspace: permissionedRepo.config.Workspace,
		Repo:      permissionedRepo, Backend: fakeBackend{}, Mode: ModeFake,
	})
	first, err := service.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	projection, metadata, summary := derivedMaterializationResult(t, permissionedRepo)
	if metadata.ContentDigest != protocol.NewContentDigest(summary.Text) {
		t.Fatalf("permissioned summary digest does not match body: %s", metadata.ContentDigest)
	}
	if metadata.DerivedArtifactSecurity == nil {
		t.Fatal("permissioned summary omitted its security record")
	}
	if err := metadata.DerivedArtifactSecurity.ValidateFor(
		authorization, metadata.SecurityDomain, projection.Version,
	); err != nil {
		t.Fatalf("permissioned summary security: %v", err)
	}
	second, err := service.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.BundleManifest, second.BundleManifest) {
		t.Fatal("identical trusted authorization produced a different artifact bundle")
	}

	localRepo := newMemoryRepo()
	localRepo.sources["sources/intro.md"] = permissionedRepo.sources["sources/intro.md"]
	localService := New(Options{Workspace: localRepo.config.Workspace, Repo: localRepo, Backend: fakeBackend{}, Mode: ModeFake})
	if _, err := localService.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	localProjection, _, _ := derivedMaterializationResult(t, localRepo)
	if localProjection.Version == projection.Version {
		t.Fatal("principal-bound and local security records reused one projection version")
	}
}

func TestDerivedSummaryMaterializationRejectsTrustedScopeDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*protocol.AuthorizationContext)
	}{
		{name: "tenant", mutate: func(auth *protocol.AuthorizationContext) { auth.TenantID = "other" }},
		{name: "knowledge base", mutate: func(auth *protocol.AuthorizationContext) { auth.KnowledgeBaseID = "other" }},
		{name: "ACL", mutate: func(auth *protocol.AuthorizationContext) { auth.ACLWatermark = "acl-other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newMemoryRepo()
			repo.sources["sources/intro.md"] = "body"
			scope, aclVersion := derivedMaterializationScope(t, repo)
			authorization := derivedMaterializationAuthorization(scope, aclVersion)
			test.mutate(&authorization)
			ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
			if err != nil {
				t.Fatal(err)
			}
			service := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: fakeBackend{}, Mode: ModeFake})
			if _, err := service.Build(ctx); err == nil || !strings.Contains(err.Error(), "does not match projection scope") {
				t.Fatalf("scope drift error = %v", err)
			}
			if repo.writeArtifactsCalls != 0 {
				t.Fatalf("scope drift wrote artifacts %d time(s)", repo.writeArtifactsCalls)
			}
		})
	}
}

func derivedMaterializationScope(t *testing.T, repo *memoryRepo) (catalog.Scope, string) {
	t.Helper()
	namespace, err := effectiveKAGNamespace(repo.config.Workspace, repo.config)
	if err != nil {
		t.Fatal(err)
	}
	scope := catalog.Scope{TenantID: localTenantID, KnowledgeBaseID: canonicalNamespace(namespace)}
	return scope, canonicalACLVersion(scope)
}

func derivedMaterializationAuthorization(
	scope catalog.Scope,
	aclVersion string,
) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:  protocol.SecurityContractVersion,
		TenantID: scope.TenantID, KnowledgeBaseID: scope.KnowledgeBaseID,
		PrincipalID: "permissioned-user", SessionID: "materialize-session", RequestID: "materialize-request",
		AgentID: "materialize-agent", TaskID: "materialize-task",
		AuthorizationModelID: "permissioned-model-v1", IdentityWatermark: "permissioned-identity-v1",
		ACLWatermark: aclVersion, Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func derivedMaterializationResult(
	t *testing.T,
	repo *memoryRepo,
) (catalog.Projection, catalog.ResourceMetadata, protocol.Summary) {
	t.Helper()
	var projection catalog.Projection
	if err := json.Unmarshal(repo.artifacts.ProjectionJSON, &projection); err != nil {
		t.Fatal(err)
	}
	for _, metadata := range projection.Resources {
		if metadata.Type == protocol.ResourceDerivedArtifact {
			if len(repo.artifacts.Summaries) != 1 || repo.artifacts.Summaries[0].SummaryID != string(metadata.ResourceID) {
				t.Fatalf("derived summary body does not match projection metadata: %#v", repo.artifacts.Summaries)
			}
			return projection, metadata, repo.artifacts.Summaries[0]
		}
	}
	t.Fatal("projection has no derived artifact metadata")
	return catalog.Projection{}, catalog.ResourceMetadata{}, protocol.Summary{}
}
