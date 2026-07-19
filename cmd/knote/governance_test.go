package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestGovernanceProviderUsesPermissionedAuthorizer(t *testing.T) {
	application, err := newPermissionedApplication(context.Background(), permissionedRuntimeConfig{
		Enabled: true, Fake: true, Principal: "alice",
	}, kag.Client{Fake: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if application.GovernanceAuthorizer() == nil {
		t.Fatal("fake permissioned application dropped the governance authorizer")
	}
	provider, err := newGovernanceProvider(application)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := application.AuthorizationContextProvider()(context.Background(), "session-governance")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.View(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Tenant == nil || snapshot.Tenant.Scope.TenantID != authorization.TenantID {
		t.Fatalf("governance snapshot tenant = %+v", snapshot.Tenant)
	}
}

func TestGovernanceProviderRejectsInvalidRegion(t *testing.T) {
	t.Setenv(governanceRegionEnv, "us west")
	_, err := newPermissionedApplication(context.Background(), permissionedRuntimeConfig{
		Enabled: true, Fake: true, Principal: "alice",
	}, kag.Client{Fake: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "region") {
		t.Fatalf("invalid governance region error = %v", err)
	}
}

func TestGovernanceProviderAuditsSuccessfulViews(t *testing.T) {
	t.Setenv(permissionedAuditPathEnv, filepath.Join(t.TempDir(), "audit"))
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := newPermissionedAuditRecorder(t.TempDir(), boundary)
	if err != nil {
		t.Fatal(err)
	}
	application, err := newPermissionedApplication(context.Background(), permissionedRuntimeConfig{
		Enabled: true, Fake: true, Principal: "alice", residency: boundary, audit: recorder,
	}, kag.Client{Fake: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newGovernanceProvider(application)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := application.AuthorizationContextProvider()(context.Background(), "session-governance-audit")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.View(ctx, authorization); err != nil {
		t.Fatal(err)
	}
	second, err := provider.View(ctx, authorization)
	if err != nil {
		t.Fatal(err)
	}
	if second.Audit == nil || second.Audit.Total != 1 || len(second.Audit.References) != 1 ||
		second.Audit.References[0].Action != "governance.view" {
		t.Fatalf("governance audit projection = %+v", second.Audit)
	}
}
