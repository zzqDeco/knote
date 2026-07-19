package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestPermissionedAuditRecorderChainsContentFreeReferences(t *testing.T) {
	t.Setenv(permissionedAuditPathEnv, filepath.Join(t.TempDir(), "audit"))
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := newPermissionedAuditRecorder(t.TempDir(), boundary)
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-audit")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	first, err := recorder.Record(ctx, "governance.view", protocol.DecisionAllow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := recorder.Record(ctx, "tool.query", protocol.DecisionDeny)
	if err != nil {
		t.Fatal(err)
	}
	if first.TenantID != authorization.TenantID || second.PreviousDigest != first.RecordDigest {
		t.Fatalf("audit chain = first %+v, second %+v", first, second)
	}
	scope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: authorization.TenantID, Region: boundary.Region(),
	}
	references, err := recorder.store.ListReferences(ctx, scope, func(context.Context, protocol.TenantScope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 2 || references[0] != first || references[1] != second {
		t.Fatalf("audit references = %+v", references)
	}
}

func TestPermissionedAuditRootDefaultsOutsideWorkspace(t *testing.T) {
	workspace := t.TempDir()
	configHome := t.TempDir()
	t.Setenv(permissionedAuditPathEnv, "")
	t.Setenv("HOME", configHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(configHome, "xdg"))
	t.Setenv("APPDATA", filepath.Join(configHome, "appdata"))

	root, err := permissionedAuditRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	insideWorkspace, err := pathWithinDirectory(workspace, root)
	if err != nil {
		t.Fatal(err)
	}
	if insideWorkspace {
		t.Fatalf("default audit root %q is inside workspace %q", root, workspace)
	}
	if !strings.HasPrefix(root, configHome+string(filepath.Separator)) {
		t.Fatalf("default audit root %q is outside user config home %q", root, configHome)
	}
	again, err := permissionedAuditRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if again != root {
		t.Fatalf("default audit root changed: first %q, second %q", root, again)
	}

	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := newPermissionedAuditRecorder(workspace, boundary)
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-default-audit-root")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Record(ctx, "governance.view", protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".knote", "audit")); !os.IsNotExist(err) {
		t.Fatalf("workspace audit path exists after default write: %v", err)
	}
}
