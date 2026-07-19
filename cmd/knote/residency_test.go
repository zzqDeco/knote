package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/residency"
)

func TestPermissionedResidencyBoundaryAuthorizesTrustedLocalBoundaries(t *testing.T) {
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-residency")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.AuthorizeKAGProcessing(ctx, "kag.query"); err != nil {
		t.Fatalf("KAG processing: %v", err)
	}
	if err := boundary.AuthorizeTelemetryStore(ctx); err != nil {
		t.Fatalf("telemetry storage: %v", err)
	}
	scope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: authorization.TenantID, Region: boundary.Region(),
	}
	if err := boundary.AuthorizeAuditStore(ctx, scope); err != nil {
		t.Fatalf("audit storage: %v", err)
	}
	if err := boundary.AuthorizeConnectorEgress(ctx, "connector-local"); err != nil {
		t.Fatalf("connector egress: %v", err)
	}
	if err := boundary.AuthorizeBackupStore(ctx); err != nil {
		t.Fatalf("backup storage: %v", err)
	}
}

func TestPermissionedResidencyBoundaryFailsClosed(t *testing.T) {
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.AuthorizeKAGProcessing(context.Background(), "kag.query"); !errors.Is(err, residency.ErrDenied) {
		t.Fatalf("missing authorization error = %v", err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-residency")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	crossTenant := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: "tenant-other", Region: boundary.Region(),
	}
	if err := boundary.AuthorizeAuditStore(ctx, crossTenant); !errors.Is(err, residency.ErrDenied) {
		t.Fatalf("cross-tenant audit error = %v", err)
	}
}

func TestPermissionedResidencyBoundaryRejectsDisallowedDestination(t *testing.T) {
	t.Setenv(residencyProcessingRegionsEnv, "eu-west")
	t.Setenv(residencyKAGRegionEnv, "us-east")
	if _, err := newPermissionedResidencyBoundary(); err == nil {
		t.Fatal("disallowed KAG destination was accepted")
	}
}

func TestPermissionedResidencyBoundaryRejectsDisallowedConnectorAndBackupDestinations(t *testing.T) {
	t.Run("connector egress", func(t *testing.T) {
		t.Setenv(residencyEgressRegionsEnv, "local")
		t.Setenv(residencyConnectorEgressRegionEnv, "eu-west")
		if _, err := newPermissionedResidencyBoundary(); err == nil {
			t.Fatal("disallowed connector egress destination was accepted")
		}
	})
	t.Run("backup", func(t *testing.T) {
		t.Setenv(residencyStorageRegionsEnv, "local")
		t.Setenv(residencyBackupRegionEnv, "eu-west")
		if _, err := newPermissionedResidencyBoundary(); err == nil {
			t.Fatal("disallowed backup destination was accepted")
		}
	})
}

func TestPermissionedResidencyBoundaryAllowsDenyAllEgressPolicy(t *testing.T) {
	t.Setenv(residencyEgressRegionsEnv, "none")
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatalf("initialize deny-all egress policy: %v", err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-residency-deny-all-egress")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = boundary.WithConnectorEgress(ctx, "connector-denied", func() error {
		called = true
		return nil
	})
	if !errors.Is(err, residency.ErrDenied) {
		t.Fatalf("connector egress error = %v, want %v", err, residency.ErrDenied)
	}
	if called {
		t.Fatal("connector egress callback ran under deny-all policy")
	}
}

func TestPermissionedResidencyBoundaryChecksBeforeConnectorOrBackupBytes(t *testing.T) {
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	called := false
	write := func() error {
		called = true
		return nil
	}
	if err := boundary.WithConnectorEgress(context.Background(), "connector-denied", write); !errors.Is(err, residency.ErrDenied) {
		t.Fatalf("connector denial error = %v", err)
	}
	if called {
		t.Fatal("connector egress callback ran before residency approval")
	}
	if err := boundary.WithBackupStore(context.Background(), write); !errors.Is(err, residency.ErrDenied) {
		t.Fatalf("backup denial error = %v", err)
	}
	if called {
		t.Fatal("backup callback ran before residency approval")
	}

	authorization := fixture.Authorization(fixture.Alice, "session-residency-callback")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.WithConnectorEgress(ctx, "connector-local", write); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("approved connector egress callback did not run")
	}
}

func TestPermissionedResidencyBoundaryRecordsContentFreeViolations(t *testing.T) {
	boundary, err := newPermissionedResidencyBoundary()
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.Authorization(fixture.Alice, "session-residency-violation")
	ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	scope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: authorization.TenantID, Region: boundary.Region(),
	}
	if err := boundary.authorizeScope(
		ctx, scope, protocol.ResidencyProcess, protocol.ResidencyProtectedContent, "eu-west",
	); !errors.Is(err, residency.ErrDenied) {
		t.Fatalf("disallowed processing error = %v", err)
	}
	violations := boundary.Violations(authorization.TenantID)
	if len(violations) != 1 || violations[0].DestinationRegion != "eu-west" ||
		violations[0].ReasonCode != "policy-denied" {
		t.Fatalf("residency violations = %+v", violations)
	}
	if other := boundary.Violations("tenant-other"); len(other) != 0 {
		t.Fatalf("cross-tenant residency violations = %+v", other)
	}
}
