package main

import (
	"context"
	"testing"

	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestPermissionedAuditRecorderChainsContentFreeReferences(t *testing.T) {
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
