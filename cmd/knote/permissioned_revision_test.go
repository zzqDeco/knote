package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestPermissionedRevisionStateBindsAuthorizationContext(t *testing.T) {
	state, config, scope := newTestPermissionedRevisionState(t)
	current, err := state.currentForScope(context.Background(), config, scope)
	if err != nil {
		t.Fatal(err)
	}
	authorization := testRevisionAuthorization(current, scope)
	got, err := state.begin(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if got != current {
		t.Fatalf("read revision = %+v, want %+v", got, current)
	}

	authorization.ACLWatermark = "acl_other"
	if _, err := state.begin(context.Background(), authorization); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("mismatched authorization context error = %v", err)
	}
	scope.ACLWatermark = "acl_other"
	if _, err := state.currentForScope(context.Background(), config, scope); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("mismatched selected bundle scope error = %v", err)
	}
}

func TestPermissionedRevisionStateRejectsRevisionChangeDuringRead(t *testing.T) {
	state, _, scope := newTestPermissionedRevisionState(t)
	current, err := state.publisher.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	readRevision, err := state.begin(context.Background(), testRevisionAuthorization(current, scope))
	if err != nil {
		t.Fatal(err)
	}
	advanceTestPermissionedRevision(t, state, authz.AuthorizationRevision{
		StoreID: current.StoreID, AuthorizationModelID: current.AuthorizationModelID,
		IdentityWatermark: current.IdentityWatermark, ACLWatermark: current.ACLWatermark,
		Epoch: current.Epoch + 1,
	})
	if err := state.finish(context.Background(), readRevision, nil); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("revision drift error = %v", err)
	}
}

func TestPermissionedRevisionStateRejectsProjectionDrift(t *testing.T) {
	state, config, scope := newTestPermissionedRevisionState(t)
	ctx := context.Background()
	current, err := state.currentForScope(ctx, config, scope)
	if err != nil {
		t.Fatal(err)
	}
	drifted := scope
	drifted.ProjectionVersion = "projection_v2"
	if _, err := state.currentForScope(ctx, config, drifted); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("projection drift context error = %v", err)
	}
	state.scopeProvider = func(context.Context) (authorized.ArtifactAuthorizationScope, error) {
		return drifted, nil
	}
	if _, err := state.begin(ctx, testRevisionAuthorization(current, scope)); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("projection drift read error = %v", err)
	}
	if err := state.finish(ctx, current, nil); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("projection drift finish error = %v", err)
	}
}

func TestPermissionedRevisionStateRefreshesScopeAfterArtifactChange(t *testing.T) {
	state, config, scope := newTestPermissionedRevisionState(t)
	ctx := context.Background()
	nextScope := scope
	state.scopeProvider = func(context.Context) (authorized.ArtifactAuthorizationScope, error) {
		return nextScope, nil
	}
	base, err := state.currentForScope(ctx, config, scope)
	if err != nil {
		t.Fatal(err)
	}

	nextScope.ProjectionVersion = "projection_v2"
	if err := state.refreshScope(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := state.currentForScope(ctx, config, nextScope)
	if err != nil {
		t.Fatal(err)
	}
	if current.Epoch != base.Epoch+1 || current.ACLWatermark != base.ACLWatermark {
		t.Fatalf("refreshed revision = %+v, want epoch %d with unchanged ACL", current, base.Epoch+1)
	}
	if err := state.finish(ctx, base, nil); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("in-flight pre-refresh revision error = %v", err)
	}
	if _, err := state.begin(ctx, testRevisionAuthorization(current, nextScope)); err != nil {
		t.Fatalf("refreshed scope remained unavailable: %v", err)
	}
}

func TestPermissionedRevisionStateRequiresNewRevisionForRegrant(t *testing.T) {
	state, _, _ := newTestPermissionedRevisionState(t)
	ctx := context.Background()
	base, err := state.publisher.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := protocol.NewStableResourceID("tenant_a", "kb_a", protocol.ResourceChunk, "chunk_a")
	if err != nil {
		t.Fatal(err)
	}
	revoked := base
	revoked.ACLWatermark = "acl_v2"
	revoked.Epoch++
	revoke := authz.RevocationTransition{
		BaseRevision: base, TargetRevision: revoked, RetiredResourceIDs: []protocol.ResourceID{resourceID},
	}
	if err := state.lifecycle.Prepare(ctx, revoke); err != nil {
		t.Fatal(err)
	}
	advanceTestPermissionedRevision(t, state, revoked)
	if err := state.lifecycle.Commit(ctx, revoke); err != nil {
		t.Fatal(err)
	}
	if err := state.finish(ctx, revoked, []protocol.ResourceID{resourceID}); !errors.Is(err, errPermissionedRevisionUnavailable) {
		t.Fatalf("revoked resource error = %v", err)
	}

	regranted := revoked
	regranted.ACLWatermark = "acl_v3"
	regranted.Epoch++
	regrant := authz.RevocationTransition{
		BaseRevision: revoked, TargetRevision: regranted, GrantedResourceIDs: []protocol.ResourceID{resourceID},
	}
	if err := state.lifecycle.Prepare(ctx, regrant); err != nil {
		t.Fatal(err)
	}
	advanceTestPermissionedRevision(t, state, regranted)
	if err := state.lifecycle.Commit(ctx, regrant); err != nil {
		t.Fatal(err)
	}
	if err := state.finish(ctx, regranted, []protocol.ResourceID{resourceID}); err != nil {
		t.Fatalf("regranted resource remained unavailable: %v", err)
	}
}

func newTestPermissionedRevisionState(
	t *testing.T,
) (*permissionedRevisionState, permissionedRuntimeConfig, authorized.ArtifactAuthorizationScope) {
	t.Helper()
	config := permissionedRuntimeConfig{
		IdentityWatermark: "identity_v1",
		OpenFGA: authz.OpenFGAConfig{
			StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", AuthorizationModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
		},
	}
	scope := authorized.ArtifactAuthorizationScope{
		TenantID: "tenant_a", KnowledgeBaseID: "kb_a", ACLWatermark: "acl_v1", ProjectionVersion: "projection_v1",
	}
	cache, err := authorized.NewQueryCache(4)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newPermissionedRevisionState(
		config,
		scope,
		cache,
		func(context.Context) (authorized.ArtifactAuthorizationScope, error) { return scope, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return state, config, scope
}

func testRevisionAuthorization(
	revision authz.AuthorizationRevision,
	scope authorized.ArtifactAuthorizationScope,
) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:  protocol.SecurityContractVersion,
		TenantID: scope.TenantID, KnowledgeBaseID: scope.KnowledgeBaseID,
		PrincipalID: "alice", SessionID: "session_a", RequestID: "request_a",
		AuthorizationModelID: revision.AuthorizationModelID,
		IdentityWatermark:    revision.IdentityWatermark, ACLWatermark: revision.ACLWatermark,
		Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func advanceTestPermissionedRevision(
	t *testing.T,
	state *permissionedRevisionState,
	target authz.AuthorizationRevision,
) {
	t.Helper()
	ctx := context.Background()
	base, err := state.publisher.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := state.publisher.Reserve(ctx, base, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.publisher.Publish(ctx, reservation); err != nil {
		t.Fatal(err)
	}
}
