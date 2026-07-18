package protocol

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testAgentTaskScopeAuthority struct {
	scope                      AgentTaskScope
	currentDelegationWatermark string
	err                        error
}

func (a *testAgentTaskScopeAuthority) CurrentAgentTaskScope(
	context.Context,
	AuthorizationContext,
) (AgentTaskScope, string, error) {
	return a.scope, a.currentDelegationWatermark, a.err
}

func TestResolveCurrentAgentTaskScopeFailsClosedOnCurrentStateDrift(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 18, 8, 0, 0, 0, time.UTC)
	auth := testAuthorizationContext()
	scope := testAgentTaskScope(auth, issuedAt, issuedAt.Add(time.Hour))
	fingerprint, err := NewAgentTaskScopeFingerprint(scope)
	if err != nil {
		t.Fatal(err)
	}
	auth.AgentTaskScopeFingerprint = fingerprint
	authority := &testAgentTaskScopeAuthority{
		scope: scope, currentDelegationWatermark: scope.DelegationWatermark,
	}

	if _, err := ResolveCurrentAgentTaskScope(
		context.Background(), authority, auth, issuedAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("current scope: %v", err)
	}

	authority.currentDelegationWatermark = "delegation-v2"
	if _, err := ResolveCurrentAgentTaskScope(
		context.Background(), authority, auth, issuedAt.Add(time.Minute),
	); err == nil {
		t.Fatal("revoked delegation watermark was accepted")
	}
	authority.currentDelegationWatermark = scope.DelegationWatermark
	if _, err := ResolveCurrentAgentTaskScope(
		context.Background(), authority, auth, scope.ExpiresAt,
	); err == nil {
		t.Fatal("expired agent task scope was accepted")
	}

	authority.err = errors.New("revoked")
	if _, err := ResolveCurrentAgentTaskScope(
		context.Background(), authority, auth, issuedAt.Add(time.Minute),
	); err == nil {
		t.Fatal("unavailable current scope was accepted")
	}
	if _, err := ResolveCurrentAgentTaskScope(
		context.Background(), nil, auth, issuedAt.Add(time.Minute),
	); err == nil {
		t.Fatal("delegated authorization without an authority was accepted")
	}

	direct := testDirectAuthorizationContext()
	if scope, err := ResolveCurrentAgentTaskScope(
		context.Background(), nil, direct, issuedAt.Add(time.Minute),
	); err != nil || scope != (AgentTaskScope{}) {
		t.Fatalf("direct-user scope = %#v, %v", scope, err)
	}
}
