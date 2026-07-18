package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestGatewayBuildsTrustedAuthorizationAndFailsClosedOnIdentityChange(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	clock := newTestClock(time.Date(2026, 7, 17, 7, 0, 0, 0, time.UTC))
	scope := testScope("tenant-gateway")
	store := openTestStore(t, root, clock)
	registerTestTenant(t, store, scope)
	userRequest := UserUpsert{
		ProviderID: "provider-main", ExternalID: "scim-alice",
		ExternalSubjectID: "subject-alice", PrincipalID: "alice", Active: true,
	}
	if _, _, err := store.UpsertUser(ctx, scope, userRequest); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertGroup(ctx, scope, GroupUpsert{
		ProviderID: "provider-main", ExternalID: "scim-engineering",
		GroupID: "engineering", DisplayName: "Engineering", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMembership(ctx, scope, MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "scim-engineering",
		UserExternalID: "scim-alice", Active: true,
	}); err != nil {
		t.Fatal(err)
	}

	_, privateKey, verifier := newTestVerifier(t)
	agentTaskScopes := &gatewayTestAgentTaskScopeAuthority{}
	gateway, err := NewGateway(store, verifier, store, GatewayOptions{
		Clock: clock, RequestIDs: &testRequestIDs{}, AgentTaskScopes: agentTaskScopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := validTestClaims(clock.Now(), scope.TenantID)
	assertion := signTestClaims(t, privateKey, claims)
	authenticated, snapshot, err := gateway.Ingest(ctx, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TenantID != scope.TenantID || snapshot.PrincipalID != "alice" ||
		!slices.Equal(snapshot.GroupIDs, []string{"engineering"}) || snapshot.State != protocol.IdentityActive {
		t.Fatalf("trusted snapshot = %+v", snapshot)
	}
	authorizationScope := AuthorizationScope{
		TenantID: scope.TenantID, KnowledgeBaseID: "kb-main", AuthorizationModelID: "authz-v1",
		ACLWatermark: "acl-0001", Consistency: protocol.ConsistencyHigherConsistency,
	}
	authorization, err := gateway.AuthorizationContext(ctx, authenticated, authorizationScope, "session-main")
	if err != nil {
		t.Fatal(err)
	}
	if authorization.PrincipalID != "alice" || authorization.IdentityWatermark != snapshot.Watermark ||
		authorization.RequestID != "request_test_1" {
		t.Fatalf("authorization context = %+v", authorization)
	}
	if err := gateway.ValidateAuthorizationContext(ctx, authenticated, authorization); err != nil {
		t.Fatalf("current authorization rejected: %v", err)
	}
	envelope, err := protocol.NewSessionAuthorizationEnvelope(authorization, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	agentTaskScope := protocol.AgentTaskScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: scope.TenantID, KnowledgeBaseID: authorizationScope.KnowledgeBaseID,
		PrincipalID: snapshot.PrincipalID, AgentID: "agent-main", TaskID: "task-main",
		AuthorizationModelID: authorizationScope.AuthorizationModelID,
		IdentityWatermark:    snapshot.Watermark, ACLWatermark: authorizationScope.ACLWatermark,
		DelegationWatermark: "delegation-0001",
		IssuedAt:            clock.Now().Add(-time.Minute), ExpiresAt: clock.Now().Add(time.Hour),
	}
	agentTaskScopes.scope = agentTaskScope
	agentTaskScopes.currentDelegationWatermark = agentTaskScope.DelegationWatermark
	delegatedScope := authorizationScope
	delegatedScope.AgentTaskScope = &agentTaskScope
	withoutAgentTaskAuthority, err := NewGateway(store, verifier, store, GatewayOptions{
		Clock: clock, RequestIDs: &testRequestIDs{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutAgentTaskAuthority.AuthorizationContext(
		ctx, authenticated, delegatedScope, "session-delegated",
	); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("delegated authorization without current authority was accepted: %v", err)
	}
	delegated, err := gateway.AuthorizationContext(ctx, authenticated, delegatedScope, "session-delegated")
	if err != nil {
		t.Fatal(err)
	}
	if err := delegated.ValidateAgentTaskScope(
		agentTaskScope, agentTaskScopes.currentDelegationWatermark, clock.Now(),
	); err != nil {
		t.Fatalf("delegated authorization scope rejected: %v", err)
	}
	agentTaskScopes.currentDelegationWatermark = "delegation-0002"
	if err := gateway.ValidateAuthorizationContext(ctx, authenticated, delegated); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("revoked delegated authorization was accepted: %v", err)
	}
	agentTaskScopes.currentDelegationWatermark = agentTaskScope.DelegationWatermark
	if err := gateway.ValidateAuthorizationContext(ctx, authenticated, delegated); err != nil {
		t.Fatalf("restored delegated authorization rejected: %v", err)
	}

	mismatchedScope := agentTaskScope
	mismatchedScope.KnowledgeBaseID = "kb-other"
	delegatedScope.AgentTaskScope = &mismatchedScope
	if _, err := gateway.AuthorizationContext(ctx, authenticated, delegatedScope, "session-delegated"); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("mismatched agent task scope was accepted: %v", err)
	}
	expiredScope := agentTaskScope
	expiredScope.IssuedAt = clock.Now().Add(-2 * time.Hour)
	expiredScope.ExpiresAt = clock.Now().Add(-time.Hour)
	delegatedScope.AgentTaskScope = &expiredScope
	if _, err := gateway.AuthorizationContext(ctx, authenticated, delegatedScope, "session-delegated"); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("expired agent task scope was accepted: %v", err)
	}

	if _, err := gateway.AuthorizationContext(ctx, authenticated, AuthorizationScope{
		TenantID: "tenant-other", KnowledgeBaseID: "kb-main", AuthorizationModelID: "authz-v1",
		ACLWatermark: "acl-0001", Consistency: protocol.ConsistencyHigherConsistency,
	}, "session-main"); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("cross-tenant authorization = %v", err)
	}

	if _, _, err := gateway.Ingest(ctx, assertion); !errors.Is(err, ErrAssertionRejected) ||
		strings.Contains(err.Error(), claims.Nonce) {
		t.Fatalf("assertion replay error = %v", err)
	}
	reusedNonce := claims
	reusedNonce.IssuedAt = reusedNonce.IssuedAt.Add(time.Second)
	reusedNonce.ExpiresAt = reusedNonce.ExpiresAt.Add(time.Second)
	if _, _, err := gateway.Ingest(ctx, signTestClaims(t, privateKey, reusedNonce)); !errors.Is(err, ErrAssertionRejected) {
		t.Fatalf("reused nonce with changed timestamps was accepted: %v", err)
	}

	if _, change, err := store.ReplaceGroupMembers(ctx, scope, MembershipReplace{
		ProviderID: "provider-main", GroupExternalID: "scim-engineering", UserExternalIDs: []string{},
	}); err != nil || !change.Changed {
		t.Fatalf("remove membership = %+v, %v", change, err)
	}
	if err := gateway.ValidateAuthorizationContext(ctx, authenticated, authorization); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("stale authorization context was accepted: %v", err)
	}
	currentSnapshot, err := gateway.CurrentSnapshot(ctx, authenticated)
	if err != nil || len(currentSnapshot.GroupIDs) != 0 || currentSnapshot.Watermark == snapshot.Watermark {
		t.Fatalf("refreshed identity snapshot = %+v, %v", currentSnapshot, err)
	}
	currentAuthorization, err := gateway.AuthorizationContext(ctx, authenticated, authorizationScope, "session-main")
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.ValidateFor(currentAuthorization); err == nil {
		t.Fatal("session resume accepted a stale identity watermark")
	}

	if _, change, err := store.DeprovisionUser(ctx, scope, userRequest.ProviderID, userRequest.ExternalID); err != nil || !change.Changed {
		t.Fatalf("deprovision gateway user = %+v, %v", change, err)
	}
	if _, err := gateway.CurrentSnapshot(ctx, authenticated); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("deprovisioned identity produced a snapshot: %v", err)
	}
	if err := gateway.ValidateAuthorizationContext(ctx, authenticated, currentAuthorization); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("deprovisioned identity resumed authorization: %v", err)
	}

	persisted, err := os.ReadFile(filepath.Join(root, tenantDirectory, tenantFileKey(scope.TenantID)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), claims.Nonce) || strings.Contains(string(persisted), string(assertion)) {
		t.Fatal("durable identity state contains raw assertion material")
	}
}

type gatewayTestAgentTaskScopeAuthority struct {
	scope                      protocol.AgentTaskScope
	currentDelegationWatermark string
	err                        error
}

func (a *gatewayTestAgentTaskScopeAuthority) CurrentAgentTaskScope(
	context.Context,
	protocol.AuthorizationContext,
) (protocol.AgentTaskScope, string, error) {
	return a.scope, a.currentDelegationWatermark, a.err
}

func TestGatewayRejectsInvalidAssertionsWithoutDisclosure(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC))
	scope := testScope("tenant-validation")
	store := openTestStore(t, t.TempDir(), clock)
	registerTestTenant(t, store, scope)
	if _, _, err := store.UpsertUser(ctx, scope, UserUpsert{
		ProviderID: "provider-main", ExternalID: "scim-validation",
		ExternalSubjectID: "subject-alice", PrincipalID: "alice", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, privateKey, verifier := newTestVerifier(t)
	gateway, err := NewGateway(store, verifier, store, GatewayOptions{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	base := validTestClaims(clock.Now(), scope.TenantID)
	tests := map[string]func(*AssertionClaims){
		"issuer":   func(claims *AssertionClaims) { claims.Issuer = "https://other.example.test" },
		"audience": func(claims *AssertionClaims) { claims.Audience = "other-client" },
		"subject":  func(claims *AssertionClaims) { claims.Subject = "subject-only-in-another-tenant" },
		"tenant":   func(claims *AssertionClaims) { claims.TenantID = "tenant-other" },
		"provider": func(claims *AssertionClaims) { claims.ProviderID = "provider-other" },
		"future":   func(claims *AssertionClaims) { claims.IssuedAt = clock.Now().Add(time.Second) },
		"expired":  func(claims *AssertionClaims) { claims.ExpiresAt = clock.Now() },
		"lifetime": func(claims *AssertionClaims) { claims.ExpiresAt = claims.IssuedAt.Add(25 * time.Hour) },
		"nonce":    func(claims *AssertionClaims) { claims.Nonce = "short" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			claims := base
			claims.Nonce += "-" + name
			mutate(&claims)
			_, _, err := gateway.Ingest(ctx, signTestClaims(t, privateKey, claims))
			if !errors.Is(err, ErrAssertionRejected) || err.Error() != ErrAssertionRejected.Error() ||
				strings.Contains(err.Error(), claims.Subject) || strings.Contains(err.Error(), claims.TenantID) {
				t.Fatalf("disclosing assertion rejection = %v", err)
			}
		})
	}

	secret := "Bearer raw-provider-credential"
	leakyVerifier := AssertionVerifierFunc(func(context.Context, []byte) (AssertionClaims, error) {
		return AssertionClaims{}, errors.New(secret)
	})
	leakSafeGateway, err := NewGateway(store, leakyVerifier, store, GatewayOptions{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := leakSafeGateway.Ingest(ctx, []byte(secret)); !errors.Is(err, ErrAssertionRejected) || strings.Contains(err.Error(), secret) {
		t.Fatalf("provider verifier leaked bearer material: %v", err)
	}
}

func newTestVerifier(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *Ed25519AssertionVerifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519AssertionVerifier(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey, verifier
}

func validTestClaims(now time.Time, tenantID string) AssertionClaims {
	return AssertionClaims{
		ProviderID: "provider-main", Issuer: "https://identity.example.test", Audience: "knote-cli",
		Subject: "subject-alice", TenantID: tenantID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-gateway-secret-001",
	}
}
