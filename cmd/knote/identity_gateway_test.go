package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestPermissionedIdentitySessionProducesProductionAuthorization(t *testing.T) {
	fixture := newCommandIdentityFixture(t, "tenant-command", "alice")
	t.Setenv(permissionedPrincipalEnv, "mallory")
	t.Setenv("KNOTE_PERMISSIONED_IDENTITY_WATERMARK", "identity-attacker")
	t.Setenv(identityStorePathEnv, fixture.root)
	t.Setenv(identityPublicKeyEnv, base64.RawURLEncoding.EncodeToString(fixture.publicKey))
	setIdentityAssertionFD(t, fixture.assertion)

	session, snapshot, err := loadPermissionedIdentitySession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := session.authorizationContext(context.Background(), identity.AuthorizationScope{
		TenantID: fixture.scope.TenantID, KnowledgeBaseID: "kb-command",
		AuthorizationModelID: "authz-command", ACLWatermark: "acl-command",
		Consistency: protocol.ConsistencyHigherConsistency,
	}, "session-command")
	if err != nil {
		t.Fatal(err)
	}
	if authorization.PrincipalID != "alice" || authorization.IdentityWatermark != snapshot.Watermark ||
		authorization.PrincipalID == os.Getenv(permissionedPrincipalEnv) ||
		authorization.IdentityWatermark == os.Getenv("KNOTE_PERMISSIONED_IDENTITY_WATERMARK") {
		t.Fatalf("production authorization trusted legacy environment: %+v", authorization)
	}

	if _, change, err := fixture.store.UpsertGroup(context.Background(), fixture.scope, identity.GroupUpsert{
		ProviderID: "provider-main", ExternalID: "group-command",
		GroupID: "command-group", DisplayName: "Command Group", Active: true,
	}); err != nil || !change.Changed {
		t.Fatalf("identity group change = %+v, %v", change, err)
	}
	if err := session.validate(context.Background(), authorization); !errors.Is(err, identity.ErrAuthorizationUnavailable) {
		t.Fatalf("stale command authorization was accepted: %v", err)
	}
	current, err := session.authorizationContext(context.Background(), identity.AuthorizationScope{
		TenantID: fixture.scope.TenantID, KnowledgeBaseID: "kb-command",
		AuthorizationModelID: "authz-command", ACLWatermark: "acl-command",
		Consistency: protocol.ConsistencyHigherConsistency,
	}, "session-command")
	if err != nil || current.IdentityWatermark == authorization.IdentityWatermark {
		t.Fatalf("current command authorization = %+v, %v", current, err)
	}
}

func TestPermissionedIdentitySessionDoesNotDiscloseRejectedAssertion(t *testing.T) {
	fixture := newCommandIdentityFixture(t, "tenant-rejected", "alice")
	secret := append([]byte(nil), fixture.assertion...)
	secret[len(secret)-1] ^= 1
	_, _, err := newPermissionedIdentitySession(context.Background(), fixture.root, fixture.publicKey, secret)
	if !errors.Is(err, identity.ErrAssertionRejected) || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("rejected assertion error = %v", err)
	}
}

func TestProductionAuthorizationContextRequiresMatchingMembershipPublication(t *testing.T) {
	ctx := context.Background()
	fixture := newCommandIdentityFixture(t, "tenant-command-publication", "alice")
	session, snapshot, err := newPermissionedIdentitySession(
		ctx, fixture.root, fixture.publicKey, fixture.assertion,
	)
	if err != nil {
		t.Fatal(err)
	}
	config := permissionedRuntimeConfig{
		IdentityWatermark: snapshot.Watermark,
		OpenFGA: authz.OpenFGAConfig{
			StoreID:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			AuthorizationModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
		},
		Consistency: protocol.ConsistencyHigherConsistency,
	}
	scope := authorized.ArtifactAuthorizationScope{
		TenantID: fixture.scope.TenantID, KnowledgeBaseID: "kb-command-publication",
		ACLWatermark: "acl-command-publication", ProjectionVersion: "projection-command-publication",
	}
	cache, err := authorized.NewQueryCache(4)
	if err != nil {
		t.Fatal(err)
	}
	revisionState, err := newPermissionedRevisionState(
		config, scope, cache,
		func(context.Context) (authorized.ArtifactAuthorizationScope, error) { return scope, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &commandMembershipPublisher{
		receipt: commandMembershipReceipt(config, scope.TenantID, snapshot.Watermark),
	}
	provider := newProductionAuthorizationContextProvider(
		config,
		config,
		session,
		publisher,
		revisionState,
		func(context.Context) (authorized.ArtifactAuthorizationScope, error) { return scope, nil },
	)
	if _, err := provider(ctx, "session-command-publication"); err != nil {
		t.Fatalf("initial published context: %v", err)
	}
	base, err := revisionState.publisher.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, change, err := fixture.store.UpsertGroup(ctx, fixture.scope, identity.GroupUpsert{
		ProviderID: "provider-main", ExternalID: "group-publication-command",
		GroupID: "group-publication-command", DisplayName: "Publication Command", Active: true,
	}); err != nil || !change.Changed {
		t.Fatalf("identity change = %+v, %v", change, err)
	}
	currentRevision, err := fixture.store.CurrentRevision(ctx, fixture.scope)
	if err != nil {
		t.Fatal(err)
	}

	publisher.set(identity.MembershipPublicationReceipt{}, errors.New("external-secret-openfga-failure"))
	if _, err := provider(ctx, "session-command-publication"); !errors.Is(err, authorized.ErrProtectedContentUnavailable) || strings.Contains(err.Error(), "external-secret") {
		t.Fatalf("publication failure error = %v", err)
	}
	assertCommandRevisionUnchanged(t, revisionState, base)

	publisher.set(commandMembershipReceipt(config, scope.TenantID, snapshot.Watermark), nil)
	beforeMismatchCalls := publisher.callCount()
	if _, err := provider(ctx, "session-command-publication"); !errors.Is(err, authorized.ErrProtectedContentUnavailable) {
		t.Fatalf("stale publication receipt error = %v", err)
	}
	if calls := publisher.callCount() - beforeMismatchCalls; calls != maxIdentityPublicationChecks {
		t.Fatalf("stale publication attempts = %d, want %d", calls, maxIdentityPublicationChecks)
	}
	assertCommandRevisionUnchanged(t, revisionState, base)

	mismatched := commandMembershipReceipt(config, "tenant-command-other", currentRevision.Watermark)
	publisher.set(mismatched, nil)
	beforeTargetMismatch := publisher.callCount()
	if _, err := provider(ctx, "session-command-publication"); !errors.Is(err, authorized.ErrProtectedContentUnavailable) {
		t.Fatalf("target mismatch error = %v", err)
	}
	if calls := publisher.callCount() - beforeTargetMismatch; calls != 1 {
		t.Fatalf("target mismatch publication calls = %d, want 1", calls)
	}
	assertCommandRevisionUnchanged(t, revisionState, base)

	publisher.set(commandMembershipReceipt(config, scope.TenantID, currentRevision.Watermark), nil)
	authorization, err := provider(ctx, "session-command-publication")
	if err != nil || authorization.IdentityWatermark != currentRevision.Watermark {
		t.Fatalf("matching published context = %+v, %v", authorization, err)
	}
	after, err := revisionState.publisher.Current(ctx)
	if err != nil || after.IdentityWatermark != currentRevision.Watermark || after.Epoch != base.Epoch+1 {
		t.Fatalf("published revision = %+v, %v", after, err)
	}
}

type commandMembershipPublisher struct {
	mu      sync.Mutex
	receipt identity.MembershipPublicationReceipt
	err     error
	calls   int
}

func (p *commandMembershipPublisher) PublishLatest(context.Context) (identity.MembershipPublicationReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.receipt, p.err
}

func (p *commandMembershipPublisher) set(receipt identity.MembershipPublicationReceipt, err error) {
	p.mu.Lock()
	p.receipt = receipt
	p.err = err
	p.mu.Unlock()
}

func (p *commandMembershipPublisher) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func commandMembershipReceipt(
	config permissionedRuntimeConfig,
	tenantID string,
	watermark string,
) identity.MembershipPublicationReceipt {
	return identity.MembershipPublicationReceipt{
		Version:              protocol.EnterpriseContractVersion,
		TenantID:             tenantID,
		StoreID:              config.OpenFGA.StoreID,
		AuthorizationModelID: config.OpenFGA.AuthorizationModelID,
		IdentityWatermark:    watermark,
		ProjectionDigest:     "sha256:" + strings.Repeat("0", 64),
		PublishedAt:          time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
	}
}

func assertCommandRevisionUnchanged(
	t *testing.T,
	state *permissionedRevisionState,
	want authz.AuthorizationRevision,
) {
	t.Helper()
	got, err := state.publisher.Current(context.Background())
	if err != nil || got != want {
		t.Fatalf("authorization revision changed without publication: got=%+v want=%+v err=%v", got, want, err)
	}
}

type commandIdentityFixture struct {
	root      string
	store     *identity.LocalStore
	scope     protocol.TenantScope
	publicKey ed25519.PublicKey
	assertion []byte
}

func newCommandIdentityFixture(t *testing.T, tenantID string, principalID string) commandIdentityFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	store, err := identity.OpenLocalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	scope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: tenantID, Region: "cn-east",
	}
	if _, err := store.RegisterTenant(ctx, scope); err != nil {
		t.Fatal(err)
	}
	provider := identity.ProviderSpec{
		ProviderID: "provider-main", Issuer: "https://identity.example.test", Audiences: []string{"knote-cli"},
	}
	if _, _, err := store.UpsertProvider(ctx, scope, provider); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertUser(ctx, scope, identity.UserUpsert{
		ProviderID: provider.ProviderID, ExternalID: "user-command",
		ExternalSubjectID: "subject-command", PrincipalID: principalID, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	claims := identity.AssertionClaims{
		ProviderID: provider.ProviderID, Issuer: provider.Issuer, Audience: provider.Audiences[0],
		Subject: "subject-command", TenantID: tenantID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-command-identity-001",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, payload)
	assertion := []byte(base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature))
	return commandIdentityFixture{
		root: root, store: store, scope: scope, publicKey: publicKey, assertion: assertion,
	}
}

func setIdentityAssertionFD(t *testing.T, assertion []byte) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(assertion); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	t.Setenv(identityAssertionFDEnv, strconv.FormatUint(uint64(reader.Fd()), 10))
}
