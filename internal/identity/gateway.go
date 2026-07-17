package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/zzqDeco/knote/internal/protocol"
)

const defaultMaxAssertionLifetime = 24 * time.Hour

type RequestIDSource interface {
	NextRequestID() (string, error)
}

type RequestIDSourceFunc func() (string, error)

func (f RequestIDSourceFunc) NextRequestID() (string, error) {
	if f == nil {
		return "", ErrAuthorizationUnavailable
	}
	return f()
}

type GatewayOptions struct {
	Clock                Clock
	MaxAssertionLifetime time.Duration
	RequestIDs           RequestIDSource
}

type Gateway struct {
	directory            IdentityDirectory
	verifier             AssertionVerifier
	nonces               NonceStore
	clock                Clock
	maxAssertionLifetime time.Duration
	requestIDs           RequestIDSource
}

// AuthenticatedIdentity has no exported fields, so callers cannot construct or
// rewrite tenant and subject bindings received from Ingest.
type AuthenticatedIdentity struct {
	tenantID   string
	providerID string
	issuer     string
	audience   string
	subject    string
	issuedAt   time.Time
	expiresAt  time.Time
}

type AuthorizationScope struct {
	TenantID             string
	KnowledgeBaseID      string
	AuthorizationModelID string
	ACLWatermark         string
	AgentID              string
	TaskID               string
	Consistency          protocol.ConsistencyPreference
}

func NewGateway(
	directory IdentityDirectory,
	verifier AssertionVerifier,
	nonces NonceStore,
	options GatewayOptions,
) (*Gateway, error) {
	if directory == nil || verifier == nil || nonces == nil {
		return nil, fmt.Errorf("%w: gateway dependencies are required", ErrInvalidInput)
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	if options.MaxAssertionLifetime == 0 {
		options.MaxAssertionLifetime = defaultMaxAssertionLifetime
	}
	if options.MaxAssertionLifetime <= 0 {
		return nil, fmt.Errorf("%w: max assertion lifetime must be positive", ErrInvalidInput)
	}
	if options.RequestIDs == nil {
		options.RequestIDs = cryptoRequestIDSource{}
	}
	return &Gateway{
		directory: directory, verifier: verifier, nonces: nonces, clock: options.Clock,
		maxAssertionLifetime: options.MaxAssertionLifetime, requestIDs: options.RequestIDs,
	}, nil
}

func (g *Gateway) Ingest(
	ctx context.Context,
	assertion []byte,
) (*AuthenticatedIdentity, protocol.IdentitySnapshot, error) {
	if g == nil || g.directory == nil || g.verifier == nil || g.nonces == nil || g.clock == nil || ctx == nil {
		return nil, protocol.IdentitySnapshot{}, ErrAssertionRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, protocol.IdentitySnapshot{}, err
	}
	claims, err := g.verifier.Verify(ctx, assertion)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, ErrAssertionRejected
	}
	now := g.clock.Now().UTC()
	if err := g.validateClaims(claims, now); err != nil {
		return nil, protocol.IdentitySnapshot{}, ErrAssertionRejected
	}
	scope, provider, resolved, err := g.resolveClaims(ctx, claims)
	if err != nil || resolved.State != protocol.IdentityActive {
		return nil, protocol.IdentitySnapshot{}, ErrAssertionRejected
	}
	_ = scope
	_ = provider
	digest := replayDigest(claims)
	if err := g.nonces.Consume(ctx, NonceUse{
		TenantID: claims.TenantID, Digest: digest, ExpiresAt: claims.ExpiresAt,
	}); err != nil {
		return nil, protocol.IdentitySnapshot{}, ErrAssertionRejected
	}
	authenticated := &AuthenticatedIdentity{
		tenantID: claims.TenantID, providerID: claims.ProviderID,
		issuer: claims.Issuer, audience: claims.Audience, subject: claims.Subject,
		issuedAt: claims.IssuedAt, expiresAt: claims.ExpiresAt,
	}
	snapshot, err := g.CurrentSnapshot(ctx, authenticated)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, ErrAssertionRejected
	}
	return authenticated, snapshot, nil
}

func (g *Gateway) CurrentSnapshot(
	ctx context.Context,
	authenticated *AuthenticatedIdentity,
) (protocol.IdentitySnapshot, error) {
	if g == nil || g.directory == nil || g.clock == nil || authenticated == nil || ctx == nil {
		return protocol.IdentitySnapshot{}, ErrAuthorizationUnavailable
	}
	if err := ctx.Err(); err != nil {
		return protocol.IdentitySnapshot{}, err
	}
	claims := authenticated.claims()
	now := g.clock.Now().UTC()
	if err := g.validateClaims(claims, now); err != nil {
		return protocol.IdentitySnapshot{}, ErrAuthorizationUnavailable
	}
	_, _, resolved, err := g.resolveClaims(ctx, claims)
	if err != nil || resolved.State != protocol.IdentityActive {
		return protocol.IdentitySnapshot{}, ErrAuthorizationUnavailable
	}
	snapshot := protocol.IdentitySnapshot{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: resolved.TenantID, ProviderID: resolved.ProviderID,
		ExternalSubjectID: resolved.ExternalSubjectID, PrincipalID: resolved.PrincipalID,
		GroupIDs: append([]string{}, resolved.GroupIDs...), State: resolved.State,
		Watermark: resolved.Watermark, IssuedAt: authenticated.issuedAt, ExpiresAt: authenticated.expiresAt,
	}
	if err := snapshot.Validate(); err != nil || snapshot.UsableAt(resolved.Watermark, now) != nil {
		return protocol.IdentitySnapshot{}, ErrAuthorizationUnavailable
	}
	return snapshot, nil
}

func (g *Gateway) AuthorizationContext(
	ctx context.Context,
	authenticated *AuthenticatedIdentity,
	scope AuthorizationScope,
	sessionID string,
) (protocol.AuthorizationContext, error) {
	snapshot, err := g.CurrentSnapshot(ctx, authenticated)
	if err != nil || scope.TenantID != snapshot.TenantID {
		return protocol.AuthorizationContext{}, ErrAuthorizationUnavailable
	}
	requestID, err := g.requestIDs.NextRequestID()
	if err != nil {
		return protocol.AuthorizationContext{}, ErrAuthorizationUnavailable
	}
	authorization := protocol.AuthorizationContext{
		Version:  protocol.SecurityContractVersion,
		TenantID: snapshot.TenantID, KnowledgeBaseID: scope.KnowledgeBaseID,
		PrincipalID: snapshot.PrincipalID, SessionID: sessionID, RequestID: requestID,
		AuthorizationModelID: scope.AuthorizationModelID,
		IdentityWatermark:    snapshot.Watermark, ACLWatermark: scope.ACLWatermark,
		AgentID: scope.AgentID, TaskID: scope.TaskID, Consistency: scope.Consistency,
	}
	if err := authorization.Validate(); err != nil {
		return protocol.AuthorizationContext{}, ErrAuthorizationUnavailable
	}
	return authorization, nil
}

func (g *Gateway) ValidateAuthorizationContext(
	ctx context.Context,
	authenticated *AuthenticatedIdentity,
	authorization protocol.AuthorizationContext,
) error {
	if err := authorization.Validate(); err != nil {
		return ErrAuthorizationUnavailable
	}
	snapshot, err := g.CurrentSnapshot(ctx, authenticated)
	if err != nil || authorization.TenantID != snapshot.TenantID ||
		authorization.PrincipalID != snapshot.PrincipalID ||
		authorization.IdentityWatermark != snapshot.Watermark {
		return ErrAuthorizationUnavailable
	}
	return nil
}

func (g *Gateway) resolveClaims(
	ctx context.Context,
	claims AssertionClaims,
) (protocol.TenantScope, Provider, ResolvedIdentity, error) {
	scope, err := g.directory.Tenant(ctx, claims.TenantID)
	if err != nil {
		return protocol.TenantScope{}, Provider{}, ResolvedIdentity{}, ErrIdentityUnavailable
	}
	provider, err := g.directory.Provider(ctx, scope, claims.ProviderID)
	if err != nil || provider.Issuer != claims.Issuer || !slices.Contains(provider.Audiences, claims.Audience) {
		return protocol.TenantScope{}, Provider{}, ResolvedIdentity{}, ErrIdentityUnavailable
	}
	resolved, err := g.directory.ResolveActiveIdentity(ctx, scope, claims.ProviderID, claims.Subject)
	if err != nil || resolved.TenantID != scope.TenantID || resolved.ProviderID != claims.ProviderID ||
		resolved.ExternalSubjectID != claims.Subject {
		return protocol.TenantScope{}, Provider{}, ResolvedIdentity{}, ErrIdentityUnavailable
	}
	return scope, provider, resolved, nil
}

func (g *Gateway) validateClaims(claims AssertionClaims, now time.Time) error {
	if now.IsZero() || validateCanonicalID("provider_id", claims.ProviderID) != nil ||
		validateCanonicalID("tenant_id", claims.TenantID) != nil ||
		validateCanonicalID("subject", claims.Subject) != nil ||
		validateTrustURI("issuer", claims.Issuer) != nil || validateAudience(claims.Audience) != nil ||
		validateUTC("issued_at", claims.IssuedAt) != nil || validateUTC("expires_at", claims.ExpiresAt) != nil ||
		validateNonce(claims.Nonce) != nil {
		return ErrAssertionRejected
	}
	if claims.IssuedAt.After(now) || !claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.IssuedAt) ||
		claims.ExpiresAt.Sub(claims.IssuedAt) > g.maxAssertionLifetime {
		return ErrAssertionRejected
	}
	return nil
}

func (a *AuthenticatedIdentity) claims() AssertionClaims {
	if a == nil {
		return AssertionClaims{}
	}
	return AssertionClaims{
		ProviderID: a.providerID, Issuer: a.issuer, Audience: a.audience,
		Subject: a.subject, TenantID: a.tenantID, IssuedAt: a.issuedAt, ExpiresAt: a.expiresAt,
		Nonce: "validated_in_memory",
	}
}

func replayDigest(claims AssertionClaims) ReplayDigest {
	parts := []string{
		claims.TenantID, claims.ProviderID, claims.Issuer, claims.Nonce,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return ReplayDigest("replay_" + hex.EncodeToString(sum[:]))
}

func validateNonce(value string) error {
	if len(value) < 8 || len(value) > 512 || value != strings.TrimSpace(value) {
		return ErrAssertionRejected
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return ErrAssertionRejected
		}
	}
	return nil
}

type cryptoRequestIDSource struct{}

func (cryptoRequestIDSource) NextRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", ErrAuthorizationUnavailable
	}
	return "request_identity_" + hex.EncodeToString(random[:]), nil
}
