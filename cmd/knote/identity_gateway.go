package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	identityStorePathEnv     = "KNOTE_IDENTITY_STORE_PATH"
	identityPublicKeyEnv     = "KNOTE_IDENTITY_ED25519_PUBLIC_KEY"
	identityAssertionFDEnv   = "KNOTE_IDENTITY_ASSERTION_FD"
	maxIdentityAssertionSize = 64 << 10
)

type permissionedIdentitySession struct {
	store         *identity.LocalStore
	gateway       *identity.Gateway
	authenticated *identity.AuthenticatedIdentity
}

func loadPermissionedIdentitySession(ctx context.Context) (*permissionedIdentitySession, protocol.IdentitySnapshot, error) {
	root, err := requiredPermissionedEnv(identityStorePathEnv)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, err
	}
	encodedPublicKey, err := requiredPermissionedEnv(identityPublicKeyEnv)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, err
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != encodedPublicKey {
		return nil, protocol.IdentitySnapshot{}, fmt.Errorf("%s must contain a canonical Ed25519 public key", identityPublicKeyEnv)
	}
	assertion, err := readPermissionedIdentityAssertion()
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, err
	}
	defer clear(assertion)
	return newPermissionedIdentitySession(ctx, root, ed25519.PublicKey(publicKey), assertion)
}

func newPermissionedIdentitySession(
	ctx context.Context,
	root string,
	publicKey ed25519.PublicKey,
	assertion []byte,
) (*permissionedIdentitySession, protocol.IdentitySnapshot, error) {
	if ctx == nil {
		return nil, protocol.IdentitySnapshot{}, identity.ErrAssertionRejected
	}
	store, err := identity.OpenLocalStore(root)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, fmt.Errorf("initialize trusted identity store: %w", identity.ErrStoreUnavailable)
	}
	verifier, err := identity.NewEd25519AssertionVerifier(publicKey)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, fmt.Errorf("initialize trusted assertion verifier: %w", identity.ErrAssertionRejected)
	}
	gateway, err := identity.NewGateway(store, verifier, store, identity.GatewayOptions{})
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, fmt.Errorf("initialize trusted identity gateway: %w", identity.ErrAuthorizationUnavailable)
	}
	authenticated, snapshot, err := gateway.Ingest(ctx, assertion)
	if err != nil {
		return nil, protocol.IdentitySnapshot{}, identity.ErrAssertionRejected
	}
	return &permissionedIdentitySession{store: store, gateway: gateway, authenticated: authenticated}, snapshot, nil
}

func readPermissionedIdentityAssertion() ([]byte, error) {
	value, err := requiredPermissionedEnv(identityAssertionFDEnv)
	if err != nil {
		return nil, err
	}
	fd, err := strconv.ParseUint(value, 10, 31)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("%s must contain an inherited file descriptor", identityAssertionFDEnv)
	}
	file := os.NewFile(uintptr(fd), "knote-identity-assertion")
	if file == nil {
		return nil, fmt.Errorf("%s is unavailable", identityAssertionFDEnv)
	}
	defer file.Close()
	assertion, err := io.ReadAll(io.LimitReader(file, maxIdentityAssertionSize+1))
	if err != nil || len(assertion) == 0 || len(assertion) > maxIdentityAssertionSize {
		clear(assertion)
		return nil, fmt.Errorf("%s did not provide a valid assertion", identityAssertionFDEnv)
	}
	return assertion, nil
}

func (s *permissionedIdentitySession) authorizationContext(
	ctx context.Context,
	scope identity.AuthorizationScope,
	sessionID string,
) (protocol.AuthorizationContext, error) {
	if s == nil || s.gateway == nil || s.authenticated == nil {
		return protocol.AuthorizationContext{}, identity.ErrAuthorizationUnavailable
	}
	return s.gateway.AuthorizationContext(ctx, s.authenticated, scope, sessionID)
}

func (s *permissionedIdentitySession) validate(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) error {
	if s == nil || s.gateway == nil || s.authenticated == nil {
		return identity.ErrAuthorizationUnavailable
	}
	return s.gateway.ValidateAuthorizationContext(ctx, s.authenticated, authorization)
}
