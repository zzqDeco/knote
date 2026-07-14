package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProtectedPageTokenRoundTripIsOpaqueAndContextBound(t *testing.T) {
	now := time.Unix(1_750_000_000, 123).UTC()
	codec := protectedQueryTestCodec(t, "current", protectedQueryTestKey("current", 1))
	request := protectedQueryTestPageTokenRequest(t, now)

	token, err := codec.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{
		request.Context.Authorization.TenantID,
		request.Context.Authorization.PrincipalID,
		request.Context.Authorization.SessionID,
		string(request.Context.TraversalPlan.StartResourceIDs[0]),
	} {
		if strings.Contains(token, canary) || strings.Contains(token, base64.RawURLEncoding.EncodeToString([]byte(canary))) {
			t.Fatalf("opaque token exposed context canary %q: %s", canary, token)
		}
	}
	position, err := codec.Decode(token, request.Context, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if position != (ProtectedPagePosition{Position: request.Position, Limit: request.Limit}) {
		t.Fatalf("page position = %+v", position)
	}

	request.Context.Authorization.RequestID = "req_next_page"
	fingerprint, err := NewVisibilityFingerprint(request.Context.Authorization, request.Context.ProjectionVersion)
	if err != nil {
		t.Fatal(err)
	}
	request.Context.VisibilityFingerprint = fingerprint
	if _, err := codec.Decode(token, request.Context, now.Add(time.Second)); err != nil {
		t.Fatalf("request-scoped ID unexpectedly invalidated session-bound token: %v", err)
	}
}

func TestProtectedPageTokenRejectsTamperingWithOneFixedPublicError(t *testing.T) {
	now := time.Unix(1_750_000_000, 0).UTC()
	codec := protectedQueryTestCodec(t, "current", protectedQueryTestKey("current", 1))
	request := protectedQueryTestPageTokenRequest(t, now)
	token, err := codec.Encode(request)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(token, ".")
	body, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0x01
	bitFlippedBody := append([]string(nil), parts...)
	bitFlippedBody[2] = base64.RawURLEncoding.EncodeToString(body)

	signature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0x80
	bitFlippedSignature := append([]string(nil), parts...)
	bitFlippedSignature[3] = base64.RawURLEncoding.EncodeToString(signature)

	for name, malformed := range map[string]string{
		"body bit flip":      strings.Join(bitFlippedBody, "."),
		"signature bit flip": strings.Join(bitFlippedSignature, "."),
		"wrong body":         parts[0] + "." + parts[1] + ".eA." + parts[3],
		"unknown key":        parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("missing")) + "." + parts[2] + "." + parts[3],
		"truncated":          token[:len(token)-1],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := codec.Decode(malformed, request.Context, now.Add(time.Second))
			assertInvalidProtectedPageToken(t, err)
		})
	}
}

func TestProtectedPageTokenRejectsCrossContextPlanProjectionAndWatermarkReplay(t *testing.T) {
	now := time.Unix(1_750_000_000, 0).UTC()
	codec := protectedQueryTestCodec(t, "current", protectedQueryTestKey("current", 1))
	request := protectedQueryTestPageTokenRequest(t, now)
	token, err := codec.Encode(request)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*ProtectedPageTokenContext){
		"tenant": func(context *ProtectedPageTokenContext) {
			context.Authorization.TenantID = "tenant_other"
			protectedQueryTestRefreshFingerprint(t, context)
		},
		"knowledge base": func(context *ProtectedPageTokenContext) {
			context.Authorization.KnowledgeBaseID = "kb_other"
			protectedQueryTestRefreshFingerprint(t, context)
		},
		"principal": func(context *ProtectedPageTokenContext) {
			context.Authorization.PrincipalID = "user_other"
			protectedQueryTestRefreshFingerprint(t, context)
		},
		"session": func(context *ProtectedPageTokenContext) {
			context.Authorization.SessionID = "sess_other"
		},
		"authorization model watermark": func(context *ProtectedPageTokenContext) {
			context.Authorization.AuthorizationModelID = "model_v2"
			protectedQueryTestRefreshFingerprint(t, context)
		},
		"identity watermark": func(context *ProtectedPageTokenContext) {
			context.Authorization.IdentityWatermark = "identity_v2"
			protectedQueryTestRefreshFingerprint(t, context)
		},
		"ACL watermark": func(context *ProtectedPageTokenContext) {
			context.Authorization.ACLWatermark = "acl_v2"
			protectedQueryTestRefreshFingerprint(t, context)
		},
		"revocation watermark": func(context *ProtectedPageTokenContext) {
			context.RevocationWatermark = "revocation_v2"
		},
		"visibility fingerprint": func(context *ProtectedPageTokenContext) {
			context.VisibilityFingerprint = "vis_ffffffffffffffffffffffffffffffff"
		},
		"plan": func(context *ProtectedPageTokenContext) {
			context.TraversalPlan.Limits.MaxDepth++
		},
		"projection and plan": func(context *ProtectedPageTokenContext) {
			context.ProjectionVersion = "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			context.TraversalPlan.ProjectionVersion = context.ProjectionVersion
			protectedQueryTestRefreshFingerprint(t, context)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			context := request.Context
			mutate(&context)
			_, err := codec.Decode(token, context, now.Add(time.Second))
			assertInvalidProtectedPageToken(t, err)
		})
	}
}

func TestProtectedPageTokenRejectsExpirationAndRevocationEpochChange(t *testing.T) {
	now := time.Unix(1_750_000_000, 0).UTC()
	codec := protectedQueryTestCodec(t, "current", protectedQueryTestKey("current", 1))
	request := protectedQueryTestPageTokenRequest(t, now)
	token, err := codec.Encode(request)
	if err != nil {
		t.Fatal(err)
	}

	_, err = codec.Decode(token, request.Context, request.ExpiresAt)
	assertInvalidProtectedPageToken(t, err)
	_, err = codec.Decode(token, request.Context, request.IssuedAt.Add(-time.Nanosecond))
	assertInvalidProtectedPageToken(t, err)

	revoked := request.Context
	revoked.RevocationWatermark = "revocation_epoch_8"
	_, err = codec.Decode(token, revoked, now.Add(time.Second))
	assertInvalidProtectedPageToken(t, err)
}

func TestProtectedPageTokenSupportsKeyRotationWithoutGlobalSecrets(t *testing.T) {
	now := time.Unix(1_750_000_000, 0).UTC()
	oldKey := protectedQueryTestKey("old", 1)
	newKey := protectedQueryTestKey("new", 2)
	request := protectedQueryTestPageTokenRequest(t, now)

	oldCodec := protectedQueryTestCodec(t, "old", oldKey)
	oldToken, err := oldCodec.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	rotated := protectedQueryTestCodec(t, "new", newKey, oldKey)
	if _, err := rotated.Decode(oldToken, request.Context, now.Add(time.Second)); err != nil {
		t.Fatalf("rotated codec rejected retained old key: %v", err)
	}
	newToken, err := rotated.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(newToken, ProtectedPageTokenVersion+"."+base64.RawURLEncoding.EncodeToString([]byte("new"))+".") {
		t.Fatalf("new token did not use active key ID: %s", newToken)
	}

	newOnly := protectedQueryTestCodec(t, "new", newKey)
	_, err = newOnly.Decode(oldToken, request.Context, now.Add(time.Second))
	assertInvalidProtectedPageToken(t, err)
	if _, err := newOnly.Decode(newToken, request.Context, now.Add(time.Second)); err != nil {
		t.Fatalf("new-only codec rejected current token: %v", err)
	}
}

func TestProtectedQueryPublicErrorsAndMetadataHaveFixedSchema(t *testing.T) {
	for _, publicError := range []*ProtectedQueryPublicError{
		NewProtectedQueryNotFoundError(),
		NewProtectedQueryPermissionDeniedError(),
		NewProtectedQueryProviderUnavailableError(),
		NewProtectedQueryInvalidPageTokenError(),
	} {
		if err := publicError.Validate(); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(publicError)
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range []string{"provider stack", "/secret/path", "res_ffffffffffffffffffffffffffffffff"} {
			if bytes.Contains(encoded, []byte(canary)) {
				t.Fatalf("fixed public error exposed canary %q: %s", canary, encoded)
			}
		}
	}

	invalid := NewProtectedQueryNotFoundError()
	invalid.Message = "missing hidden document /secret/path"
	if invalid.Validate() == nil {
		t.Fatal("accepted content-bearing public error")
	}
}

func TestProtectedQueryVisibleResultRequiresProtectedNextPageTokenStructure(t *testing.T) {
	result := EmptyProtectedQueryVisibleResult()
	result.Page.NextPageToken = "res_ffffffffffffffffffffffffffffffff"
	if err := result.Validate(); err == nil {
		t.Fatal("visible result accepted an internal resource ID as a next page token")
	}
	result.Page.NextPageToken = "pqt1.a2lk.b2Zmc2V0.c2lnbmF0dXJl"
	if err := result.Validate(); err == nil {
		t.Fatal("visible result accepted a truncated protected token structure")
	}

	now := time.Unix(1_750_000_000, 0).UTC()
	codec := protectedQueryTestCodec(t, "current", protectedQueryTestKey("current", 1))
	token, err := codec.Encode(protectedQueryTestPageTokenRequest(t, now))
	if err != nil {
		t.Fatal(err)
	}
	result.Page.NextPageToken = token
	if err := result.Validate(); err != nil {
		t.Fatalf("visible result rejected a protected page token: %v", err)
	}
}

func TestProtectedTraversalPlanIdentityIsStableAndRestricted(t *testing.T) {
	plan := protectedQueryTestPlan(t)
	first, err := NewProtectedTraversalPlanIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProtectedTraversalPlanIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("plan identity is not stable: %+v != %+v", first, second)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(plan.StartResourceIDs[0])) || bytes.Contains(encoded, []byte("start_resource_ids")) {
		t.Fatalf("restricted plan identity exposed traversal inputs: %s", encoded)
	}
	changed := plan
	changed.Limits.MaxDepth++
	changedIdentity, err := NewProtectedTraversalPlanIdentity(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedIdentity.Digest == first.Digest {
		t.Fatal("plan digest did not bind traversal limits")
	}
}

func protectedQueryTestPageTokenRequest(t *testing.T, now time.Time) ProtectedPageTokenRequest {
	t.Helper()
	authorization := protectedQueryTestAuthorization()
	plan := protectedQueryTestPlan(t)
	fingerprint, err := NewVisibilityFingerprint(authorization, plan.ProjectionVersion)
	if err != nil {
		t.Fatal(err)
	}
	return ProtectedPageTokenRequest{
		Context: ProtectedPageTokenContext{
			Authorization: authorization, VisibilityFingerprint: fingerprint,
			ProjectionVersion: plan.ProjectionVersion, TraversalPlan: plan,
			RevocationWatermark: "revocation_epoch_7",
		},
		Position: 64, Limit: 32, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
}

func protectedQueryTestAuthorization() AuthorizationContext {
	return AuthorizationContext{
		Version: SecurityContractVersion, TenantID: "tenant_canary", KnowledgeBaseID: "kb_canary",
		PrincipalID: "user_canary", SessionID: "sess_canary", RequestID: "req_canary",
		AuthorizationModelID: "model_v1", IdentityWatermark: "identity_v1", ACLWatermark: "acl_v1",
		Consistency: ConsistencyHigherConsistency,
	}
}

func protectedQueryTestPlan(t *testing.T) TraversalPlan {
	t.Helper()
	descriptor, err := CompileGraphQuery(GraphQuery{
		Version: GraphQueryContractVersion, Operation: GraphOperationTraverseClaims,
		ProjectionVersion: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IdentityVersion: GraphBindingContractVersion,
		StartResourceIDs: []ResourceID{"res_99999999999999999999999999999999"},
		PredicateSources: []ClaimPredicateSourceKey{ClaimPredicateSupports},
		ResourceKinds:    []GraphResourceKind{GraphResourceDerivedArtifact},
		Direction:        TraversalOutbound,
		Limits: TraversalLimits{
			MaxDepth: 2, MaxFrontierWidth: 32, MaxCandidatesPerHop: 64,
			MaxTotalResources: 128, MaxBatchChecks: 16, MaxWallClockMillis: 5_000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.Parameters
}

func protectedQueryTestRefreshFingerprint(t *testing.T, context *ProtectedPageTokenContext) {
	t.Helper()
	fingerprint, err := NewVisibilityFingerprint(context.Authorization, context.ProjectionVersion)
	if err != nil {
		t.Fatal(err)
	}
	context.VisibilityFingerprint = fingerprint
}

func protectedQueryTestKey(id string, fill byte) ProtectedPageTokenKey {
	return ProtectedPageTokenKey{ID: id, Secret: bytes.Repeat([]byte{fill}, 32)}
}

func protectedQueryTestCodec(t *testing.T, active string, keys ...ProtectedPageTokenKey) *ProtectedPageTokenCodec {
	t.Helper()
	codec, err := NewProtectedPageTokenCodec(active, keys)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func assertInvalidProtectedPageToken(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidProtectedPageToken) {
		t.Fatalf("error = %T %v, want fixed invalid token error", err, err)
	}
	if err.Error() != protectedQueryInvalidPageTokenMessage {
		t.Fatalf("public token error changed: %q", err)
	}
	for _, canary := range []string{"tenant_canary", "sess_canary", "res_99999999999999999999999999999999"} {
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("public token error exposed canary %q: %v", canary, err)
		}
	}
}
