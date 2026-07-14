package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	ProtectedQueryContractVersion = "v1"
	ProtectedPageTokenVersion     = "pqt1"
	MaxProtectedQueryPageLimit    = 256

	maxProtectedQueryStringLength = 512
	maxProtectedQueryValues       = 256
	maxProtectedPageTokenLength   = 16 * 1024
	protectedPageTokenNonceSize   = 12
	protectedPageTokenTagSize     = 16
)

type ProtectedQueryOperation string

const (
	ProtectedQueryOperationQuery        ProtectedQueryOperation = "query"
	ProtectedQueryOperationCount        ProtectedQueryOperation = "count"
	ProtectedQueryOperationExists       ProtectedQueryOperation = "exists"
	ProtectedQueryOperationAutocomplete ProtectedQueryOperation = "autocomplete"
	ProtectedQueryOperationFacets       ProtectedQueryOperation = "facets"
	ProtectedQueryOperationPage         ProtectedQueryOperation = "page"
)

func (operation ProtectedQueryOperation) Validate() error {
	switch operation {
	case ProtectedQueryOperationQuery,
		ProtectedQueryOperationCount,
		ProtectedQueryOperationExists,
		ProtectedQueryOperationAutocomplete,
		ProtectedQueryOperationFacets,
		ProtectedQueryOperationPage:
		return nil
	default:
		return fmt.Errorf("unsupported protected query operation")
	}
}

type ProtectedQueryPublicOutcome string

const (
	ProtectedQueryOutcomeOK                  ProtectedQueryPublicOutcome = "ok"
	ProtectedQueryOutcomeNotFound            ProtectedQueryPublicOutcome = "not_found"
	ProtectedQueryOutcomePermissionDenied    ProtectedQueryPublicOutcome = "permission_denied"
	ProtectedQueryOutcomeProviderUnavailable ProtectedQueryPublicOutcome = "provider_unavailable"
	ProtectedQueryOutcomeInvalidPageToken    ProtectedQueryPublicOutcome = "invalid_page_token"
)

type ProtectedQueryErrorCode string

const (
	ProtectedQueryErrorNotFound            ProtectedQueryErrorCode = "not_found"
	ProtectedQueryErrorPermissionDenied    ProtectedQueryErrorCode = "permission_denied"
	ProtectedQueryErrorProviderUnavailable ProtectedQueryErrorCode = "provider_unavailable"
	ProtectedQueryErrorInvalidPageToken    ProtectedQueryErrorCode = "invalid_page_token"
)

const (
	protectedQueryNotFoundMessage            = "query result not found"
	protectedQueryPermissionDeniedMessage    = "query is not permitted"
	protectedQueryProviderUnavailableMessage = "query is temporarily unavailable"
	protectedQueryInvalidPageTokenMessage    = "page token is invalid"
)

type ProtectedQueryPublicError struct {
	Code    ProtectedQueryErrorCode `json:"code"`
	Message string                  `json:"message"`
}

func (publicError ProtectedQueryPublicError) Error() string { return publicError.Message }

func NewProtectedQueryNotFoundError() *ProtectedQueryPublicError {
	return &ProtectedQueryPublicError{Code: ProtectedQueryErrorNotFound, Message: protectedQueryNotFoundMessage}
}

func NewProtectedQueryPermissionDeniedError() *ProtectedQueryPublicError {
	return &ProtectedQueryPublicError{Code: ProtectedQueryErrorPermissionDenied, Message: protectedQueryPermissionDeniedMessage}
}

func NewProtectedQueryProviderUnavailableError() *ProtectedQueryPublicError {
	return &ProtectedQueryPublicError{Code: ProtectedQueryErrorProviderUnavailable, Message: protectedQueryProviderUnavailableMessage}
}

func NewProtectedQueryInvalidPageTokenError() *ProtectedQueryPublicError {
	return &ProtectedQueryPublicError{Code: ProtectedQueryErrorInvalidPageToken, Message: protectedQueryInvalidPageTokenMessage}
}

func (publicError ProtectedQueryPublicError) Validate() error {
	want := fixedProtectedQueryError(publicError.Code)
	if want == nil || publicError.Message != want.Message {
		return fmt.Errorf("protected query error must use a fixed code and message")
	}
	return nil
}

func fixedProtectedQueryError(code ProtectedQueryErrorCode) *ProtectedQueryPublicError {
	switch code {
	case ProtectedQueryErrorNotFound:
		return NewProtectedQueryNotFoundError()
	case ProtectedQueryErrorPermissionDenied:
		return NewProtectedQueryPermissionDeniedError()
	case ProtectedQueryErrorProviderUnavailable:
		return NewProtectedQueryProviderUnavailableError()
	case ProtectedQueryErrorInvalidPageToken:
		return NewProtectedQueryInvalidPageTokenError()
	default:
		return nil
	}
}

type ProtectedQueryFacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type ProtectedQueryFacet struct {
	Name   string                     `json:"name"`
	Values []ProtectedQueryFacetValue `json:"values"`
}

// ProtectedQueryPageItem contains only an authorization-filtered public value.
// Internal resource IDs, paths, labels, and bodies have no representation here.
type ProtectedQueryPageItem struct {
	Value string `json:"value"`
}

type ProtectedQueryPage struct {
	Items         []ProtectedQueryPageItem `json:"items"`
	NextPageToken string                   `json:"next_page_token"`
}

type ProtectedQueryVisibleResult struct {
	Count        int                   `json:"count"`
	Exists       bool                  `json:"exists"`
	Autocomplete []string              `json:"autocomplete"`
	Facets       []ProtectedQueryFacet `json:"facets"`
	Page         ProtectedQueryPage    `json:"page"`
}

func EmptyProtectedQueryVisibleResult() ProtectedQueryVisibleResult {
	return ProtectedQueryVisibleResult{
		Autocomplete: []string{},
		Facets:       []ProtectedQueryFacet{},
		Page:         ProtectedQueryPage{Items: []ProtectedQueryPageItem{}},
	}
}

func (result ProtectedQueryVisibleResult) Validate() error {
	if result.Count < 0 || result.Exists != (result.Count > 0) {
		return fmt.Errorf("protected query count and exists are inconsistent")
	}
	if result.Autocomplete == nil || result.Facets == nil || result.Page.Items == nil {
		return fmt.Errorf("protected query collections must use a stable empty array")
	}
	if len(result.Autocomplete) > maxProtectedQueryValues || len(result.Facets) > maxProtectedQueryValues ||
		len(result.Page.Items) > MaxProtectedQueryPageLimit {
		return fmt.Errorf("protected query public result exceeds its fixed limit")
	}
	if len(result.Page.Items) > result.Count || (!result.Exists && result.Page.NextPageToken != "") {
		return fmt.Errorf("protected query page is inconsistent with the visible result")
	}
	for index, value := range result.Autocomplete {
		if err := validateProtectedQueryPublicValue("autocomplete", value); err != nil {
			return err
		}
		if index > 0 && result.Autocomplete[index-1] >= value {
			return fmt.Errorf("protected query autocomplete must be sorted and unique")
		}
	}
	for index, facet := range result.Facets {
		if err := validateProtectedQueryPublicValue("facet name", facet.Name); err != nil {
			return err
		}
		if index > 0 && result.Facets[index-1].Name >= facet.Name {
			return fmt.Errorf("protected query facets must be sorted and unique")
		}
		if facet.Values == nil || len(facet.Values) > maxProtectedQueryValues {
			return fmt.Errorf("protected query facet values must use a bounded stable array")
		}
		for valueIndex, value := range facet.Values {
			if err := validateProtectedQueryPublicValue("facet value", value.Value); err != nil {
				return err
			}
			if value.Count < 0 || value.Count > result.Count {
				return fmt.Errorf("protected query facet count is outside the visible result")
			}
			if valueIndex > 0 && facet.Values[valueIndex-1].Value >= value.Value {
				return fmt.Errorf("protected query facet values must be sorted and unique")
			}
		}
	}
	for _, item := range result.Page.Items {
		if err := validateProtectedQueryPublicValue("page item", item.Value); err != nil {
			return err
		}
	}
	if result.Page.NextPageToken != "" {
		if err := validateProtectedPageTokenStructure(result.Page.NextPageToken); err != nil {
			return fmt.Errorf("protected query next page token is malformed")
		}
	}
	return nil
}

func validateProtectedQueryPublicValue(name, value string) error {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > maxProtectedQueryStringLength ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("protected query %s is malformed", name)
	}
	return nil
}

type ProtectedQueryLatencyBucket string

const (
	ProtectedQueryLatencyUnder10MS  ProtectedQueryLatencyBucket = "under_10ms"
	ProtectedQueryLatencyUnder50MS  ProtectedQueryLatencyBucket = "under_50ms"
	ProtectedQueryLatencyUnder250MS ProtectedQueryLatencyBucket = "under_250ms"
	ProtectedQueryLatencyOver250MS  ProtectedQueryLatencyBucket = "over_250ms"
)

type ProtectedQueryTraceMetadata struct {
	Operation ProtectedQueryOperation     `json:"operation"`
	Outcome   ProtectedQueryPublicOutcome `json:"outcome"`
}

type ProtectedQueryDebugMetadata struct {
	ProjectionVersion     string                          `json:"projection_version,omitempty"`
	VisibilityFingerprint VisibilityFingerprint           `json:"visibility_fingerprint,omitempty"`
	Plan                  *ProtectedTraversalPlanIdentity `json:"plan,omitempty"`
}

type ProtectedQueryMetricsMetadata struct {
	Operation     ProtectedQueryOperation     `json:"operation"`
	Outcome       ProtectedQueryPublicOutcome `json:"outcome"`
	LatencyBucket ProtectedQueryLatencyBucket `json:"latency_bucket,omitempty"`
}

type ProtectedQueryAuditMetadata struct {
	Action   string                      `json:"action"`
	Decision ProtectedQueryPublicOutcome `json:"decision"`
}

type ProtectedQueryMetadata struct {
	Trace   ProtectedQueryTraceMetadata   `json:"trace"`
	Debug   ProtectedQueryDebugMetadata   `json:"debug"`
	Metrics ProtectedQueryMetricsMetadata `json:"metrics"`
	Audit   ProtectedQueryAuditMetadata   `json:"audit"`
}

func (metadata ProtectedQueryMetadata) Validate() error {
	if err := metadata.Trace.Operation.Validate(); err != nil {
		return err
	}
	if metadata.Metrics.Operation != metadata.Trace.Operation || metadata.Metrics.Outcome != metadata.Trace.Outcome ||
		metadata.Audit.Decision != metadata.Trace.Outcome || metadata.Audit.Action != "protected_query" {
		return fmt.Errorf("protected query metadata is inconsistent")
	}
	switch metadata.Trace.Outcome {
	case ProtectedQueryOutcomeOK, ProtectedQueryOutcomeNotFound,
		ProtectedQueryOutcomePermissionDenied, ProtectedQueryOutcomeProviderUnavailable,
		ProtectedQueryOutcomeInvalidPageToken:
	default:
		return fmt.Errorf("unsupported protected query outcome")
	}
	if metadata.Metrics.LatencyBucket != "" {
		switch metadata.Metrics.LatencyBucket {
		case ProtectedQueryLatencyUnder10MS, ProtectedQueryLatencyUnder50MS,
			ProtectedQueryLatencyUnder250MS, ProtectedQueryLatencyOver250MS:
		default:
			return fmt.Errorf("unsupported protected query latency bucket")
		}
	}
	debug := metadata.Debug
	debugEmpty := debug.ProjectionVersion == "" && debug.VisibilityFingerprint == "" && debug.Plan == nil
	if metadata.Trace.Outcome == ProtectedQueryOutcomeOK && debugEmpty {
		return fmt.Errorf("protected query success requires debug binding metadata")
	}
	if metadata.Trace.Outcome != ProtectedQueryOutcomeOK && !debugEmpty {
		return fmt.Errorf("protected query errors must not include debug binding metadata")
	}
	if debugEmpty {
		return nil
	}
	if !validGraphProjectionVersion(debug.ProjectionVersion) || debug.VisibilityFingerprint.Validate() != nil || debug.Plan == nil {
		return fmt.Errorf("protected query debug metadata is incomplete")
	}
	if err := debug.Plan.Validate(); err != nil || debug.Plan.ProjectionVersion != debug.ProjectionVersion {
		return fmt.Errorf("protected query debug plan metadata is invalid")
	}
	return nil
}

type ProtectedQueryEnvelope struct {
	Version  string                      `json:"version"`
	Result   ProtectedQueryVisibleResult `json:"result"`
	Error    *ProtectedQueryPublicError  `json:"error"`
	Metadata ProtectedQueryMetadata      `json:"metadata"`
}

func (envelope ProtectedQueryEnvelope) Validate() error {
	if envelope.Version != ProtectedQueryContractVersion {
		return fmt.Errorf("unsupported protected query contract version")
	}
	if err := envelope.Result.Validate(); err != nil {
		return err
	}
	if err := envelope.Metadata.Validate(); err != nil {
		return err
	}
	if envelope.Error == nil {
		if envelope.Metadata.Trace.Outcome != ProtectedQueryOutcomeOK {
			return fmt.Errorf("protected query success has an invalid outcome")
		}
		return nil
	}
	if err := envelope.Error.Validate(); err != nil {
		return err
	}
	if envelope.Result.Count != 0 || envelope.Result.Exists || len(envelope.Result.Autocomplete) != 0 ||
		len(envelope.Result.Facets) != 0 || len(envelope.Result.Page.Items) != 0 || envelope.Result.Page.NextPageToken != "" {
		return fmt.Errorf("protected query errors must use the fixed empty result")
	}
	wantOutcome := map[ProtectedQueryErrorCode]ProtectedQueryPublicOutcome{
		ProtectedQueryErrorNotFound:            ProtectedQueryOutcomeNotFound,
		ProtectedQueryErrorPermissionDenied:    ProtectedQueryOutcomePermissionDenied,
		ProtectedQueryErrorProviderUnavailable: ProtectedQueryOutcomeProviderUnavailable,
		ProtectedQueryErrorInvalidPageToken:    ProtectedQueryOutcomeInvalidPageToken,
	}[envelope.Error.Code]
	if envelope.Metadata.Trace.Outcome != wantOutcome {
		return fmt.Errorf("protected query error outcome is inconsistent")
	}
	return nil
}

type ProtectedTraversalPlanIdentity struct {
	ContractVersion              int    `json:"contract_version"`
	PredicateAllowlistVersion    int    `json:"predicate_allowlist_version"`
	ResourceKindAllowlistVersion int    `json:"resource_kind_allowlist_version"`
	ProjectionVersion            string `json:"projection_version"`
	IdentityVersion              int    `json:"identity_version"`
	Digest                       string `json:"digest"`
}

func NewProtectedTraversalPlanIdentity(plan TraversalPlan) (ProtectedTraversalPlanIdentity, error) {
	if err := plan.Validate(); err != nil {
		return ProtectedTraversalPlanIdentity{}, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return ProtectedTraversalPlanIdentity{}, fmt.Errorf("encode protected traversal plan: %w", err)
	}
	sum := sha256.Sum256(encoded)
	identity := ProtectedTraversalPlanIdentity{
		ContractVersion:              plan.Version,
		PredicateAllowlistVersion:    plan.PredicateAllowlistVersion,
		ResourceKindAllowlistVersion: plan.ResourceKindAllowlistVersion,
		ProjectionVersion:            plan.ProjectionVersion,
		IdentityVersion:              plan.IdentityVersion,
		Digest:                       "sha256:" + hex.EncodeToString(sum[:]),
	}
	return identity, identity.Validate()
}

func (identity ProtectedTraversalPlanIdentity) Validate() error {
	if identity.ContractVersion != GraphQueryContractVersion ||
		identity.PredicateAllowlistVersion != ClaimPredicateAllowlistVersion ||
		identity.ResourceKindAllowlistVersion != GraphResourceKindAllowlistVersion ||
		identity.IdentityVersion != GraphBindingContractVersion || !validGraphProjectionVersion(identity.ProjectionVersion) {
		return fmt.Errorf("protected traversal plan identity has unsupported versions")
	}
	if !strings.HasPrefix(identity.Digest, "sha256:") || len(identity.Digest) != len("sha256:")+sha256.Size*2 {
		return fmt.Errorf("protected traversal plan identity has an invalid digest")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(identity.Digest, "sha256:")); err != nil {
		return fmt.Errorf("protected traversal plan identity has an invalid digest")
	}
	return nil
}

type ProtectedPageTokenKey struct {
	ID     string
	Secret []byte
}

type ProtectedPageTokenContext struct {
	Authorization         AuthorizationContext
	VisibilityFingerprint VisibilityFingerprint
	ProjectionVersion     string
	TraversalPlan         TraversalPlan
	RevocationWatermark   string
}

type ProtectedPageTokenRequest struct {
	Context   ProtectedPageTokenContext
	Position  int
	Limit     int
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type ProtectedPagePosition struct {
	Position int
	Limit    int
}

type ProtectedPageTokenCodec struct {
	activeKeyID string
	keys        map[string][]byte
	random      io.Reader
}

type invalidProtectedPageTokenError struct{}

func (invalidProtectedPageTokenError) Error() string { return protectedQueryInvalidPageTokenMessage }

var ErrInvalidProtectedPageToken error = invalidProtectedPageTokenError{}

func NewProtectedPageTokenCodec(activeKeyID string, keys []ProtectedPageTokenKey) (*ProtectedPageTokenCodec, error) {
	if err := validateProtectedPageTokenKeyID(activeKeyID); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("protected page token keys are required")
	}
	copied := make(map[string][]byte, len(keys))
	for _, key := range keys {
		if err := validateProtectedPageTokenKeyID(key.ID); err != nil {
			return nil, err
		}
		if len(key.Secret) < sha256.Size {
			return nil, fmt.Errorf("protected page token key %q must contain at least 32 bytes", key.ID)
		}
		if _, duplicate := copied[key.ID]; duplicate {
			return nil, fmt.Errorf("duplicate protected page token key %q", key.ID)
		}
		copied[key.ID] = append([]byte(nil), key.Secret...)
	}
	if _, ok := copied[activeKeyID]; !ok {
		return nil, fmt.Errorf("active protected page token key is not configured")
	}
	return &ProtectedPageTokenCodec{activeKeyID: activeKeyID, keys: copied, random: rand.Reader}, nil
}

func (codec *ProtectedPageTokenCodec) Encode(request ProtectedPageTokenRequest) (string, error) {
	if codec == nil {
		return "", fmt.Errorf("protected page token codec is nil")
	}
	contextClaims, err := protectedPageTokenContextClaimsFor(request.Context)
	if err != nil {
		return "", err
	}
	if request.Position < 0 || request.Limit <= 0 || request.Limit > MaxProtectedQueryPageLimit {
		return "", fmt.Errorf("protected page token position or limit is invalid")
	}
	if request.IssuedAt.IsZero() || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.IssuedAt) ||
		request.IssuedAt.UTC().UnixNano() <= 0 || request.ExpiresAt.UTC().UnixNano() <= 0 {
		return "", fmt.Errorf("protected page token lifetime is invalid")
	}
	claims := protectedPageTokenClaims{
		Version: ProtectedPageTokenVersion, Context: contextClaims,
		Position: request.Position, Limit: request.Limit,
		IssuedAtUnixNano: request.IssuedAt.UTC().UnixNano(), ExpiresAtUnixNano: request.ExpiresAt.UTC().UnixNano(),
	}
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode protected page token: %w", err)
	}
	key := codec.keys[codec.activeKeyID]
	aead, err := protectedPageTokenAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(codec.random, nonce); err != nil {
		return "", fmt.Errorf("read protected page token nonce: %w", err)
	}
	header := ProtectedPageTokenVersion + "." + base64.RawURLEncoding.EncodeToString([]byte(codec.activeKeyID))
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(header))
	bodyBytes := append(append([]byte(nil), nonce...), ciphertext...)
	body := base64.RawURLEncoding.EncodeToString(bodyBytes)
	unsigned := header + "." + body
	signature := protectedPageTokenMAC(key, unsigned)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (codec *ProtectedPageTokenCodec) Decode(
	token string,
	expected ProtectedPageTokenContext,
	now time.Time,
) (ProtectedPagePosition, error) {
	fail := func() (ProtectedPagePosition, error) { return ProtectedPagePosition{}, ErrInvalidProtectedPageToken }
	if codec == nil || now.IsZero() || validateProtectedPageTokenStructure(token) != nil {
		return fail()
	}
	expectedClaims, err := protectedPageTokenContextClaimsFor(expected)
	if err != nil {
		return fail()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != ProtectedPageTokenVersion {
		return fail()
	}
	keyIDBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || validateProtectedPageTokenKeyID(string(keyIDBytes)) != nil {
		return fail()
	}
	key, ok := codec.keys[string(keyIDBytes)]
	if !ok {
		return fail()
	}
	providedSignature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(providedSignature) != sha256.Size {
		return fail()
	}
	unsigned := strings.Join(parts[:3], ".")
	expectedSignature := protectedPageTokenMAC(key, unsigned)
	if subtle.ConstantTimeCompare(providedSignature, expectedSignature) != 1 {
		return fail()
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fail()
	}
	aead, err := protectedPageTokenAEAD(key)
	if err != nil || len(body) < aead.NonceSize()+aead.Overhead() {
		return fail()
	}
	header := strings.Join(parts[:2], ".")
	plaintext, err := aead.Open(nil, body[:aead.NonceSize()], body[aead.NonceSize():], []byte(header))
	if err != nil {
		return fail()
	}
	var claims protectedPageTokenClaims
	if err := decodeStrictJSON(plaintext, &claims); err != nil || claims.Version != ProtectedPageTokenVersion ||
		claims.Position < 0 || claims.Limit <= 0 || claims.Limit > MaxProtectedQueryPageLimit ||
		claims.IssuedAtUnixNano <= 0 || claims.ExpiresAtUnixNano <= claims.IssuedAtUnixNano {
		return fail()
	}
	if !secureJSONEqual(claims.Context, expectedClaims) {
		return fail()
	}
	issuedAt := time.Unix(0, claims.IssuedAtUnixNano)
	expiresAt := time.Unix(0, claims.ExpiresAtUnixNano)
	if now.Before(issuedAt) || !now.Before(expiresAt) {
		return fail()
	}
	return ProtectedPagePosition{Position: claims.Position, Limit: claims.Limit}, nil
}

func validateProtectedPageTokenStructure(token string) error {
	if len(token) == 0 || len(token) > maxProtectedPageTokenLength ||
		strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return ErrInvalidProtectedPageToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != ProtectedPageTokenVersion {
		return ErrInvalidProtectedPageToken
	}
	keyID, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || validateProtectedPageTokenKeyID(string(keyID)) != nil {
		return ErrInvalidProtectedPageToken
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(body) < protectedPageTokenNonceSize+protectedPageTokenTagSize {
		return ErrInvalidProtectedPageToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(signature) != sha256.Size {
		return ErrInvalidProtectedPageToken
	}
	return nil
}

type protectedPageTokenClaims struct {
	Version           string                          `json:"version"`
	Context           protectedPageTokenContextClaims `json:"context"`
	Position          int                             `json:"position"`
	Limit             int                             `json:"limit"`
	IssuedAtUnixNano  int64                           `json:"issued_at_unix_nano"`
	ExpiresAtUnixNano int64                           `json:"expires_at_unix_nano"`
}

type protectedPageTokenContextClaims struct {
	TenantID              string                         `json:"tenant_id"`
	KnowledgeBaseID       string                         `json:"knowledge_base_id"`
	PrincipalID           string                         `json:"principal_id"`
	SessionID             string                         `json:"session_id"`
	AuthorizationModelID  string                         `json:"authorization_model_id"`
	IdentityWatermark     string                         `json:"identity_watermark"`
	ACLWatermark          string                         `json:"acl_watermark"`
	RevocationWatermark   string                         `json:"revocation_watermark"`
	VisibilityFingerprint VisibilityFingerprint          `json:"visibility_fingerprint"`
	ProjectionVersion     string                         `json:"projection_version"`
	Plan                  ProtectedTraversalPlanIdentity `json:"plan"`
}

func protectedPageTokenContextClaimsFor(context ProtectedPageTokenContext) (protectedPageTokenContextClaims, error) {
	if err := context.Authorization.Validate(); err != nil {
		return protectedPageTokenContextClaims{}, err
	}
	if !validGraphProjectionVersion(context.ProjectionVersion) {
		return protectedPageTokenContextClaims{}, fmt.Errorf("protected page token projection version is invalid")
	}
	if err := context.VisibilityFingerprint.Validate(); err != nil {
		return protectedPageTokenContextClaims{}, err
	}
	expectedFingerprint, err := NewVisibilityFingerprint(context.Authorization, context.ProjectionVersion)
	if err != nil || expectedFingerprint != context.VisibilityFingerprint {
		return protectedPageTokenContextClaims{}, fmt.Errorf("protected page token visibility fingerprint does not match its context")
	}
	if err := validateToken("revocation_watermark", context.RevocationWatermark); err != nil {
		return protectedPageTokenContextClaims{}, err
	}
	plan, err := NewProtectedTraversalPlanIdentity(context.TraversalPlan)
	if err != nil {
		return protectedPageTokenContextClaims{}, err
	}
	if plan.ProjectionVersion != context.ProjectionVersion {
		return protectedPageTokenContextClaims{}, fmt.Errorf("protected page token plan projection does not match its context")
	}
	authorization := context.Authorization
	return protectedPageTokenContextClaims{
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID: authorization.PrincipalID, SessionID: authorization.SessionID,
		AuthorizationModelID: authorization.AuthorizationModelID,
		IdentityWatermark:    authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		RevocationWatermark:   context.RevocationWatermark,
		VisibilityFingerprint: context.VisibilityFingerprint, ProjectionVersion: context.ProjectionVersion,
		Plan: plan,
	}, nil
}

func validateProtectedPageTokenKeyID(keyID string) error {
	if err := validateToken("protected page token key id", keyID); err != nil {
		return err
	}
	if len(keyID) > 64 {
		return fmt.Errorf("protected page token key id is too long")
	}
	return nil
}

func protectedPageTokenAEAD(secret []byte) (cipher.AEAD, error) {
	key := protectedPageTokenDerivedKey(secret, "knote/protected-page-token/encryption/v1")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create protected page token cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func protectedPageTokenMAC(secret []byte, value string) []byte {
	key := protectedPageTokenDerivedKey(secret, "knote/protected-page-token/authentication/v1")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func protectedPageTokenDerivedKey(secret []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

func secureJSONEqual(left, right any) bool {
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftDigest := sha256.Sum256(leftEncoded)
	rightDigest := sha256.Sum256(rightEncoded)
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}

func CanonicalizeProtectedQueryVisibleResult(result ProtectedQueryVisibleResult) ProtectedQueryVisibleResult {
	canonical := result
	canonical.Autocomplete = append([]string(nil), result.Autocomplete...)
	if canonical.Autocomplete == nil {
		canonical.Autocomplete = []string{}
	}
	sort.Strings(canonical.Autocomplete)
	canonical.Facets = append([]ProtectedQueryFacet(nil), result.Facets...)
	if canonical.Facets == nil {
		canonical.Facets = []ProtectedQueryFacet{}
	}
	for index := range canonical.Facets {
		canonical.Facets[index].Values = append([]ProtectedQueryFacetValue(nil), canonical.Facets[index].Values...)
		if canonical.Facets[index].Values == nil {
			canonical.Facets[index].Values = []ProtectedQueryFacetValue{}
		}
		sort.Slice(canonical.Facets[index].Values, func(i, j int) bool {
			return canonical.Facets[index].Values[i].Value < canonical.Facets[index].Values[j].Value
		})
	}
	sort.Slice(canonical.Facets, func(i, j int) bool { return canonical.Facets[i].Name < canonical.Facets[j].Name })
	canonical.Page.Items = append([]ProtectedQueryPageItem(nil), result.Page.Items...)
	if canonical.Page.Items == nil {
		canonical.Page.Items = []ProtectedQueryPageItem{}
	}
	return canonical
}
