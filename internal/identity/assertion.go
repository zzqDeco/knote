package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const maxSignedAssertionSize = 64 << 10

type AssertionClaims struct {
	ProviderID string    `json:"provider_id"`
	Issuer     string    `json:"issuer"`
	Audience   string    `json:"audience"`
	Subject    string    `json:"subject"`
	TenantID   string    `json:"tenant_id"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Nonce      string    `json:"nonce"`
}

// AssertionVerifier owns provider-specific signature and trust-chain checks.
// Its errors are never propagated by Gateway because provider implementations
// may otherwise include bearer material in diagnostic strings.
type AssertionVerifier interface {
	Verify(context.Context, []byte) (AssertionClaims, error)
}

type AssertionVerifierFunc func(context.Context, []byte) (AssertionClaims, error)

func (f AssertionVerifierFunc) Verify(ctx context.Context, assertion []byte) (AssertionClaims, error) {
	if f == nil {
		return AssertionClaims{}, ErrAssertionRejected
	}
	return f(ctx, assertion)
}

// Ed25519AssertionVerifier is a provider-neutral reference verifier for a
// compact "base64url(payload).base64url(signature)" assertion. The signed JSON
// payload is exactly AssertionClaims and unknown or duplicate fields fail closed.
type Ed25519AssertionVerifier struct {
	publicKey ed25519.PublicKey
}

func NewEd25519AssertionVerifier(publicKey ed25519.PublicKey) (*Ed25519AssertionVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &Ed25519AssertionVerifier{publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

func (v *Ed25519AssertionVerifier) Verify(ctx context.Context, assertion []byte) (AssertionClaims, error) {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize || ctx == nil ||
		len(assertion) == 0 || len(assertion) > maxSignedAssertionSize {
		return AssertionClaims{}, ErrAssertionRejected
	}
	if err := ctx.Err(); err != nil {
		return AssertionClaims{}, err
	}
	encodedPayload, encodedSignature, ok := strings.Cut(string(assertion), ".")
	if !ok || encodedPayload == "" || encodedSignature == "" || strings.Contains(encodedSignature, ".") {
		return AssertionClaims{}, ErrAssertionRejected
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encodedPayload {
		return AssertionClaims{}, ErrAssertionRejected
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != encodedSignature {
		return AssertionClaims{}, ErrAssertionRejected
	}
	if !ed25519.Verify(v.publicKey, payload, signature) {
		return AssertionClaims{}, ErrAssertionRejected
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return AssertionClaims{}, ErrAssertionRejected
	}
	if err := validateAssertionJSONShape(payload); err != nil {
		return AssertionClaims{}, ErrAssertionRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var claims AssertionClaims
	if err := decoder.Decode(&claims); err != nil {
		return AssertionClaims{}, ErrAssertionRejected
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return AssertionClaims{}, ErrAssertionRejected
	}
	if err := ctx.Err(); err != nil {
		return AssertionClaims{}, err
	}
	return claims, nil
}

func validateAssertionJSONShape(payload []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || len(fields) != 8 {
		return ErrAssertionRejected
	}
	for _, name := range []string{
		"provider_id", "issuer", "audience", "subject", "tenant_id", "issued_at", "expires_at", "nonce",
	} {
		if _, ok := fields[name]; !ok {
			return ErrAssertionRejected
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var consumeValue func() error
	consumeValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrAssertionRejected
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrAssertionRejected
				}
				seen[key] = struct{}{}
				if err := consumeValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrAssertionRejected
			}
		case '[':
			for decoder.More() {
				if err := consumeValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrAssertionRejected
			}
		default:
			return ErrAssertionRejected
		}
		return nil
	}
	if err := consumeValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrAssertionRejected
	}
	return nil
}

var _ AssertionVerifier = (*Ed25519AssertionVerifier)(nil)
