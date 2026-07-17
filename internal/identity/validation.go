package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	maxCanonicalIDLength = 128
	maxURIValueLength    = 2048
)

func validateCanonicalID(name, value string) error {
	if value == "" || len(value) > maxCanonicalIDLength {
		return fmt.Errorf("%w: %s is empty or too long", ErrInvalidInput, name)
	}
	for index, character := range []byte(value) {
		allowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' || character == ':' || character == '@'
		if !allowed || index == 0 && !isASCIIAlphaNumeric(character) {
			return fmt.Errorf("%w: %s is not a canonical opaque identifier", ErrInvalidInput, name)
		}
	}
	return nil
}

func validateAuthorizationID(name, value string) error {
	if err := validateCanonicalID(name, value); err != nil {
		return err
	}
	if strings.ContainsAny(value, ":#") {
		return fmt.Errorf("%w: %s is not a concrete authorization identifier", ErrInvalidInput, name)
	}
	return nil
}

func validateDisplayName(value string) error {
	if len(value) > 256 || value != strings.TrimSpace(value) {
		return fmt.Errorf("%w: display_name is invalid", ErrInvalidInput)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%w: display_name is invalid", ErrInvalidInput)
		}
	}
	return nil
}

func validateProviderSpec(spec ProviderSpec) error {
	if err := validateCanonicalID("provider_id", spec.ProviderID); err != nil {
		return err
	}
	if err := validateTrustURI("issuer", spec.Issuer); err != nil {
		return err
	}
	if len(spec.Audiences) == 0 {
		return fmt.Errorf("%w: audiences are required", ErrInvalidInput)
	}
	for index, audience := range spec.Audiences {
		if err := validateAudience(audience); err != nil {
			return err
		}
		if index > 0 && audience <= spec.Audiences[index-1] {
			return fmt.Errorf("%w: audiences must be sorted and unique", ErrInvalidInput)
		}
	}
	return nil
}

func (s ProviderSpec) Validate() error {
	_, err := canonicalProviderSpec(s)
	return err
}

func (r ExternalResourceRef) Validate() error {
	if err := validateCanonicalID("provider_id", r.ProviderID); err != nil {
		return err
	}
	return validateCanonicalID("external_id", r.ExternalID)
}

func validateAudience(value string) error {
	if validateCanonicalID("audience", value) == nil {
		return nil
	}
	return validateTrustURI("audience", value)
}

func canonicalProviderSpec(spec ProviderSpec) (ProviderSpec, error) {
	spec.Audiences = append([]string(nil), spec.Audiences...)
	slices.Sort(spec.Audiences)
	spec.Audiences = slices.Compact(spec.Audiences)
	if err := validateProviderSpec(spec); err != nil {
		return ProviderSpec{}, err
	}
	return spec, nil
}

func validateTrustURI(name, value string) error {
	if value == "" || len(value) > maxURIValueLength || value != strings.TrimSpace(value) {
		return fmt.Errorf("%w: %s is invalid", ErrInvalidInput, name)
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return fmt.Errorf("%w: %s is invalid", ErrInvalidInput, name)
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: %s is invalid", ErrInvalidInput, name)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "urn" {
		return fmt.Errorf("%w: %s must use https or urn", ErrInvalidInput, name)
	}
	if parsed.Scheme == "https" && parsed.Host == "" {
		return fmt.Errorf("%w: %s is invalid", ErrInvalidInput, name)
	}
	return nil
}

func validateUTC(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC {
		return fmt.Errorf("%w: %s must be a non-zero UTC timestamp", ErrInvalidInput, name)
	}
	return nil
}

func stableResourceID(prefix, tenantID, providerID, externalID string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID, providerID, externalID}, "\x00")))
	return prefix + hex.EncodeToString(sum[:16])
}

func tenantFileKey(tenantID string) string {
	sum := sha256.Sum256([]byte(tenantID))
	return hex.EncodeToString(sum[:])
}

func watermarkFor(tenantID string, number uint64, previous, digest string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s", tenantID, number, previous, digest)))
	return fmt.Sprintf("identity_%020d_%s", number, hex.EncodeToString(sum[:16]))
}

func validateDigest(name, value string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return fmt.Errorf("%w: %s is invalid", ErrStoreUnavailable, name)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, prefix)); err != nil {
		return fmt.Errorf("%w: %s is invalid", ErrStoreUnavailable, name)
	}
	return nil
}

func validateScope(scope protocol.TenantScope) error {
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("%w: tenant scope is invalid", ErrInvalidInput)
	}
	return nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
