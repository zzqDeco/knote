package identity

import (
	"testing"
	"time"
)

func TestIdentityUTCValidationAcceptsRFC3339ZeroOffset(t *testing.T) {
	zeroOffset, err := time.Parse(time.RFC3339, "2026-07-18T00:00:00+00:00")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateUTC("issued_at", zeroOffset); err != nil {
		t.Fatalf("zero-offset RFC3339 timestamp was rejected: %v", err)
	}

	nonUTC, err := time.Parse(time.RFC3339, "2026-07-18T08:00:00+08:00")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateUTC("issued_at", nonUTC); err == nil {
		t.Fatal("non-zero-offset timestamp was accepted")
	}
}
