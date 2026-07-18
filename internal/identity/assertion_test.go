package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEd25519AssertionVerifierStrictlyVerifiesClaims(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519AssertionVerifier(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	claims := AssertionClaims{
		ProviderID: "provider-main", Issuer: "https://identity.example.test", Audience: "knote-cli",
		Subject: "subject-assertion", TenantID: "tenant-assertion",
		IssuedAt:  time.Date(2026, 7, 17, 5, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC), Nonce: "nonce-assertion-001",
	}
	assertion := signTestClaims(t, privateKey, claims)
	got, err := verifier.Verify(context.Background(), assertion)
	if err != nil || !reflect.DeepEqual(got, claims) {
		t.Fatalf("verified claims = %+v, %v", got, err)
	}

	// The verifier owns a defensive copy of its trust key.
	publicKey[0] ^= 0xff
	if _, err := verifier.Verify(context.Background(), assertion); err != nil {
		t.Fatalf("caller mutation changed verifier key: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unknownPayload := append([]byte(nil), payload[:len(payload)-1]...)
	unknownPayload = append(unknownPayload, []byte(`,"credential":"must-not-appear"}`)...)
	cases := map[string][]byte{
		"duplicate field": signTestPayload(privateKey, []byte(`{"provider_id":"one","provider_id":"two"}`)),
		"unknown field":   signTestPayload(privateKey, unknownPayload),
		"wrong field case": signTestPayload(privateKey, []byte(strings.Replace(
			string(payload), `"provider_id"`, `"Provider_ID"`, 1,
		))),
		"missing field": signTestPayload(privateKey, []byte(`{"provider_id":"provider-main"}`)),
		"trailing json": signTestPayload(privateKey, append(append([]byte(nil), payload...), []byte(` {}`)...)),
	}
	tampered := append([]byte(nil), assertion...)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	cases["bad signature"] = tampered
	cases["malformed compact value"] = []byte("bearer-material-without-a-signature")

	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), candidate)
			if !errors.Is(err, ErrAssertionRejected) || err.Error() != ErrAssertionRejected.Error() {
				t.Fatalf("verification error = %v", err)
			}
		})
	}
}

func TestEd25519AssertionVerifierHonorsCancellation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519AssertionVerifier(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.Verify(ctx, []byte("secret-bearer")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification = %v", err)
	}
}
