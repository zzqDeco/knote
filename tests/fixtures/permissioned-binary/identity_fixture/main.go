package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	tenantID   = "tenant_permissioned_binary"
	providerID = "provider-permissioned-binary"
	principal  = "principal_permissioned_binary_canary_78"
	subject    = "subject-permissioned-binary"
	issuer     = "https://identity.permissioned-binary.test"
	audience   = "knote-permissioned-binary"
)

type fixtureManifest struct {
	StorePath         string   `json:"store_path"`
	PublicKey         string   `json:"public_key"`
	AssertionPaths    []string `json:"assertion_paths"`
	IdentityWatermark string   `json:"identity_watermark"`
}

type revisionManifest struct {
	IdentityWatermark string `json:"identity_watermark"`
}

func main() {
	mode := flag.String("mode", "init", "fixture operation: init or bump")
	root := flag.String("root", "", "absolute fixture root")
	count := flag.Int("count", 24, "number of one-shot assertions to create")
	generation := flag.Int("generation", 2, "SCIM generation used by bump")
	flag.Parse()

	if !filepath.IsAbs(*root) {
		fatalf("fixture root must be absolute")
	}
	var err error
	switch *mode {
	case "init":
		err = initialize(*root, *count)
	case "bump":
		err = bump(*root, *generation)
	default:
		err = fmt.Errorf("unsupported fixture mode %q", *mode)
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func initialize(root string, count int) error {
	if count < 1 || count > 128 {
		return fmt.Errorf("assertion count must be between 1 and 128")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	storePath := filepath.Join(root, "store")
	store, err := identity.OpenLocalStore(storePath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	scope := fixtureScope()
	if _, err := store.RegisterTenant(ctx, scope); err != nil {
		return err
	}
	if _, _, err := store.UpsertProvider(ctx, scope, identity.ProviderSpec{
		ProviderID: providerID,
		Issuer:     issuer,
		Audiences:  []string{audience},
	}); err != nil {
		return err
	}
	if _, _, err := store.UpsertUser(ctx, scope, identity.UserUpsert{
		ProviderID:        providerID,
		ExternalID:        "user-permissioned-binary",
		ExternalSubjectID: subject,
		PrincipalID:       principal,
		Active:            true,
	}); err != nil {
		return err
	}

	seed := sha256.Sum256([]byte("knote-permissioned-binary-ed25519-fixture-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	assertionsDirectory := filepath.Join(root, "assertions")
	if err := os.MkdirAll(assertionsDirectory, 0o700); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	paths := make([]string, 0, count)
	for index := 1; index <= count; index++ {
		claims := identity.AssertionClaims{
			ProviderID: providerID,
			Issuer:     issuer,
			Audience:   audience,
			Subject:    subject,
			TenantID:   tenantID,
			IssuedAt:   now.Add(-time.Minute),
			ExpiresAt:  now.Add(time.Hour),
			Nonce:      fmt.Sprintf("nonce-permissioned-binary-%04d", index),
		}
		assertion, err := signAssertion(privateKey, claims)
		if err != nil {
			return err
		}
		path := filepath.Join(assertionsDirectory, fmt.Sprintf("assertion-%04d.txt", index))
		if err := writePrivate(path, assertion); err != nil {
			return err
		}
		paths = append(paths, path)
	}
	revision, err := store.CurrentRevision(ctx, scope)
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, fixtureManifest{
		StorePath:         storePath,
		PublicKey:         base64.RawURLEncoding.EncodeToString(publicKey),
		AssertionPaths:    paths,
		IdentityWatermark: revision.Watermark,
	})
}

func bump(root string, generation int) error {
	if generation < 2 {
		return fmt.Errorf("bump generation must be at least 2")
	}
	store, err := identity.OpenLocalStore(filepath.Join(root, "store"))
	if err != nil {
		return err
	}
	ctx := context.Background()
	scope := fixtureScope()
	externalID := fmt.Sprintf("group-permissioned-binary-%d", generation)
	if _, _, err := store.UpsertGroup(ctx, scope, identity.GroupUpsert{
		ProviderID:  providerID,
		ExternalID:  externalID,
		GroupID:     fmt.Sprintf("permissioned-binary-group-%d", generation),
		DisplayName: fmt.Sprintf("Permissioned Binary Group %d", generation),
		Active:      true,
	}); err != nil {
		return err
	}
	if _, _, err := store.UpsertMembership(ctx, scope, identity.MembershipUpsert{
		ProviderID:      providerID,
		GroupExternalID: externalID,
		UserExternalID:  "user-permissioned-binary",
		Active:          true,
	}); err != nil {
		return err
	}
	revision, err := store.CurrentRevision(ctx, scope)
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, revisionManifest{IdentityWatermark: revision.Watermark})
}

func fixtureScope() protocol.TenantScope {
	return protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: tenantID,
		Region:   "test-local",
	}
}

func signAssertion(privateKey ed25519.PrivateKey, claims identity.AssertionClaims) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return []byte(encodedPayload + "." + encodedSignature), nil
}

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeJSON(file *os.File, value any) error {
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(2)
}
