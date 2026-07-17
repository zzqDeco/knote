//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/protocol"
)

type identityControlProcessResult struct {
	stdout []byte
	stderr []byte
	err    error
}

func TestIdentityControlBuiltBinaryAcceptance(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "knote")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build knote: %v\n%s", err, output)
	}

	commandDirectory := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "identity-store")
	scope := `"scope":{"version":"v1","tenant_id":"tenant-control","region":"cn-east"}`
	requests := [][]byte{
		[]byte(`{"version":"v1","operation":"tenant.register",` + scope + `,"input":{}}`),
		[]byte(`{"version":"v1","operation":"provider.register",` + scope + `,"input":{"provider_id":"provider-main","issuer":"https://identity.secret.example.test","audiences":["knote-cli"]}}`),
		[]byte(`{"version":"v1","operation":"user.upsert",` + scope + `,"input":{"provider_id":"provider-main","external_id":"alice-external","external_subject_id":"alice-subject-secret","principal_id":"alice-principal"}}`),
		[]byte(`{"version":"v1","operation":"user.upsert",` + scope + `,"input":{"provider_id":"provider-main","external_id":"bob-external","external_subject_id":"bob-subject-secret","principal_id":"bob-principal"}}`),
		[]byte(`{"version":"v1","operation":"group.upsert",` + scope + `,"input":{"provider_id":"provider-main","external_id":"engineering-external","group_id":"engineering-grant","display_name":"Secret Engineering"}}`),
		[]byte(`{"version":"v1","operation":"membership.upsert",` + scope + `,"input":{"provider_id":"provider-main","group_external_id":"engineering-external","user_external_id":"alice-external","active":true}}`),
		[]byte(`{"version":"v1","operation":"membership.replace",` + scope + `,"input":{"provider_id":"provider-main","group_external_id":"engineering-external","user_external_ids":["bob-external"]}}`),
	}
	var receipts []identityControlReceipt
	for _, request := range requests {
		result := runIdentityControlBinary(t, binary, commandDirectory, storePath, request, identityControlDigest(request))
		receipts = append(receipts, assertIdentityControlSuccess(t, result, request))
	}

	store, err := identity.OpenLocalStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	tenantScope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: "tenant-control", Region: "cn-east",
	}
	snapshot, err := store.Snapshot(t.Context(), tenantScope)
	if err != nil {
		t.Fatal(err)
	}
	var bobID string
	for _, user := range snapshot.Users {
		if user.ExternalID == "bob-external" {
			bobID = user.ID
		}
	}
	if bobID == "" || len(snapshot.Groups) != 1 || !slices.Equal(snapshot.Groups[0].MemberUserIDs, []string{bobID}) {
		t.Fatalf("membership.replace state = users:%+v groups:%+v", snapshot.Users, snapshot.Groups)
	}

	deprovisionRequests := [][]byte{
		[]byte(`{"version":"v1","operation":"user.deprovision",` + scope + `,"input":{"provider_id":"provider-main","external_id":"alice-external"}}`),
		[]byte(`{"version":"v1","operation":"group.deprovision",` + scope + `,"input":{"provider_id":"provider-main","external_id":"engineering-external"}}`),
	}
	for _, request := range deprovisionRequests {
		result := runIdentityControlBinary(t, binary, commandDirectory, storePath, request, identityControlDigest(request))
		receipts = append(receipts, assertIdentityControlSuccess(t, result, request))
	}
	snapshot, err = store.Snapshot(t.Context(), tenantScope)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Users[0].State != protocol.IdentityDeprovisioned ||
		snapshot.Groups[0].State != protocol.IdentityDeprovisioned || len(snapshot.Groups[0].MemberUserIDs) != 0 {
		t.Fatalf("deprovisioned identity state = users:%+v groups:%+v", snapshot.Users, snapshot.Groups)
	}
	for index := 1; index < len(receipts); index++ {
		if receipts[index].RevisionNumber <= receipts[index-1].RevisionNumber {
			t.Fatalf("receipt revisions are not monotonic: %+v", receipts)
		}
	}
	if _, err := os.Stat(filepath.Join(commandDirectory, ".knote")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity control initialized workspace config: %v", err)
	}

	first := requests[0]
	repeat := runIdentityControlBinary(t, binary, commandDirectory, storePath, first, identityControlDigest(first))
	repeatReceipt := assertIdentityControlSuccess(t, repeat, first)
	latest := receipts[len(receipts)-1]
	if repeatReceipt.Changed || repeatReceipt.RevisionNumber != latest.RevisionNumber ||
		repeatReceipt.IdentityWatermark != latest.IdentityWatermark {
		t.Fatalf("idempotent tenant receipt = %+v, latest = %+v", repeatReceipt, latest)
	}
}

func TestIdentityControlBuiltBinaryRejectsUnconfirmedOrNonStrictRequestsBeforeSideEffects(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "knote")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build knote: %v\n%s", err, output)
	}
	valid := []byte(`{"version":"v1","operation":"tenant.register","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{}}`)
	tests := []struct {
		name         string
		request      []byte
		confirmation string
	}{
		{name: "wrong confirmation", request: valid, confirmation: "sha256:" + strings.Repeat("0", 64)},
		{name: "unknown field", request: []byte(`{"version":"v1","operation":"tenant.register","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{},"secret":"must-not-echo"}`)},
		{name: "unknown operation", request: []byte(`{"version":"v1","operation":"tenant.destroy","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{}}`)},
		{name: "duplicate field", request: []byte(`{"version":"v1","version":"v1","operation":"tenant.register","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{}}`)},
		{name: "trailing value", request: append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{name: "missing required active", request: []byte(`{"version":"v1","operation":"membership.upsert","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{"provider_id":"provider-main","group_external_id":"group-external","user_external_id":"user-external"}}`)},
		{name: "missing provider fields", request: []byte(`{"version":"v1","operation":"provider.register","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{}}`)},
		{name: "missing user fields", request: []byte(`{"version":"v1","operation":"user.upsert","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{"provider_id":"provider-main"}}`)},
		{name: "missing user deprovision fields", request: []byte(`{"version":"v1","operation":"user.deprovision","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{}}`)},
		{name: "missing group fields", request: []byte(`{"version":"v1","operation":"group.upsert","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{"provider_id":"provider-main"}}`)},
		{name: "missing group deprovision fields", request: []byte(`{"version":"v1","operation":"group.deprovision","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{}}`)},
		{name: "missing membership fields", request: []byte(`{"version":"v1","operation":"membership.upsert","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{"active":true}}`)},
		{name: "missing membership replacement fields", request: []byte(`{"version":"v1","operation":"membership.replace","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{"user_external_ids":[]}}`)},
		{name: "invalid provider semantics", request: []byte(`{"version":"v1","operation":"provider.register","scope":{"version":"v1","tenant_id":"tenant-rejected","region":"cn-east"},"input":{"provider_id":"provider-main","issuer":"http://insecure.example.test","audiences":["knote-cli"]}}`)},
		{name: "oversized", request: bytes.Repeat([]byte(" "), maxIdentityControlRequestSize+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "identity-store")
			commandDirectory := t.TempDir()
			confirmation := test.confirmation
			if confirmation == "" {
				confirmation = identityControlDigest(test.request)
			}
			result := runIdentityControlBinary(t, binary, commandDirectory, storePath, test.request, confirmation)
			if result.err == nil || len(result.stdout) != 0 || string(result.stderr) != errIdentityControlRejected.Error()+"\n" {
				t.Fatalf("rejection = err:%v stdout:%q stderr:%q", result.err, result.stdout, result.stderr)
			}
			if bytes.Contains(result.stderr, []byte("must-not-echo")) || bytes.Contains(result.stderr, test.request) {
				t.Fatalf("rejection disclosed request: %q", result.stderr)
			}
			if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected request created identity store: %v", err)
			}
			if _, err := os.Stat(filepath.Join(commandDirectory, ".knote")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected request initialized workspace config: %v", err)
			}
		})
	}
}

func runIdentityControlBinary(
	t *testing.T,
	binary string,
	directory string,
	storePath string,
	request []byte,
	confirmation string,
) identityControlProcessResult {
	t.Helper()
	requestFile, err := os.CreateTemp(t.TempDir(), "identity-control-request-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer requestFile.Close()
	if _, err := requestFile.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := requestFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(
		binary, identityControlCommand, "--request-fd=3", "--confirm="+confirmation,
	)
	command.Dir = directory
	command.Env = identityControlProcessEnv(storePath)
	command.ExtraFiles = []*os.File{requestFile}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	return identityControlProcessResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), err: err}
}

func identityControlProcessEnv(storePath string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	prefix := identityStorePathEnv + "="
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, prefix) {
			environment = append(environment, entry)
		}
	}
	return append(environment, prefix+storePath)
}

func assertIdentityControlSuccess(
	t *testing.T,
	result identityControlProcessResult,
	request []byte,
) identityControlReceipt {
	t.Helper()
	if result.err != nil || len(result.stderr) != 0 {
		t.Fatalf("identity control result = err:%v stdout:%q stderr:%q", result.err, result.stdout, result.stderr)
	}
	if len(result.stdout) == 0 || result.stdout[len(result.stdout)-1] != '\n' || bytes.Count(result.stdout, []byte("\n")) != 1 {
		t.Fatalf("receipt framing = %q", result.stdout)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result.stdout, &fields); err != nil {
		t.Fatalf("decode receipt fields: %v", err)
	}
	wantFields := []string{"changed", "identity_watermark", "request_digest", "revision_number", "version"}
	gotFields := make([]string, 0, len(fields))
	for field := range fields {
		gotFields = append(gotFields, field)
	}
	slices.Sort(gotFields)
	if !slices.Equal(gotFields, wantFields) {
		t.Fatalf("receipt fields = %v, want %v", gotFields, wantFields)
	}
	var receipt identityControlReceipt
	if err := json.Unmarshal(result.stdout, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Version != protocol.EnterpriseContractVersion ||
		receipt.RequestDigest != identityControlDigest(request) || receipt.RevisionNumber == 0 ||
		receipt.IdentityWatermark == "" {
		t.Fatalf("receipt = %+v", receipt)
	}
	for _, secret := range []string{
		"tenant-control", "provider-main", "identity.secret.example.test", "alice-external",
		"alice-subject-secret", "alice-principal", "bob-external", "bob-subject-secret",
		"bob-principal", "engineering-external", "engineering-grant", "Secret Engineering",
	} {
		if bytes.Contains(result.stdout, []byte(secret)) || bytes.Contains(result.stderr, []byte(secret)) {
			t.Fatalf("control result disclosed %q: stdout:%q stderr:%q", secret, result.stdout, result.stderr)
		}
	}
	return receipt
}

func TestIdentityControlRequestDigestIsCanonical(t *testing.T) {
	request := []byte(`{"version":"v1"}`)
	digest := identityControlDigest(request)
	if !isCanonicalIdentityControlDigest(digest) ||
		isCanonicalIdentityControlDigest(strings.ToUpper(digest)) ||
		isCanonicalIdentityControlDigest(fmt.Sprintf("%s0", digest)) {
		t.Fatalf("canonical digest validation failed for %q", digest)
	}
}
