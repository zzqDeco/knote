package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type permissionedPlanContractFixture struct {
	PredicateAllowlistVersion    int      `json:"predicate_allowlist_version"`
	PredicateKeys                []string `json:"predicate_keys"`
	ResourceKindAllowlistVersion int      `json:"resource_kind_allowlist_version"`
	ResourceKinds                []string `json:"resource_kinds"`
}

func TestPermissionedPlanContractAllowlistParity(t *testing.T) {
	fixture := loadPermissionedPlanContractFixture(t)

	if fixture.PredicateAllowlistVersion != ClaimPredicateAllowlistVersion {
		t.Fatalf(
			"predicate_allowlist_version mismatch (fixture=%d, protocol=%d)",
			fixture.PredicateAllowlistVersion,
			ClaimPredicateAllowlistVersion,
		)
	}
	if fixture.ResourceKindAllowlistVersion != GraphResourceKindAllowlistVersion {
		t.Fatalf(
			"resource_kind_allowlist_version mismatch (fixture=%d, protocol=%d)",
			fixture.ResourceKindAllowlistVersion,
			GraphResourceKindAllowlistVersion,
		)
	}

	requireStrictlySortedContractValues(t, "predicate_keys", fixture.PredicateKeys)
	requireStrictlySortedContractValues(t, "resource_kinds", fixture.ResourceKinds)

	predicateKeys := make([]string, 0, len(SupportedClaimPredicateSourceKeys()))
	for index, sourceKey := range SupportedClaimPredicateSourceKeys() {
		predicateKey, err := NewClaimPredicateKey(string(sourceKey))
		if err != nil {
			t.Fatalf("protocol predicate allowlist entry %d is invalid (value omitted)", index)
		}
		predicateKeys = append(predicateKeys, string(predicateKey))
	}
	sort.Strings(predicateKeys)

	resourceKinds := make([]string, 0, len(SupportedGraphResourceKinds()))
	for _, kind := range SupportedGraphResourceKinds() {
		resourceKinds = append(resourceKinds, string(kind))
	}
	sort.Strings(resourceKinds)

	requireExactContractValues(t, "predicate_keys", fixture.PredicateKeys, predicateKeys)
	requireExactContractValues(t, "resource_kinds", fixture.ResourceKinds, resourceKinds)
}

func loadPermissionedPlanContractFixture(t *testing.T) permissionedPlanContractFixture {
	t.Helper()

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal("locate repository root for permissioned plan contract fixture")
	}
	repositoryRoot := filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
	fixturePath := filepath.Join(repositoryRoot, "tests", "fixtures", "permissioned-plan-contract.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read permissioned plan contract fixture: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var fixture permissionedPlanContractFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode permissioned plan contract fixture: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("permissioned plan contract fixture must contain exactly one JSON object")
	}
	return fixture
}

func requireStrictlySortedContractValues(t *testing.T, field string, values []string) {
	t.Helper()
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			t.Fatalf("%s fixture is not strictly sorted at index %d (values omitted)", field, index)
		}
	}
}

func requireExactContractValues(t *testing.T, field string, fixture, protocol []string) {
	t.Helper()

	limit := len(fixture)
	if len(protocol) < limit {
		limit = len(protocol)
	}
	for index := 0; index < limit; index++ {
		if fixture[index] != protocol[index] {
			t.Fatalf(
				"%s mismatch at index %d (values omitted; fixture_count=%d, protocol_count=%d)",
				field,
				index,
				len(fixture),
				len(protocol),
			)
		}
	}
	if len(fixture) != len(protocol) {
		t.Fatalf(
			"%s count mismatch after index %d (values omitted; fixture_count=%d, protocol_count=%d)",
			field,
			limit,
			len(fixture),
			len(protocol),
		)
	}
}
