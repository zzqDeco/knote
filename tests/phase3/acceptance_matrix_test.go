package phase3_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	acceptanceManifestVersion = "phase3-acceptance.v1"
	acceptanceIssue           = 97
)

type acceptanceManifest struct {
	Version    string                `json:"version"`
	Issue      int                   `json:"issue"`
	FalseAllow int                   `json:"false_allow"`
	Invariants []acceptanceInvariant `json:"invariants"`
	Budgets    []acceptanceBudget    `json:"budgets"`
}

type acceptanceInvariant struct {
	ID          string       `json:"id"`
	Requirement string       `json:"requirement"`
	SampleCount int          `json:"sample_count"`
	Anchors     []testAnchor `json:"anchors"`
}

type acceptanceBudget struct {
	ID                 string       `json:"id"`
	Metric             string       `json:"metric"`
	Percentile         string       `json:"percentile"`
	SampleCount        int          `json:"sample_count"`
	BudgetMilliseconds int          `json:"budget_milliseconds"`
	Anchors            []testAnchor `json:"anchors"`
}

type testAnchor struct {
	File string `json:"file"`
	Test string `json:"test"`
}

type expectedInvariant struct {
	ID          string
	Requirement string
}

type expectedBudget struct {
	ID         string
	Metric     string
	Percentile string
}

var expectedInvariants = []expectedInvariant{
	{
		ID:          "audit-content-free-tamper-evident",
		Requirement: "Audit remains content free and tamper evidence is detected.",
	},
	{
		ID:          "connector-acl-failure-never-serves",
		Requirement: "Connector content plus ACL failure never serves.",
	},
	{
		ID:          "durable-connector-convergence",
		Requirement: "Duplicate and reordered events, crashes, DLQ replay, tombstones, and full reconciliation converge correctly.",
	},
	{
		ID:          "false-allow-zero",
		Requirement: "False allow equals zero across the complete matrix.",
	},
	{
		ID:          "identity-fail-closed-replay-safe",
		Requirement: "SSO assertion and SCIM provisioning and deprovisioning behavior is fail closed and replay safe.",
	},
	{
		ID:          "operational-latency-budgets",
		Requirement: "BatchCheck, connector lag, replay, reconciliation, revocation, and governance latency budgets are documented and met.",
	},
	{
		ID:          "residency-blocks-storage-egress",
		Requirement: "Residency violations block storage and egress.",
	},
	{
		ID:          "simulation-read-only-oracle-parity",
		Requirement: "Simulation is non-mutating and impact results match the policy oracle.",
	},
	{
		ID:          "tenant-collision-isolation",
		Requirement: "Two tenants with colliding external IDs cannot observe each other.",
	},
	{
		ID:          "tool-invocation-and-results-authorized",
		Requirement: "Tool invocation and every returned resource are authorized.",
	},
	{
		ID:          "unauthorized-observability-hidden",
		Requirement: "Unauthorized existence, count, pagination, errors, traces, telemetry, and governance views do not leak.",
	},
	{
		ID:          "user-agent-task-intersection",
		Requirement: "User, agent, and task intersection is enforced on retrieval, traversal, generation, cache, citation, and session replay.",
	},
}

var expectedBudgets = []expectedBudget{
	{ID: "batch-check-latency", Metric: "openfga_batch_check", Percentile: "p99"},
	{ID: "connector-lag", Metric: "connector_apply_lag", Percentile: "max"},
	{ID: "governance-latency", Metric: "governance_view", Percentile: "max"},
	{ID: "reconciliation-latency", Metric: "full_reconciliation", Percentile: "max"},
	{ID: "replay-latency", Metric: "session_replay", Percentile: "max"},
	{ID: "revocation-latency", Metric: "revocation_propagation", Percentile: "p99"},
}

func TestPhase3AcceptanceMatrix(t *testing.T) {
	repositoryRoot := phase3RepositoryRoot(t)
	manifestPath := filepath.Join(repositoryRoot, "tests", "fixtures", "phase3-acceptance.json")
	raw, manifest := readAcceptanceManifest(t, manifestPath)

	t.Run("canonical manifest", func(t *testing.T) {
		canonical, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatalf("marshal canonical manifest: %v", err)
		}
		canonical = append(canonical, '\n')
		if !bytes.Equal(raw, canonical) {
			t.Fatal("phase3 acceptance manifest is not canonical JSON")
		}
	})

	t.Run("complete invariant matrix", func(t *testing.T) {
		if manifest.Version != acceptanceManifestVersion {
			t.Fatalf("manifest version = %q, want %q", manifest.Version, acceptanceManifestVersion)
		}
		if manifest.Issue != acceptanceIssue {
			t.Fatalf("manifest issue = %d, want %d", manifest.Issue, acceptanceIssue)
		}
		if manifest.FalseAllow != 0 {
			t.Fatalf("false_allow = %d, want 0", manifest.FalseAllow)
		}
		if len(manifest.Invariants) != len(expectedInvariants) {
			t.Fatalf("invariant count = %d, want %d", len(manifest.Invariants), len(expectedInvariants))
		}

		for index, expected := range expectedInvariants {
			invariant := manifest.Invariants[index]
			if invariant.ID != expected.ID {
				t.Fatalf("invariant %d id = %q, want %q", index, invariant.ID, expected.ID)
			}
			if invariant.Requirement != expected.Requirement {
				t.Fatalf("invariant %q requirement = %q, want %q", invariant.ID, invariant.Requirement, expected.Requirement)
			}
			if invariant.SampleCount <= 0 {
				t.Fatalf("invariant %q sample_count = %d, want a positive cohort", invariant.ID, invariant.SampleCount)
			}
			if len(invariant.Anchors) == 0 {
				t.Fatalf("invariant %q has no test anchors", invariant.ID)
			}
			if invariant.SampleCount < len(invariant.Anchors) {
				t.Fatalf("invariant %q sample_count = %d, smaller than %d anchors", invariant.ID, invariant.SampleCount, len(invariant.Anchors))
			}
			validateAnchors(t, repositoryRoot, "invariant "+invariant.ID, invariant.Anchors)
		}
	})

	t.Run("documented operational budgets", func(t *testing.T) {
		if len(manifest.Budgets) != len(expectedBudgets) {
			t.Fatalf("budget count = %d, want %d", len(manifest.Budgets), len(expectedBudgets))
		}
		for index, expected := range expectedBudgets {
			budget := manifest.Budgets[index]
			if budget.ID != expected.ID || budget.Metric != expected.Metric || budget.Percentile != expected.Percentile {
				t.Fatalf("budget %d identity = %q/%q/%q, want %q/%q/%q",
					index, budget.ID, budget.Metric, budget.Percentile,
					expected.ID, expected.Metric, expected.Percentile)
			}
			if budget.SampleCount <= 0 {
				t.Fatalf("budget %q sample_count = %d, want a positive cohort", budget.ID, budget.SampleCount)
			}
			if budget.BudgetMilliseconds <= 0 {
				t.Fatalf("budget %q budget_milliseconds = %d, want a positive limit", budget.ID, budget.BudgetMilliseconds)
			}
			if len(budget.Anchors) == 0 {
				t.Fatalf("budget %q has no test anchors", budget.ID)
			}
			validateAnchors(t, repositoryRoot, "budget "+budget.ID, budget.Anchors)
		}
	})
}

func readAcceptanceManifest(t *testing.T, path string) ([]byte, acceptanceManifest) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read acceptance manifest: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest acceptanceManifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode acceptance manifest: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("acceptance manifest has trailing data: %v", err)
	}
	return raw, manifest
}

func validateAnchors(t *testing.T, repositoryRoot, owner string, anchors []testAnchor) {
	t.Helper()
	previous := ""
	for index, anchor := range anchors {
		key := anchor.File + "#" + anchor.Test
		if index > 0 && key <= previous {
			t.Fatalf("%s anchors are not strictly sorted: %q follows %q", owner, key, previous)
		}
		previous = key
		validateGoTestAnchor(t, repositoryRoot, owner, anchor)
	}
}

func validateGoTestAnchor(t *testing.T, repositoryRoot, owner string, anchor testAnchor) {
	t.Helper()
	if anchor.File == "" || anchor.Test == "" {
		t.Fatalf("%s contains an empty anchor: %+v", owner, anchor)
	}
	if filepath.IsAbs(anchor.File) || filepath.ToSlash(filepath.Clean(anchor.File)) != anchor.File ||
		anchor.File == ".." || strings.HasPrefix(anchor.File, "../") {
		t.Fatalf("%s anchor has a non-canonical repository path: %q", owner, anchor.File)
	}
	if !strings.HasSuffix(anchor.File, "_test.go") {
		t.Fatalf("%s anchor is not a Go test file: %q", owner, anchor.File)
	}
	if !strings.HasPrefix(anchor.Test, "Test") {
		t.Fatalf("%s anchor is not a Go test function: %q", owner, anchor.Test)
	}

	path := filepath.Join(repositoryRoot, filepath.FromSlash(anchor.File))
	relative, err := filepath.Rel(repositoryRoot, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("%s anchor escapes the repository: %q", owner, anchor.File)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s anchor file %q: %v", owner, anchor.File, err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == anchor.Test && isGoTestFunction(function) {
			return
		}
	}
	t.Fatalf("%s anchor %s is not an exact TestXxx(*testing.T) declaration", owner, keyForAnchor(anchor))
}

func isGoTestFunction(function *ast.FuncDecl) bool {
	if function.Recv != nil || function.Type.TypeParams != nil || function.Type.Results != nil ||
		function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return false
	}
	parameter := function.Type.Params.List[0]
	if len(parameter.Names) > 1 {
		return false
	}
	pointer, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "T"
}

func keyForAnchor(anchor testAnchor) string {
	return fmt.Sprintf("%s#%s", anchor.File, anchor.Test)
}

func phase3RepositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve acceptance test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
}
