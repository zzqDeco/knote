package boundarytest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectAgentPackageRemoved(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRoot(), "internal", "agent")); !os.IsNotExist(err) {
		t.Fatalf("internal/agent should not exist in Eino-only runtime, stat err=%v", err)
	}
}

func TestVersionedKnowledgePackageImportBoundary(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "./internal/knowledge/versioned")
	cmd.Dir = repoRoot()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list versioned knowledge imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/runtime",
		"/internal/tui",
		"/internal/repository/" + "local",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("versioned knowledge imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

func TestRuntimePackageImportBoundary(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "./internal/runtime")
	cmd.Dir = repoRoot()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list runtime imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/tui",
		"/internal/knowledge/" + "kag",
		"/internal/repository/" + "local",
		"/internal/" + "kag",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("runtime imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

func TestRuntimeEinoPackageImportBoundary(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "./internal/runtime/eino")
	cmd.Dir = repoRoot()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list runtime/eino imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/tui",
		"/internal/agent",
		"/internal/knowledge/" + "kag",
		"/internal/repository/" + "local",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("runtime/eino imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

func TestTUIPackageImportBoundary(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "./internal/tui")
	cmd.Dir = repoRoot()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list tui imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/knowledge",
		"/internal/repository",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("tui imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

func repoRoot() string {
	return filepath.Clean(filepath.Join("..", ".."))
}
