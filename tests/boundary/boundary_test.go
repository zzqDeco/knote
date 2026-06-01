package boundarytest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentPackageImportBoundary(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "./internal/agent")
	cmd.Dir = repoRoot()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list agent imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/repository/" + "local",
		"/internal/knowledge/" + "kag",
		"/internal/" + "artifact",
		"/internal/" + "evalstore",
		"/internal/" + "gitstore",
		"/internal/" + "kag",
		"/internal/" + "runtime",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("agent imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

func TestAgentProductionCodeHasNoFilesystemOrProcessSideEffects(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(), "internal", "agent", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{"os.ReadFile", "os.WriteFile", "exec.Command"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden side-effect primitive %s", file, forbidden)
			}
		}
	}
}

func repoRoot() string {
	return filepath.Clean(filepath.Join("..", ".."))
}
