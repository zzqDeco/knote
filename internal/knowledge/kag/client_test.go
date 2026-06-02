package kag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientReadsLargeNDJSONLine(t *testing.T) {
	workspace := t.TempDir()
	adapter := filepath.Join(workspace, "adapter.py")
	largeAnswer := strings.Repeat("x", 128*1024)
	script := `import json
print(json.dumps({"id":"req","type":"result","data":{"answer":"` + largeAnswer + `"}}))
`
	if err := os.WriteFile(adapter, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KNOTE_PYTHON", pythonForTest())

	resp, err := Client{AdapterPath: adapter, Workspace: workspace}.Query(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data["answer"]; got != largeAnswer {
		t.Fatalf("large answer mismatch: %T", got)
	}
}

func TestResolveAdapterPathChecksExecutableParents(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	cwd := t.TempDir()
	rel := filepath.Join("adapters", "kag", "knote_kag_adapter.py")
	adapter := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(adapter), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter, []byte("adapter"), 0o644); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin", "knote")

	got := resolveAdapterPath(rel, workspace, cwd, executable)
	if got != adapter {
		t.Fatalf("resolved adapter path = %q, want %q", got, adapter)
	}
}

func pythonForTest() string {
	if _, err := os.Stat("/usr/bin/python3"); err == nil {
		return "/usr/bin/python3"
	}
	return "python3"
}
