package einotoolstest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestQueryToolUsesFakeKAGBackend(t *testing.T) {
	ctx := context.Background()
	root := repoRoot(t)
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nknote is local-first.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := local.New(workspace)
	cfg, err := repo.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.KAG.Fake = true
	cfg.KAG.AdapterPath = filepath.Join(root, "adapters", "kag", "knote_kag_adapter.py")
	if err := repo.SaveConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	backend := kag.Client{
		AdapterPath: cfg.KAG.AdapterPath,
		Workspace:   workspace,
		Host:        cfg.KAG.Host,
		Fake:        true,
		ConfigPath:  cfg.KAG.ConfigPath,
		ProjectID:   cfg.KAG.ProjectID,
		Namespace:   cfg.KAG.Namespace,
		Language:    cfg.KAG.Language,
		RuntimeDir:  cfg.KAG.RuntimeDir,
	}
	svc := versioned.New(versioned.Options{
		Workspace: workspace,
		Repo:      repo,
		Versions:  repo,
		Backend:   backend,
		Mode:      versioned.ModeFake,
	})
	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}

	out, err := einotools.ByName(svc)[einotools.NameQuery].InvokableRun(ctx, `{"question":"what is this knowledge base?"}`)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Answer       string `json:"answer"`
		AdapterError string `json:"adapter_error"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("query tool returned invalid JSON %q: %v", out, err)
	}
	if !strings.Contains(decoded.Answer, "Fake KAG answer") || decoded.AdapterError != "" {
		t.Fatalf("query tool did not use fake KAG backend: %+v", decoded)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
