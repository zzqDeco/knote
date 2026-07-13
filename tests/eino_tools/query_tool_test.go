package einotoolstest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
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

func TestPermissionedQueryToolIsolatesFakeEvidenceByPrincipal(t *testing.T) {
	root := repoRoot(t)
	backend := kag.Client{
		AdapterPath: filepath.Join(root, "adapters", "kag", "knote_kag_adapter.py"),
		Workspace:   root,
		Fake:        true,
	}
	permissioned, err := fixture.New(backend)
	if err != nil {
		t.Fatal(err)
	}
	query := func(ctx context.Context, request protocol.QueryRequest) (einotools.PermissionedQueryResult, error) {
		result, err := permissioned.Query(ctx, request)
		if err != nil {
			return einotools.PermissionedQueryResult{}, err
		}
		return einotools.PermissionedQueryResult{
			Answer: result.Generation.Answer, Mode: result.Generation.Mode, EvidencePackage: result.Evidence,
		}, nil
	}
	legacy := versioned.New(versioned.Options{Workspace: root, Backend: backend, Mode: versioned.ModeFake})
	tool := einotools.ByNameWithOptions(einotools.Options{Service: legacy, PermissionedQuery: query})[einotools.NameQuery]

	for _, test := range []struct {
		principal string
		wantItems int
	}{
		{principal: fixture.Alice, wantItems: 2},
		{principal: fixture.Bob, wantItems: 1},
	} {
		authorization := fixture.Authorization(test.principal, "session-"+test.principal)
		ctx, err := protocol.WithAuthorizationContext(context.Background(), authorization)
		if err != nil {
			t.Fatal(err)
		}
		out, err := tool.InvokableRun(ctx, `{"question":"what is knote?"}`)
		if err != nil {
			t.Fatalf("%s query failed: %v", test.principal, err)
		}
		if strings.Contains(out, "DENIED CANARY") {
			t.Fatalf("%s result leaked denied canary: %s", test.principal, out)
		}
		var decoded struct {
			EvidencePackage protocol.EvidencePackage `json:"evidence_package"`
		}
		if err := json.Unmarshal([]byte(out), &decoded); err != nil {
			t.Fatalf("decode %s query result: %v", test.principal, err)
		}
		if got := len(decoded.EvidencePackage.Items); got != test.wantItems {
			t.Fatalf("%s evidence items = %d, want %d", test.principal, got, test.wantItems)
		}
		if err := decoded.EvidencePackage.ValidateFor(authorization); err != nil {
			t.Fatalf("%s evidence package is invalid: %v", test.principal, err)
		}
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
