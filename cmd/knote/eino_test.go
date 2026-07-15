package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/authz"
	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestValidateRuntimeModeRejectsDirect(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_RUNTIME_MODE", "direct")
	if err := validateRuntimeMode(); err == nil || !strings.Contains(err.Error(), "Eino runtime only") {
		t.Fatalf("expected direct runtime mode to be rejected, got %v", err)
	}
	t.Setenv("KNOTE_RUNTIME_MODE", "")
	if err := validateRuntimeMode(); err != nil {
		t.Fatalf("empty runtime mode should use Eino-only default: %v", err)
	}
	t.Setenv("KNOTE_RUNTIME_MODE", "eino")
	if err := validateRuntimeMode(); err != nil {
		t.Fatalf("explicit Eino runtime mode should be accepted: %v", err)
	}
}

func TestNewRuntimeRejectsRuntimeModeBeforeWritingConfig(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_RUNTIME_MODE", "direct")
	workspace := t.TempDir()
	_, _, err := newRuntime(context.Background(), workspace, "")
	if err == nil || !strings.Contains(err.Error(), "Eino runtime only") {
		t.Fatalf("expected runtime mode error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(workspace, ".knote", "config.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("invalid runtime mode should not write config, stat err=%v", statErr)
	}
}

func TestNewEinoRunnerFailsFastForDefaultLocalProfile(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("KNOTE_EINO_PROVIDER", "local")
	t.Setenv("KNOTE_EINO_API_KEY", "test-key")
	runner, err := newEinoRunner(context.Background(), repository.Config{
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "openai or openai-compatible") {
		t.Fatalf("expected provider error, got runner=%v err=%v", runner, err)
	}
}

func TestNewEinoRunnerUsesOpenAIEnvironmentOverrides(t *testing.T) {
	clearEinoEnv(t)
	t.Setenv("OPENAI_MODEL", "gpt-test")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", "https://example.invalid/v1")
	runner, err := newEinoRunner(context.Background(), repository.Config{
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Ready(context.Background()); err != nil {
		t.Fatalf("runner should be ready with environment-configured agent: %v", err)
	}
}

func TestPermissionedFixturePrincipalUsesTrustedRuntimeEnvironment(t *testing.T) {
	t.Setenv(permissionedPrincipalEnv, "")
	principal, err := permissionedFixturePrincipal()
	if err != nil || principal != "alice" {
		t.Fatalf("default principal = %q, %v; want alice", principal, err)
	}

	t.Setenv(permissionedPrincipalEnv, "bob")
	principal, err = permissionedFixturePrincipal()
	if err != nil || principal != "bob" {
		t.Fatalf("configured principal = %q, %v; want bob", principal, err)
	}

	t.Setenv(permissionedPrincipalEnv, "mallory")
	if _, err := permissionedFixturePrincipal(); err == nil || !strings.Contains(err.Error(), permissionedPrincipalEnv) {
		t.Fatalf("unknown principal should fail closed, got %v", err)
	}
}

func TestPermissionedRuntimeConfigIsExplicitAndComplete(t *testing.T) {
	for _, name := range []string{
		permissionedEnabledEnv, permissionedPrincipalEnv, permissionedIdentityWatermarkEnv,
		permissionedProviderEnv, openFGAEndpointEnv, openFGAStoreIDEnv, openFGAModelIDEnv,
		openFGATimeoutEnv, openFGAConsistencyEnv, "KNOTE_OPENFGA_API_TOKEN",
		permissionedTelemetryPathEnv,
	} {
		t.Setenv(name, "")
	}
	config, err := loadPermissionedRuntimeConfig(false)
	if err != nil || config.Enabled {
		t.Fatalf("disabled config = %+v, %v", config, err)
	}

	t.Setenv(permissionedEnabledEnv, "1")
	if _, err := loadPermissionedRuntimeConfig(false); err == nil || !strings.Contains(err.Error(), permissionedPrincipalEnv) {
		t.Fatalf("partial real config should fail closed, got %v", err)
	}

	t.Setenv(permissionedPrincipalEnv, "alice")
	t.Setenv(permissionedIdentityWatermarkEnv, "identity_v1")
	t.Setenv(permissionedProviderEnv, "permissioned_provider:create")
	t.Setenv(openFGAEndpointEnv, "http://127.0.0.1:8080")
	t.Setenv(openFGAStoreIDEnv, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	t.Setenv(openFGAModelIDEnv, "01ARZ3NDEKTSV4RRFFQ69G5FAW")
	t.Setenv("KNOTE_OPENFGA_API_TOKEN", "test-token")
	telemetryPath := filepath.Join(t.TempDir(), "telemetry.jsonl")
	t.Setenv(permissionedTelemetryPathEnv, telemetryPath)
	config, err = loadPermissionedRuntimeConfig(false)
	if err != nil || !config.Enabled || config.Fake || config.Provider != "permissioned_provider:create" {
		t.Fatalf("real config = %+v, %v", config, err)
	}
	if config.TelemetryPath != telemetryPath {
		t.Fatalf("telemetry path = %q", config.TelemetryPath)
	}
	t.Setenv(permissionedTelemetryPathEnv, "relative/telemetry.jsonl")
	if _, err := loadPermissionedRuntimeConfig(false); err == nil || !strings.Contains(err.Error(), permissionedTelemetryPathEnv) {
		t.Fatalf("relative telemetry path should fail closed, got %v", err)
	}
	t.Setenv(permissionedTelemetryPathEnv, telemetryPath)
	if _, err := loadPermissionedRuntimeConfig(true); err == nil {
		t.Fatal("real and fake permissioned modes were both accepted")
	}
}

func TestPermissionedApplicationOnlyWiresCachedRevocationPathInFakeMode(t *testing.T) {
	application, err := newPermissionedApplication(context.Background(), permissionedRuntimeConfig{}, nil, nil)
	if err != nil || application != nil {
		t.Fatalf("real-mode permissioned application = %#v, %v", application, err)
	}
	application, err = newPermissionedApplication(context.Background(), permissionedRuntimeConfig{
		Enabled: true, Fake: true, Principal: "alice",
	}, kag.Client{Fake: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if application == nil || application.fixture == nil || application.service == nil || application.AuthorizationContextProvider() == nil {
		t.Fatalf("fake-mode permissioned application was not fully wired: %#v", application)
	}
}

func TestPermissionedApplicationWiresRealSelectedBundleScope(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("# Intro\n\nreal permissioned content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := local.New(workspace)
	service := versioned.New(versioned.Options{
		Workspace: workspace, Repo: store, Backend: permissionedBuildBackend{}, Mode: versioned.ModeFake,
	})
	if _, err := service.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Setenv(authz.APITokenEnv, "test-token")
	config := permissionedRuntimeConfig{
		Enabled: true, Principal: "alice", IdentityWatermark: "identity_v1",
		OpenFGA: authz.OpenFGAConfig{
			Endpoint: "http://127.0.0.1:8080", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			AuthorizationModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Timeout: defaultOpenFGATimeout,
			Consistency: authz.ConsistencyHigherConsistency,
		},
		Consistency: protocol.ConsistencyHigherConsistency,
	}
	application, err := newPermissionedApplication(context.Background(), config, kag.Client{Fake: true}, store)
	if err != nil {
		t.Fatal(err)
	}
	provider := application.AuthorizationContextProvider()
	if application.service == nil || application.revisionState == nil || provider == nil {
		t.Fatalf("real permissioned application was not fully wired: %#v", application)
	}
	authorization, err := provider(context.Background(), "sess_real")
	if err != nil {
		t.Fatal(err)
	}
	if authorization.PrincipalID != "alice" || authorization.SessionID != "sess_real" ||
		authorization.AuthorizationModelID != config.OpenFGA.AuthorizationModelID ||
		authorization.TenantID != "local" || authorization.KnowledgeBaseID == "" || authorization.ACLWatermark == "" {
		t.Fatalf("unexpected real authorization context: %+v", authorization)
	}
}

func TestPermissionedToolsUseExactModeToolSets(t *testing.T) {
	service := versioned.New(versioned.Options{})
	all := einotools.New(service)
	nonPermissioned := []string{
		einotools.NameBuild,
		einotools.NameCheckout,
		einotools.NameCommit,
		einotools.NameDiff,
		einotools.NameRelease,
		einotools.NameVersions,
	}
	tests := []struct {
		name            string
		enabled         bool
		wantModel       []string
		wantSlash       []string
		wantSideEffects []string
	}{
		{
			name:            "nonpermissioned mode",
			enabled:         false,
			wantModel:       nonPermissioned,
			wantSlash:       nonPermissioned,
			wantSideEffects: nonPermissioned,
		},
		{
			name:    "permissioned mode",
			enabled: true,
			wantModel: []string{
				einotools.NameExplain,
				einotools.NameQuery,
			},
			wantSlash: []string{
				einotools.NameBuild,
				einotools.NameCheckout,
				einotools.NameCommit,
				einotools.NameRelease,
			},
			wantSideEffects: []string{
				einotools.NameBuild,
				einotools.NameCheckout,
				einotools.NameCommit,
				einotools.NameRelease,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotModel := toolNames(t, permissionedModelTools(all, test.enabled))
			if !slices.Equal(gotModel, test.wantModel) {
				t.Fatalf("model tools = %v, want exact set %v", gotModel, test.wantModel)
			}
			gotSlash := toolNames(t, permissionedSlashTools(all, test.enabled))
			if !slices.Equal(gotSlash, test.wantSlash) {
				t.Fatalf("slash tools = %v, want exact set %v", gotSlash, test.wantSlash)
			}

			registry := permissionedSideEffectToolMap(einotools.ByName(service), test.enabled)
			gotRegistry := make([]string, 0, len(registry))
			for name := range registry {
				gotRegistry = append(gotRegistry, name)
			}
			slices.Sort(gotRegistry)
			if !slices.Equal(gotRegistry, test.wantSideEffects) {
				t.Fatalf("approved tool registry = %v, want exact set %v", gotRegistry, test.wantSideEffects)
			}
		})
	}
}

func toolNames(t *testing.T, tools []einotool.InvokableTool) []string {
	t.Helper()
	names := make([]string, 0, len(tools))
	for _, candidate := range tools {
		info, err := candidate.Info(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, info.Name)
	}
	slices.Sort(names)
	return names
}

func clearEinoEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"KNOTE_EINO_PROVIDER",
		"KNOTE_EINO_MODEL",
		"KNOTE_EINO_API_KEY",
		"KNOTE_EINO_BASE_URL",
		"KNOTE_EINO_REASONING_EFFORT",
		"KNOTE_EINO_MODEL_PROFILE",
		"KNOTE_RUNTIME_MODE",
		permissionedEnabledEnv,
		permissionedPrincipalEnv,
		permissionedIdentityWatermarkEnv,
		permissionedProviderEnv,
		openFGAEndpointEnv,
		openFGAStoreIDEnv,
		openFGAModelIDEnv,
		openFGATimeoutEnv,
		openFGAConsistencyEnv,
		permissionedTelemetryPathEnv,
		authz.APITokenEnv,
		"OPENAI_MODEL",
		"OPENAI_API_KEY",
		"OPENAI_BASE_URL",
		"OPENAI_REASONING_EFFORT",
	} {
		t.Setenv(name, "")
	}
}

type permissionedBuildBackend struct{}

func (permissionedBuildBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "fake"}}, nil
}

func (permissionedBuildBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "fake", "mode": "fake"}}, nil
}

func (permissionedBuildBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "fake", "mode": "fake"}}, nil
}

func (b permissionedBuildBackend) BuildInNamespace(ctx context.Context, _, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b permissionedBuildBackend) BuildInNamespaceWithCorpus(ctx context.Context, _, _ string, _ []kag.CorpusRecord) (kag.Response, error) {
	return b.Build(ctx)
}

func (b permissionedBuildBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b permissionedBuildBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}
