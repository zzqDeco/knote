package versioned

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestServiceBuildQueryAndEvalWithFakeBackend(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "# Intro\n\nknote is local-first.\n"
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	build, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if build.Manifest.DocumentCount != 1 || build.Manifest.ChunkCount != 1 {
		t.Fatalf("unexpected build manifest: %+v", build.Manifest)
	}
	if repo.artifacts.Manifest.DocumentCount != 1 {
		t.Fatalf("artifacts were not written: %+v", repo.artifacts.Manifest)
	}

	answer, err := svc.Query(ctx, "what is knote?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer.Answer, "Fake KAG answer") {
		t.Fatalf("unexpected answer: %+v", answer)
	}

	report, err := svc.Eval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 1 || report.AdapterErrors != 0 || report.KnowledgeHash != repo.hash {
		t.Fatalf("unexpected eval report: %+v", report)
	}
	if len(repo.eval.Results) != 1 || repo.eval.Results[0].KnowledgeHash != repo.hash {
		t.Fatalf("eval results were not persisted with current hash: %+v", repo.eval.Results)
	}
}

func TestServiceQueryFallsBackToArtifacts(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "hello\n"
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   failingBackend{},
		Mode:      ModeFake,
	})
	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}
	answer, err := svc.Query(ctx, "what is here?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer.Answer, "artifacts fallback") || answer.AdapterError == "" {
		t.Fatalf("expected fallback answer with adapter error, got %+v", answer)
	}
}

func TestServiceBuildFailsBeforeWritingArtifactsWhenBackendFails(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "# Intro\n\nknote is local-first.\n"
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   buildFailingBackend{},
		Mode:      ModeReal,
	})

	build, err := svc.Build(ctx)
	if err == nil {
		t.Fatal("expected build to fail when backend build fails")
	}
	if build.AdapterError == "" {
		t.Fatalf("expected adapter error in build result: %+v", build)
	}
	if repo.writeArtifactsCalls != 0 {
		t.Fatalf("backend failure wrote artifacts %d time(s)", repo.writeArtifactsCalls)
	}
}

func TestServiceBuildWithoutBackendFailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/intro.md"] = "# Intro\n\nknote is local-first.\n"
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Mode: ModeReal})

	build, err := svc.Build(ctx)
	if err == nil || !strings.Contains(err.Error(), "KAG backend is not configured") {
		t.Fatalf("build without backend error = %v, want configured fail-closed error", err)
	}
	if build.AdapterError == "" {
		t.Fatalf("build without backend omitted adapter error: %+v", build)
	}
	if repo.writeArtifactsCalls != 0 {
		t.Fatalf("build without backend wrote artifacts %d time(s)", repo.writeArtifactsCalls)
	}
}

func TestServiceBuildArtifactsAreStableAndEntityIsPerDocument(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sourceModTimes["sources/long.md"] = time.Unix(42, 0).UTC()
	repo.sources["sources/long.md"] = "# Long\n\n" + strings.Repeat("hello world ", 120)
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstManifest, err := json.Marshal(first.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	repo.sourceModTimes["sources/long.md"] = time.Unix(99, 0).UTC()
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := json.Marshal(second.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstManifest) != string(secondManifest) {
		t.Fatalf("manifest changed on no-op rebuild:\nfirst=%s\nsecond=%s", firstManifest, secondManifest)
	}
	firstBundle, err := json.Marshal(first.BundleManifest)
	if err != nil {
		t.Fatal(err)
	}
	secondBundle, err := json.Marshal(second.BundleManifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBundle) != string(secondBundle) {
		t.Fatalf("v2 bundle manifest changed on no-op rebuild:\nfirst=%s\nsecond=%s", firstBundle, secondBundle)
	}
	if !first.Manifest.GeneratedAt.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("generated_at must exclude source mtimes, got %s", first.Manifest.GeneratedAt)
	}
	if len(repo.artifacts.Chunks) < 2 {
		t.Fatalf("test source did not split into multiple chunks: %+v", repo.artifacts.Chunks)
	}
	if len(repo.artifacts.Entities) != 1 {
		t.Fatalf("expected one document entity, got %d: %+v", len(repo.artifacts.Entities), repo.artifacts.Entities)
	}
	if got, want := len(repo.artifacts.Entities[0].EvidenceChunkIDs), len(repo.artifacts.Chunks); got != want {
		t.Fatalf("document entity evidence chunk count = %d, want %d", got, want)
	}
}

func TestServiceBuildUsesProjectionIsolatedKAGNamespaceAndMetadata(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "Team Knowledge"
	repo.sources["sources/intro.md"] = "first\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if backend.buildNamespace != first.BundleManifest.Namespace {
		t.Fatalf("KAG build namespace = %q, want %q", backend.buildNamespace, first.BundleManifest.Namespace)
	}
	if !strings.HasPrefix(first.BundleManifest.Namespace, "Team_Knowledge__prj_") {
		t.Fatalf("namespace was not canonical and projection isolated: %q", first.BundleManifest.Namespace)
	}
	if first.BundleManifest.ProjectionVersion != first.BundleManifest.ProjectionID ||
		first.BundleManifest.AuthorizationVersion == "" {
		t.Fatalf("projection/authz metadata is inconsistent: %+v", first.BundleManifest)
	}
	answer, err := svc.Query(ctx, "what is here?")
	if err != nil {
		t.Fatal(err)
	}
	if backend.queryNamespace != first.BundleManifest.Namespace ||
		answer.ProjectionVersion != first.BundleManifest.ProjectionVersion || answer.Namespace != first.BundleManifest.Namespace ||
		answer.AuthorizationObject != first.BundleManifest.AuthorizationObject ||
		answer.AuthorizationVersion != first.BundleManifest.AuthorizationVersion {
		t.Fatalf("retrieval metadata does not match serving build: answer=%+v manifest=%+v", answer, first.BundleManifest)
	}

	repo.sources["sources/intro.md"] = "second\n"
	firstDocumentID := repo.artifacts.Documents[0].DocumentID
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.BundleManifest.ProjectionID == first.BundleManifest.ProjectionID ||
		second.BundleManifest.Namespace == first.BundleManifest.Namespace ||
		second.BundleManifest.AuthorizationObject != first.BundleManifest.AuthorizationObject ||
		second.BundleManifest.AuthorizationVersion != first.BundleManifest.AuthorizationVersion {
		t.Fatalf("content-only projection change altered identity isolation or ACL version:\nfirst=%+v\nsecond=%+v", first.BundleManifest, second.BundleManifest)
	}
	if backend.buildNamespace != second.BundleManifest.Namespace {
		t.Fatalf("second KAG build namespace = %q, want %q", backend.buildNamespace, second.BundleManifest.Namespace)
	}
	if repo.artifacts.Documents[0].DocumentID != firstDocumentID {
		t.Fatalf("content update changed stable document identity: first=%s second=%s", firstDocumentID, repo.artifacts.Documents[0].DocumentID)
	}
}

func TestProjectionIdentityExcludesAbsoluteWorkspacePaths(t *testing.T) {
	ctx := context.Background()
	build := func(workspace string) BuildResult {
		repo := newMemoryRepo()
		repo.config.Workspace = workspace
		repo.config.KAG.Namespace = "PortableKB"
		repo.config.KAG.RuntimeDir = filepath.Join(workspace, ".knote", "kag-runtime")
		repo.sources["sources/intro.md"] = "portable\n"
		result, err := New(Options{Workspace: workspace, Repo: repo, Backend: fakeBackend{}, Mode: ModeFake}).Build(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(repo.artifacts.ProjectionJSON), workspace) {
			t.Fatalf("public projection contains absolute workspace path %q", workspace)
		}
		return result
	}
	first := build("/private/checkout/one")
	second := build("/different/checkout/two")
	if first.BundleManifest.ProjectionVersion != second.BundleManifest.ProjectionVersion ||
		first.BundleManifest.Namespace != second.BundleManifest.Namespace {
		t.Fatalf("absolute workspace path changed projection identity: first=%+v second=%+v", first.BundleManifest, second.BundleManifest)
	}
}

func TestServiceFailedProjectionLeavesCatalogAndArtifactPointersServingPriorVersion(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "FailureTest"
	repo.sources["sources/intro.md"] = "first\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})
	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend.buildErr = errFakeUnavailable
	repo.sources["sources/intro.md"] = "second\n"
	failed, err := svc.Build(ctx)
	if err == nil || failed.AdapterError == "" {
		t.Fatalf("expected projection KAG failure, result=%+v err=%v", failed, err)
	}
	if repo.artifacts.BundleManifest.ProjectionVersion != first.BundleManifest.ProjectionVersion {
		t.Fatalf("failed projection replaced artifact pointer: got=%s want=%s",
			repo.artifacts.BundleManifest.ProjectionVersion, first.BundleManifest.ProjectionVersion)
	}
	empty, err := emptyBaseProjection(catalog.Scope{TenantID: localTenantID, KnowledgeBaseID: canonicalNamespace(repo.config.KAG.Namespace)})
	if err != nil {
		t.Fatal(err)
	}
	store, err := catalog.NewProjectionStore(projectionJournalRoot(
		repo.projectionRoot, empty.Version, first.BundleManifest.ProjectionVersion,
	))
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := store.ServingPointer()
	if err != nil {
		t.Fatal(err)
	}
	if pointer.ProjectionVersion != first.BundleManifest.ProjectionVersion {
		t.Fatalf("failed projection advanced catalog pointer: got=%s want=%s", pointer.ProjectionVersion, first.BundleManifest.ProjectionVersion)
	}
}

func TestServiceRetriesFailedProjectionWithoutSourceChanges(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "RetryTest"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{buildErr: errFakeUnavailable}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	failed, err := svc.Build(ctx)
	if err == nil || failed.AdapterError == "" {
		t.Fatalf("expected initial KAG failure, result=%+v err=%v", failed, err)
	}
	backend.buildErr = nil
	recovered, err := svc.Build(ctx)
	if err != nil {
		t.Fatalf("retry unchanged failed projection: %v", err)
	}
	if backend.buildCalls != 2 {
		t.Fatalf("KAG build calls = %d, want 2 across failed attempt and retry", backend.buildCalls)
	}
	if recovered.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion ||
		repo.artifacts.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion {
		t.Fatalf("retry did not publish the failed projection identity: failed=%s recovered=%s current=%s",
			failed.BundleManifest.ProjectionVersion, recovered.BundleManifest.ProjectionVersion,
			repo.artifacts.BundleManifest.ProjectionVersion)
	}
}

func TestServiceKAGConfigurationChangeCreatesNewProjection(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "ConfigTest"
	repo.config.KAG.Language = "en"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.config.KAG.Language = "zh"
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.BundleManifest.ProjectionVersion == first.BundleManifest.ProjectionVersion ||
		second.BundleManifest.Namespace == first.BundleManifest.Namespace {
		t.Fatalf("KAG configuration change reused projection identity: first=%+v second=%+v",
			first.BundleManifest, second.BundleManifest)
	}
	if backend.buildCalls != 2 {
		t.Fatalf("KAG build calls = %d, want 2 after configuration change", backend.buildCalls)
	}
}

func TestKAGBuildConfigVersionTracksGeneratedConfigSemanticEnvironment(t *testing.T) {
	workspace := t.TempDir()
	cfg := newMemoryRepo().config
	secretEnvVars := []string{
		"KNOTE_CHAT_LLM_API_KEY",
		"KNOTE_OPENIE_LLM_API_KEY",
		"KNOTE_VECTOR_API_KEY",
	}
	for _, name := range append(append([]string(nil), generatedKAGSemanticEnvVars...), secretEnvVars...) {
		t.Setenv(name, "")
	}

	baseline, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	semanticValues := map[string]string{
		"KNOTE_CHAT_LLM_BASE_URL":   "https://chat.example/v1",
		"KNOTE_CHAT_LLM_MODEL":      "chat-v2",
		"KNOTE_CHAT_LLM_TYPE":       "custom-chat",
		"KNOTE_KAG_LANGUAGE":        "zh",
		"KNOTE_KAG_NAMESPACE":       "GeneratedEnvKB",
		"KNOTE_KAG_PROJECT_ID":      "42",
		"KNOTE_OPENIE_LLM_BASE_URL": "https://openie.example/v1",
		"KNOTE_OPENIE_LLM_MODEL":    "openie-v2",
		"KNOTE_OPENIE_LLM_TYPE":     "custom-openie",
		"KNOTE_VECTOR_BASE_URL":     "https://vector.example/v1",
		"KNOTE_VECTOR_DIMENSIONS":   "2048",
		"KNOTE_VECTOR_MODEL":        "embed-v2",
		"KNOTE_VECTOR_TYPE":         "custom-vector",
	}
	if len(semanticValues) != len(generatedKAGSemanticEnvVars) {
		t.Fatalf("semantic environment test covers %d variables, allowlist has %d", len(semanticValues), len(generatedKAGSemanticEnvVars))
	}
	for _, name := range generatedKAGSemanticEnvVars {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, semanticValues[name])
			changed, err := kagBuildConfigVersion(workspace, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if changed == baseline {
				t.Fatalf("semantic environment change %s did not change build config version", name)
			}
			repeated, err := kagBuildConfigVersion(workspace, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if repeated != changed {
				t.Fatalf("unchanged semantic environment was unstable: first=%s second=%s", changed, repeated)
			}
		})
	}

	for _, name := range secretEnvVars {
		t.Setenv(name, "rotated-secret")
	}
	t.Setenv("KNOTE_UNRELATED_SETTING", "ignored")
	withCredentials, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withCredentials != baseline {
		t.Fatalf("credentials or unrelated environment changed generated config identity: baseline=%s changed=%s", baseline, withCredentials)
	}
}

func TestKAGBuildConfigVersionTracksAdapterContentPortably(t *testing.T) {
	firstWorkspace := t.TempDir()
	secondWorkspace := t.TempDir()
	firstAdapter := filepath.Join(firstWorkspace, "adapters", "kag", "custom.py")
	secondAdapter := filepath.Join(secondWorkspace, "adapters", "kag", "custom.py")
	writeKAGTestFile(t, firstAdapter, "ADAPTER_VERSION = 1\n")
	writeKAGTestFile(t, secondAdapter, "ADAPTER_VERSION = 1\n")

	firstConfig := newMemoryRepo().config
	firstConfig.KAG.AdapterPath = firstAdapter
	secondConfig := newMemoryRepo().config
	secondConfig.KAG.AdapterPath = secondAdapter
	first, err := kagBuildConfigVersion(firstWorkspace, firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := kagBuildConfigVersion(secondWorkspace, secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("identical adapter content changed identity across checkout roots: first=%s second=%s", first, second)
	}

	writeKAGTestFile(t, secondAdapter, "ADAPTER_VERSION = 2\n")
	upgraded, err := kagBuildConfigVersion(secondWorkspace, secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded == second {
		t.Fatal("adapter content upgrade did not change build config identity")
	}
}

func TestKAGBuildConfigVersionIgnoresGeneratedEnvironmentWithCheckedInConfig(t *testing.T) {
	workspace := t.TempDir()
	writeKAGTestFile(t, filepath.Join(workspace, "kag_config.yaml"), "project:\n  namespace: checked-in\n")
	cfg := newMemoryRepo().config

	t.Setenv("KNOTE_OPENIE_LLM_MODEL", "first")
	first, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KNOTE_OPENIE_LLM_MODEL", "second")
	second, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("generated-config environment changed checked-in config identity: first=%s second=%s", first, second)
	}
}

func TestKAGBuildConfigVersionTracksReferencedEnvironmentWithCheckedInConfig(t *testing.T) {
	workspace := t.TempDir()
	writeKAGTestFile(t, filepath.Join(workspace, "kag_config.yaml"), `openie_llm:
  model: !ENV CUSTOM_OPENIE_MODEL
  api_key: !ENV CUSTOM_OPENIE_API_KEY
project:
  namespace: "{{ CUSTOM_KAG_NAMESPACE }}"
`)
	cfg := newMemoryRepo().config
	t.Setenv("CUSTOM_OPENIE_MODEL", "model-a")
	t.Setenv("CUSTOM_KAG_NAMESPACE", "namespace-a")
	t.Setenv("CUSTOM_OPENIE_API_KEY", "secret-a")

	first, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CUSTOM_OPENIE_MODEL", "model-b")
	withModelChange, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withModelChange == first {
		t.Fatal("referenced !ENV semantic environment change did not change checked-in config identity")
	}
	t.Setenv("CUSTOM_KAG_NAMESPACE", "namespace-b")
	withTemplateChange, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withTemplateChange == withModelChange {
		t.Fatal("referenced template semantic environment change did not change checked-in config identity")
	}
	t.Setenv("CUSTOM_OPENIE_API_KEY", "secret-b")
	withSecretChange, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withSecretChange != withTemplateChange {
		t.Fatal("referenced secret environment changed checked-in config identity")
	}
}

func TestKAGBuildConfigVersionTracksResourceTreeAndExcludesGeneratedState(t *testing.T) {
	workspace := t.TempDir()
	writeKAGTestFile(t, filepath.Join(workspace, "kag_config.yaml"), "project:\n  namespace: resource-test\n")
	writeKAGTestFile(t, filepath.Join(workspace, "prompt.txt"), "first prompt")
	writeKAGTestFile(t, filepath.Join(workspace, "custom_builder.py"), "VERSION = 1\n")
	cfg := newMemoryRepo().config
	cfg.KAG.ConfigPath = "kag_config.yaml"
	cfg.KAG.RuntimeDir = filepath.Join(".knote", "kag-runtime")

	first, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeKAGTestFile(t, filepath.Join(workspace, ".knote", "kag-runtime", "projections", "old", "receipt.json"), "generated")
	writeKAGTestFile(t, filepath.Join(workspace, "artifacts", "current.json"), "generated")
	writeKAGTestFile(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: first\n")
	writeKAGTestFile(t, filepath.Join(workspace, "evals", "report.md"), "generated report")
	writeKAGTestFile(t, filepath.Join(workspace, "evals", "results.jsonl"), "{}\n")
	withGeneratedState, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withGeneratedState != first {
		t.Fatalf("generated/runtime state changed build config version: first=%s second=%s", first, withGeneratedState)
	}
	writeKAGTestFile(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: second\n")
	withWorkspaceConfigChange, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withWorkspaceConfigChange != first {
		t.Fatalf("unrelated .knote/config.yaml changed build config version: first=%s second=%s", first, withWorkspaceConfigChange)
	}
	writeKAGTestFile(t, filepath.Join(workspace, "evals", "questions.jsonl"), `{"id":"q1","question":"tracked input"}`+"\n")
	withEvalInput, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withEvalInput == first {
		t.Fatal("eval input did not change build config version")
	}
	first = withEvalInput

	writeKAGTestFile(t, filepath.Join(workspace, "prompt.txt"), "second prompt")
	withPromptChange, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withPromptChange == first {
		t.Fatal("prompt resource change did not change build config version")
	}
	writeKAGTestFile(t, filepath.Join(workspace, "custom_builder.py"), "VERSION = 2\n")
	withModuleChange, err := kagBuildConfigVersion(workspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if withModuleChange == withPromptChange {
		t.Fatal("custom module change did not change build config version")
	}
}

func TestKAGBuildConfigVersionIsPortableAndIncludesConfigDirectoryIdentity(t *testing.T) {
	root := t.TempDir()
	writeProject := func(workspace, projectDir string) {
		t.Helper()
		writeKAGTestFile(t, filepath.Join(workspace, projectDir, "kag_config.yaml"), "project:\n  namespace: portable\n")
		writeKAGTestFile(t, filepath.Join(workspace, projectDir, "prompt.txt"), "portable prompt")
	}
	firstWorkspace := filepath.Join(root, "checkout-one")
	secondWorkspace := filepath.Join(root, "checkout-two")
	writeProject(firstWorkspace, "kag_project")
	writeProject(secondWorkspace, "kag_project")
	cfg := newMemoryRepo().config
	cfg.KAG.ConfigPath = filepath.Join("kag_project", "kag_config.yaml")

	first, err := kagBuildConfigVersion(firstWorkspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := kagBuildConfigVersion(secondWorkspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("checkout path changed build config version: first=%s second=%s", first, second)
	}

	writeProject(firstWorkspace, "alternate_project")
	cfg.KAG.ConfigPath = filepath.Join("alternate_project", "kag_config.yaml")
	alternate, err := kagBuildConfigVersion(firstWorkspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if alternate == first {
		t.Fatal("config directory identity did not change build config version")
	}

	externalOne := filepath.Join(root, "external-one", "project")
	externalTwo := filepath.Join(root, "external-two", "project")
	writeKAGTestFile(t, filepath.Join(externalOne, "kag_config.yaml"), "project:\n  namespace: portable\n")
	writeKAGTestFile(t, filepath.Join(externalOne, "prompt.txt"), "portable prompt")
	writeKAGTestFile(t, filepath.Join(externalTwo, "kag_config.yaml"), "project:\n  namespace: portable\n")
	writeKAGTestFile(t, filepath.Join(externalTwo, "prompt.txt"), "portable prompt")
	cfg.KAG.ConfigPath = filepath.Join(externalOne, "kag_config.yaml")
	externalFirst, err := kagBuildConfigVersion(firstWorkspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.KAG.ConfigPath = filepath.Join(externalTwo, "kag_config.yaml")
	externalSecond, err := kagBuildConfigVersion(firstWorkspace, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if externalFirst == externalSecond {
		t.Fatal("distinct external config directories produced the same build config version")
	}
}

func TestKAGBuildConfigVersionBoundsIndividualResources(t *testing.T) {
	workspace := t.TempDir()
	writeKAGTestFile(t, filepath.Join(workspace, "kag_project", "kag_config.yaml"), "project:\n  namespace: bounded\n")
	largePath := filepath.Join(workspace, "kag_project", "large-resource.bin")
	file, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxKAGResourceFileBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := newMemoryRepo().config
	cfg.KAG.ConfigPath = filepath.Join("kag_project", "kag_config.yaml")

	if _, err := kagBuildConfigVersion(workspace, cfg); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized KAG resource error = %v, want bounded failure", err)
	}
}

func TestServiceKAGNamespaceChangeStartsNewProjectionScope(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "NamespaceA"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.config.KAG.Namespace = "NamespaceB"
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatalf("build after KAG namespace change: %v", err)
	}
	if first.BundleManifest.Namespace == second.BundleManifest.Namespace ||
		first.BundleManifest.ProjectionVersion == second.BundleManifest.ProjectionVersion {
		t.Fatalf("namespace change reused projection identity: first=%+v second=%+v", first.BundleManifest, second.BundleManifest)
	}
	if second.Manifest.Workspace != "NamespaceB" || backend.buildCalls != 2 {
		t.Fatalf("namespace change did not build the new scope: manifest=%+v calls=%d", second.Manifest, backend.buildCalls)
	}
}

func TestServiceKAGRuntimeDirChangeCreatesNewProjection(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "RuntimeTest"
	repo.config.KAG.RuntimeDir = filepath.Join(".knote", "runtime-a")
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.config.KAG.RuntimeDir = filepath.Join(".knote", "runtime-b")
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleManifest.ProjectionVersion == second.BundleManifest.ProjectionVersion || backend.buildCalls != 2 {
		t.Fatalf("runtime_dir change did not rebuild: first=%s second=%s calls=%d",
			first.BundleManifest.ProjectionVersion, second.BundleManifest.ProjectionVersion, backend.buildCalls)
	}
}

func TestServiceBuildPassesProjectionWideIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "IdempotencyTest"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{}
	svc := service{workspace: repo.config.Workspace, repo: repo, backend: backend, mode: ModeFake}

	artifacts, build, err := svc.prepareArtifactProjection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := projectionKAGBuildIdempotencyKey(artifacts.BundleManifest.ProjectionVersion)
	if _, err := svc.executeProjectionBuild(ctx, artifacts, build); err != nil {
		t.Fatal(err)
	}
	if backend.buildIdempotencyKey != want {
		t.Fatalf("KAG build idempotency key = %q, want projection key %q", backend.buildIdempotencyKey, want)
	}
}

func TestServiceBuildUsesPreparedSourceBytesAfterSourceMutation(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "PreparedCorpusTest"
	repo.sources["sources/intro.md"] = "# Original\n\nprepared bytes\n"
	backend := &recordingNamespacedBackend{}
	svc := service{workspace: repo.config.Workspace, repo: repo, backend: backend, mode: ModeFake}

	artifacts, build, err := svc.prepareArtifactProjection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.sources["sources/intro.md"] = "# Mutated\n\nbytes changed after prepare\n"
	if _, err := svc.executeProjectionBuild(ctx, artifacts, build); err != nil {
		t.Fatal(err)
	}
	if len(backend.buildCorpora) != 1 || len(backend.buildCorpora[0]) != 1 {
		t.Fatalf("prepared corpus requests = %+v, want one record", backend.buildCorpora)
	}
	got := backend.buildCorpora[0][0]
	if got.Content != "# Original\n\nprepared bytes\n" || got.SourcePath != "sources/intro.md" || got.Name != "Original" {
		t.Fatalf("KAG corpus was not pinned to prepared bytes: %+v", got)
	}
}

func TestServiceBuildSkipsBlankSourcesOnlyFromKAGCorpus(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "BlankCorpusTest"
	repo.sources["sources/blank.md"] = " \n\t\r\n"
	repo.sources["sources/content.md"] = "# Content\n\nindexed bytes\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	result, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.SourceCount != 2 || result.Manifest.DocumentCount != 2 {
		t.Fatalf("blank source was not represented in artifacts: %+v", result.Manifest)
	}
	if len(backend.buildCorpora) != 1 || len(backend.buildCorpora[0]) != 1 {
		t.Fatalf("KAG corpus = %+v, want only the non-blank source", backend.buildCorpora)
	}
	got := backend.buildCorpora[0][0]
	if got.SourcePath != "sources/content.md" || got.Content != repo.sources["sources/content.md"] {
		t.Fatalf("KAG corpus record = %+v, want content source", got)
	}
}

func TestServiceBuildFailsClosedWhenKAGCorpusHasOnlyBlankSources(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/blank.md"] = " \n\t\r\n"
	repo.sources["sources/also-blank.txt"] = "\n\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	_, err := svc.Build(ctx)
	if err == nil || !strings.Contains(err.Error(), "KAG corpus contains no non-blank sources") {
		t.Fatalf("all-blank KAG corpus error = %v", err)
	}
	if backend.buildCalls != 0 {
		t.Fatalf("all-blank KAG corpus invoked backend %d time(s)", backend.buildCalls)
	}
	if repo.writeArtifactsCalls != 0 {
		t.Fatalf("all-blank KAG corpus staged artifacts %d time(s)", repo.writeArtifactsCalls)
	}
}

func TestServiceNoopRebuildRematerializesMissingKAGRuntime(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "NoopRuntimeTest"
	repo.sources["sources/intro.md"] = "stable\n"
	runtimeRoot := t.TempDir()
	backend := &recordingNamespacedBackend{runtimeDir: runtimeRoot}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(runtimeRoot); err != nil {
		t.Fatal(err)
	}
	second, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleManifest.ProjectionVersion != second.BundleManifest.ProjectionVersion {
		t.Fatalf("noop rebuild changed projection: first=%s second=%s",
			first.BundleManifest.ProjectionVersion, second.BundleManifest.ProjectionVersion)
	}
	if backend.buildCalls != 2 || backend.wholeNamespaceBuilds != 2 {
		t.Fatalf("KAG replay/rematerialization calls=%d builds=%d, want 2/2",
			backend.buildCalls, backend.wholeNamespaceBuilds)
	}
	if noop, _ := second.KAGData["idempotent_noop"].(bool); !noop {
		t.Fatalf("unchanged build did not report idempotent noop: %+v", second.KAGData)
	}
}

func TestServiceDivergentSuccessorAfterCheckoutIgnoresStalePrivateJournal(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "CheckoutJournalTest"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})

	repo.sources["sources/intro.md"] = "base\n"
	base, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	baseArtifacts := repo.artifacts
	repo.sources["sources/intro.md"] = "branch-a\n"
	branchA, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.artifacts = baseArtifacts
	repo.stagedArtifacts = repository.ArtifactSet{}
	repo.sources["sources/intro.md"] = "branch-b\n"
	branchB, err := svc.Build(ctx)
	if err != nil {
		t.Fatalf("build divergent checked-out successor: %v", err)
	}
	if branchB.BundleManifest.ProjectionVersion == branchA.BundleManifest.ProjectionVersion ||
		branchB.BundleManifest.ProjectionVersion == base.BundleManifest.ProjectionVersion {
		t.Fatalf("divergent checkout reused projection: base=%s branch-a=%s branch-b=%s",
			base.BundleManifest.ProjectionVersion, branchA.BundleManifest.ProjectionVersion,
			branchB.BundleManifest.ProjectionVersion)
	}
	for _, successor := range []string{branchA.BundleManifest.ProjectionVersion, branchB.BundleManifest.ProjectionVersion} {
		if _, err := os.Stat(projectionJournalRoot(repo.projectionRoot, base.BundleManifest.ProjectionVersion, successor)); err != nil {
			t.Fatalf("successor journal %s: %v", successor, err)
		}
	}
}

func TestServiceDivergentSuccessorRejectsChangedPublicBase(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "PublicCASTest"
	backend := &recordingNamespacedBackend{}
	svc := service{workspace: repo.config.Workspace, repo: repo, backend: backend, mode: ModeFake}

	repo.sources["sources/intro.md"] = "base\n"
	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}
	baseArtifacts := repo.artifacts
	repo.sources["sources/intro.md"] = "branch-a\n"
	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}
	branchAArtifacts := repo.artifacts
	repo.artifacts = baseArtifacts
	repo.sources["sources/intro.md"] = "branch-b\n"
	artifacts, build, err := svc.prepareArtifactProjection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.artifacts = branchAArtifacts
	callsBefore := backend.buildCalls
	if _, err := svc.executeProjectionBuild(ctx, artifacts, build); err == nil ||
		!strings.Contains(err.Error(), "public projection base changed") {
		t.Fatalf("changed public base error = %v, want stale-base rejection", err)
	}
	if backend.buildCalls != callsBefore {
		t.Fatalf("stale successor invoked KAG: before=%d after=%d", callsBefore, backend.buildCalls)
	}
	if repo.artifacts.BundleManifest.ProjectionVersion != branchAArtifacts.BundleManifest.ProjectionVersion {
		t.Fatal("stale successor replaced the changed public base")
	}
}

func TestProjectionKAGBuildIdempotencyKeyIgnoresCatalogRetryIdentity(t *testing.T) {
	projectionVersion := "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	want := "kag-build-" + projectionVersion
	if got := projectionKAGBuildIdempotencyKey(projectionVersion); got != want {
		t.Fatalf("projection KAG key = %q, want %q", got, want)
	}
	for _, runKey := range []string{"sync-" + projectionVersion, "sync-" + projectionVersion + "-retry-1"} {
		if got := projectionKAGBuildIdempotencyKey(projectionVersion); got == runKey {
			t.Fatalf("projection KAG key unexpectedly depends on catalog run key %q", runKey)
		}
	}
}

func TestServiceProjectionReplayUsesOneKAGBuildKeyAfterPersistedIndexReceipt(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "IdempotentReplayTest"
	repo.sources["sources/intro.md"] = "stable\n"
	backend := &recordingNamespacedBackend{}
	svc := service{workspace: repo.config.Workspace, repo: repo, backend: backend, mode: ModeFake}

	artifacts, build, err := svc.prepareArtifactProjection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var indexOperations []catalog.ProjectionOperation
	for _, operation := range build.plan.Operations {
		if operation.Kind == catalog.OperationProjectIndex {
			indexOperations = append(indexOperations, operation)
		}
	}
	if len(indexOperations) < 2 {
		t.Fatalf("projection plan has %d index operations, want at least 2", len(indexOperations))
	}
	wantKey := projectionKAGBuildIdempotencyKey(artifacts.BundleManifest.ProjectionVersion)
	if _, err := backend.BuildInNamespaceWithCorpus(ctx, artifacts.BundleManifest.Namespace, wantKey, build.corpus); err != nil {
		t.Fatal(err)
	}
	if err := build.store.Stage(build.plan); err != nil {
		t.Fatal(err)
	}
	if err := build.store.RecordResult(build.plan, catalog.OperationResult{
		OperationID: indexOperations[0].OperationID,
		Outcome:     catalog.OperationSucceeded,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.executeProjectionBuild(ctx, artifacts, build); err != nil {
		t.Fatal(err)
	}
	if backend.buildCalls != 2 {
		t.Fatalf("KAG build requests = %d, want interrupted request plus one replay request", backend.buildCalls)
	}
	if backend.wholeNamespaceBuilds != 1 {
		t.Fatalf("whole-namespace KAG work = %d, want one idempotent build", backend.wholeNamespaceBuilds)
	}
	for _, key := range backend.buildIdempotencyKeys {
		if key != wantKey {
			t.Fatalf("KAG replay key = %q, want projection key %q", key, wantKey)
		}
	}
	if len(backend.buildCorpora) != 2 || !reflect.DeepEqual(backend.buildCorpora[0], backend.buildCorpora[1]) {
		t.Fatalf("crash replay changed prepared corpus: %+v", backend.buildCorpora)
	}
}

func TestServiceRetryRecoversArtifactPointerAfterCatalogCAS(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.config.KAG.Namespace = "RecoveryTest"
	repo.sources["sources/intro.md"] = "first\n"
	backend := &recordingNamespacedBackend{}
	svc := New(Options{Workspace: repo.config.Workspace, Repo: repo, Backend: backend, Mode: ModeFake})
	first, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo.sources["sources/intro.md"] = "second\n"
	repo.publishErr = errors.New("injected public pointer failure")
	failed, err := svc.Build(ctx)
	if err == nil || !strings.Contains(err.Error(), "injected public pointer failure") {
		t.Fatalf("expected public pointer failure, result=%+v err=%v", failed, err)
	}
	if repo.artifacts.BundleManifest.ProjectionVersion != first.BundleManifest.ProjectionVersion {
		t.Fatal("failed public pointer publication changed selected artifacts")
	}
	callsAfterCAS := backend.buildCalls
	workAfterCAS := backend.wholeNamespaceBuilds
	repo.publishErr = nil
	recovered, err := svc.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion ||
		repo.artifacts.BundleManifest.ProjectionVersion != failed.BundleManifest.ProjectionVersion {
		t.Fatalf("retry did not finish the catalog-selected projection: failed=%s recovered=%s current=%s",
			failed.BundleManifest.ProjectionVersion, recovered.BundleManifest.ProjectionVersion,
			repo.artifacts.BundleManifest.ProjectionVersion)
	}
	if backend.buildCalls != callsAfterCAS+1 || backend.wholeNamespaceBuilds != workAfterCAS {
		t.Fatalf("artifact pointer recovery did not idempotently replay KAG: calls=%d->%d work=%d->%d",
			callsAfterCAS, backend.buildCalls, workAfterCAS, backend.wholeNamespaceBuilds)
	}
}

func TestServiceBuildUsesUTF8SafeChunksAndClaims(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.sources["sources/中文.md"] = "# 中文\n\n" + strings.Repeat("知识", 700)
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	if _, err := svc.Build(ctx); err != nil {
		t.Fatal(err)
	}
	if len(repo.artifacts.Chunks) < 2 {
		t.Fatalf("test source did not split into multiple chunks: %+v", repo.artifacts.Chunks)
	}
	for _, chunk := range repo.artifacts.Chunks {
		if !utf8.ValidString(chunk.Text) || strings.Contains(chunk.Text, "\ufffd") {
			t.Fatalf("chunk contains invalid UTF-8 or replacement rune: %+v", chunk)
		}
	}
	for _, claim := range repo.artifacts.Claims {
		if !utf8.ValidString(claim.Text) || strings.Contains(claim.Text, "\ufffd") {
			t.Fatalf("claim contains invalid UTF-8 or replacement rune: %+v", claim)
		}
	}
}

func TestVersionedServiceDelegatesVersionOperations(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryRepo()
	repo.status = repository.Status{Branch: "dev", Raw: "clean"}
	repo.diff = "diff output"
	repo.versions = []repository.Version{{Hash: "abcdef", ShortHash: "abcdef", Subject: "initial", Current: true}}
	repo.commitResult = repository.CommitResult{Hash: "123456", Summary: "committed"}
	svc := New(Options{
		Workspace: repo.config.Workspace,
		Repo:      repo,
		Versions:  repo,
		Backend:   fakeBackend{},
		Mode:      ModeFake,
	})

	status, err := svc.Status(ctx)
	if err != nil || status.Branch != "dev" {
		t.Fatalf("unexpected status: status=%+v err=%v", status, err)
	}
	diff, err := svc.Diff(ctx, "HEAD~1")
	if err != nil || diff != "diff output" || repo.diffRef != "HEAD~1" {
		t.Fatalf("unexpected diff: diff=%q ref=%q err=%v", diff, repo.diffRef, err)
	}
	versions, err := svc.Versions(ctx, 20)
	if err != nil || len(versions) != 1 || versions[0].ShortHash != "abcdef" {
		t.Fatalf("unexpected versions: versions=%+v err=%v", versions, err)
	}
	commit, err := svc.Commit(ctx, "knowledge update")
	if err != nil || commit.Hash != "123456" || repo.commitMessage != "knowledge update" {
		t.Fatalf("unexpected commit: commit=%+v message=%q err=%v", commit, repo.commitMessage, err)
	}
	if err := svc.Release(ctx, "v0.1.1"); err != nil || repo.tagged != "v0.1.1" {
		t.Fatalf("unexpected release: tag=%q err=%v", repo.tagged, err)
	}
	if err := svc.Checkout(ctx, "main", repository.CheckoutOptions{AllowDirty: true}); err != nil {
		t.Fatalf("checkout failed: %v", err)
	}
	if repo.checkoutRef != "main" || !repo.checkoutOpts.AllowDirty {
		t.Fatalf("unexpected checkout call: ref=%q opts=%+v", repo.checkoutRef, repo.checkoutOpts)
	}
}

func TestVersionedPackageImportBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list versioned imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/runtime",
		"/internal/tui",
		"/internal/repository/local",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("knowledge imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

type memoryRepo struct {
	config              repository.Config
	sources             map[string]string
	sourceModTimes      map[string]time.Time
	artifacts           repository.ArtifactSet
	stagedArtifacts     repository.ArtifactSet
	writeArtifactsCalls int
	publishErr          error
	eval                repository.EvalReport
	hash                string
	status              repository.Status
	diff                string
	diffRef             string
	versions            []repository.Version
	commitResult        repository.CommitResult
	commitMessage       string
	tagged              string
	checkoutRef         string
	checkoutOpts        repository.CheckoutOptions
	projectionRoot      string
}

func newMemoryRepo() *memoryRepo {
	projectionRoot, err := os.MkdirTemp("", "knote-versioned-projections-")
	if err != nil {
		panic(err)
	}
	return &memoryRepo{
		config:         repository.Config{Workspace: "/memory"},
		sources:        map[string]string{},
		sourceModTimes: map[string]time.Time{},
		hash:           "current-knowledge-hash",
		projectionRoot: projectionRoot,
	}
}

func (r *memoryRepo) Config(context.Context) (repository.Config, error) {
	return r.config, nil
}

func (r *memoryRepo) SaveConfig(_ context.Context, cfg repository.Config) error {
	r.config = cfg
	return nil
}

func (r *memoryRepo) ListSources(context.Context) ([]repository.Source, error) {
	out := make([]repository.Source, 0, len(r.sources))
	for path, content := range r.sources {
		modTime := time.Unix(1, 0).UTC()
		if configured := r.sourceModTimes[path]; !configured.IsZero() {
			modTime = configured.UTC()
		}
		out = append(out, repository.Source{
			Path:    path,
			Size:    int64(len(content)),
			ModTime: modTime,
		})
	}
	return out, nil
}

func (r *memoryRepo) ReadSource(_ context.Context, path string) ([]byte, error) {
	return []byte(r.sources[path]), nil
}

func (r *memoryRepo) WriteArtifacts(_ context.Context, set repository.ArtifactSet) error {
	r.writeArtifactsCalls++
	r.artifacts = set
	return nil
}

func (r *memoryRepo) StageArtifacts(_ context.Context, set repository.ArtifactSet) error {
	r.writeArtifactsCalls++
	r.stagedArtifacts = set
	return nil
}

func (r *memoryRepo) PublishArtifacts(
	context.Context,
	repository.ArtifactPublicationBase,
	protocol.ArtifactBundleManifest,
) error {
	if r.publishErr != nil {
		return r.publishErr
	}
	r.artifacts = r.stagedArtifacts
	return nil
}

func (r *memoryRepo) ReadCurrentProjection(context.Context) ([]byte, error) {
	if len(r.artifacts.ProjectionJSON) == 0 {
		return nil, repository.ErrArtifactCurrentNotFound
	}
	return append([]byte(nil), r.artifacts.ProjectionJSON...), nil
}

func (r *memoryRepo) ProjectionStoreRoot() string { return r.projectionRoot }

func (r *memoryRepo) ReadManifest(context.Context) (protocol.ArtifactManifest, error) {
	return r.artifacts.Manifest, nil
}

func (r *memoryRepo) ReadCurrentArtifactManifest(context.Context) (protocol.ArtifactBundleManifest, error) {
	if r.artifacts.BundleManifest.Version == 0 {
		return protocol.ArtifactBundleManifest{}, repository.ErrArtifactCurrentNotFound
	}
	return r.artifacts.BundleManifest, nil
}

func (r *memoryRepo) ReadSummaries(context.Context) ([]protocol.Summary, error) {
	return r.artifacts.Summaries, nil
}

func (r *memoryRepo) LoadQuestions(context.Context) ([]repository.EvalQuestion, error) {
	return []repository.EvalQuestion{{ID: "smoke", Question: "What does this knowledge base contain?"}}, nil
}

func (r *memoryRepo) WriteEval(_ context.Context, report repository.EvalReport) error {
	r.eval = report
	return nil
}

func (r *memoryRepo) EvalGate(context.Context) error {
	return nil
}

func (r *memoryRepo) KnowledgeHash(context.Context) (string, error) {
	return r.hash, nil
}

func (r *memoryRepo) Status(context.Context) (repository.Status, error) {
	return r.status, nil
}

func (r *memoryRepo) Diff(_ context.Context, ref string) (string, error) {
	r.diffRef = ref
	return r.diff, nil
}

func (r *memoryRepo) Versions(context.Context, int) ([]repository.Version, error) {
	return append([]repository.Version(nil), r.versions...), nil
}

func (r *memoryRepo) Commit(_ context.Context, message string) (repository.CommitResult, error) {
	r.commitMessage = message
	return r.commitResult, nil
}

func (r *memoryRepo) Tag(_ context.Context, tag string) error {
	r.tagged = tag
	return nil
}

func (r *memoryRepo) Checkout(_ context.Context, ref string, opts repository.CheckoutOptions) error {
	r.checkoutRef = ref
	r.checkoutOpts = opts
	return nil
}

func writeKAGTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

type fakeBackend struct{}

func (fakeBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "fake"}}, nil
}

func (fakeBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "Fake KAG answer", "mode": "fake"}}, nil
}

func (fakeBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "Fake KAG answer", "explanation": "because", "mode": "fake"}}, nil
}

func (b fakeBackend) BuildInNamespace(ctx context.Context, _, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b fakeBackend) BuildInNamespaceWithCorpus(ctx context.Context, _, _ string, _ []kag.CorpusRecord) (kag.Response, error) {
	return b.Build(ctx)
}

func (b fakeBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b fakeBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}

type recordingNamespacedBackend struct {
	buildNamespace       string
	buildIdempotencyKey  string
	buildIdempotencyKeys []string
	queryNamespace       string
	explainNamespace     string
	buildErr             error
	buildCalls           int
	wholeNamespaceBuilds int
	completedBuildKeys   map[string]struct{}
	buildCorpora         [][]kag.CorpusRecord
	runtimeDir           string
}

func (b *recordingNamespacedBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "legacy"}}, nil
}

func (b *recordingNamespacedBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "legacy"}}, nil
}

func (b *recordingNamespacedBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "legacy"}}, nil
}

func (b *recordingNamespacedBackend) BuildInNamespace(_ context.Context, namespace, idempotencyKey string) (kag.Response, error) {
	b.buildNamespace = namespace
	b.buildIdempotencyKey = idempotencyKey
	b.buildIdempotencyKeys = append(b.buildIdempotencyKeys, idempotencyKey)
	b.buildCalls++
	if b.buildErr != nil {
		return kag.Response{}, b.buildErr
	}
	if b.runtimeDir != "" {
		marker := filepath.Join(b.runtimeDir, namespace, idempotencyKey)
		if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
				return kag.Response{}, err
			}
			if err := os.WriteFile(marker, []byte("complete\n"), 0o644); err != nil {
				return kag.Response{}, err
			}
			b.wholeNamespaceBuilds++
		} else if err != nil {
			return kag.Response{}, err
		}
		return kag.Response{Data: map[string]any{"mode": "namespaced", "namespace": namespace}}, nil
	}
	if b.completedBuildKeys == nil {
		b.completedBuildKeys = make(map[string]struct{})
	}
	if _, completed := b.completedBuildKeys[idempotencyKey]; !completed {
		b.completedBuildKeys[idempotencyKey] = struct{}{}
		b.wholeNamespaceBuilds++
	}
	return kag.Response{Data: map[string]any{"mode": "namespaced", "namespace": namespace}}, nil
}

func (b *recordingNamespacedBackend) BuildInNamespaceWithCorpus(ctx context.Context, namespace, idempotencyKey string, corpus []kag.CorpusRecord) (kag.Response, error) {
	b.buildCorpora = append(b.buildCorpora, append([]kag.CorpusRecord(nil), corpus...))
	return b.BuildInNamespace(ctx, namespace, idempotencyKey)
}

func (b *recordingNamespacedBackend) QueryInNamespace(_ context.Context, namespace, _ string) (kag.Response, error) {
	b.queryNamespace = namespace
	return kag.Response{Data: map[string]any{"answer": "namespaced", "namespace": namespace}}, nil
}

func (b *recordingNamespacedBackend) ExplainInNamespace(_ context.Context, namespace, _ string) (kag.Response, error) {
	b.explainNamespace = namespace
	return kag.Response{Data: map[string]any{"answer": "namespaced", "namespace": namespace}}, nil
}

type failingBackend struct{}

func (failingBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{}, nil
}

func (failingBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (failingBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (b failingBackend) BuildInNamespace(ctx context.Context, _, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b failingBackend) BuildInNamespaceWithCorpus(ctx context.Context, _, _ string, _ []kag.CorpusRecord) (kag.Response, error) {
	return b.Build(ctx)
}

func (b failingBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b failingBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}

var errFakeUnavailable = &fakeError{"fake unavailable"}

type buildFailingBackend struct{}

func (buildFailingBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (buildFailingBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (buildFailingBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{}, errFakeUnavailable
}

func (b buildFailingBackend) BuildInNamespace(ctx context.Context, _, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b buildFailingBackend) BuildInNamespaceWithCorpus(ctx context.Context, _, _ string, _ []kag.CorpusRecord) (kag.Response, error) {
	return b.Build(ctx)
}

func (b buildFailingBackend) QueryInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b buildFailingBackend) ExplainInNamespace(ctx context.Context, _ string, query string) (kag.Response, error) {
	return b.Explain(ctx, query)
}

type fakeError struct {
	message string
}

func (e *fakeError) Error() string {
	return e.message
}
