package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestStoreImplementsRepositoryContracts(t *testing.T) {
	var _ repository.Workspace = Store{}
	var _ repository.Sessions = Store{}
	var _ repository.PermissionedSessions = Store{}
	var _ repository.Versions = Store{}
}

func TestConfigSourcesAndSafeRead(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)

	cfg := repository.Config{
		Workspace: workspace,
		Permissions: repository.PermissionConfig{
			BuildDefault: "confirm",
			GitDefault:   "allow-once",
		},
		KAG: repository.KAGConfig{
			AdapterPath: "adapters/kag/knote_kag_adapter.py",
			Host:        "http://127.0.0.1:8887",
			Fake:        true,
			ProjectID:   "1",
			Namespace:   "KnoteKB",
			Language:    "en",
			RuntimeDir:  ".knote/kag-runtime",
		},
		Models: map[string]repository.ModelProfile{
			"default": {Provider: "local", Model: "deterministic"},
		},
	}
	if err := store.SaveConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Workspace != workspace || loaded.KAG.Host != cfg.KAG.Host || !loaded.KAG.Fake {
		t.Fatalf("config round trip lost fields: %+v", loaded)
	}

	mustWrite(t, filepath.Join(workspace, "sources", "b.txt"), "second\n")
	mustWrite(t, filepath.Join(workspace, "sources", "a.md"), "first\n")
	mustWrite(t, filepath.Join(workspace, "sources", "ignored.pdf"), "ignored\n")
	sources, err := store.ListSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := sourcePaths(sources); strings.Join(got, ",") != "sources/a.md,sources/b.txt" {
		t.Fatalf("unexpected sources: %+v", sources)
	}
	data, err := store.ReadSource(ctx, "sources/a.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\n" {
		t.Fatalf("unexpected source content: %q", data)
	}
	if _, err := store.ReadSource(ctx, "../outside.md"); err == nil {
		t.Fatal("path traversal should be rejected")
	}
	if _, err := store.ReadSource(ctx, ".knote/config.yaml"); err == nil {
		t.Fatal("non-source workspace files should be rejected")
	}
	outside := filepath.Join(t.TempDir(), "outside.md")
	mustWrite(t, outside, "secret\n")
	if err := os.Symlink(outside, filepath.Join(workspace, "sources", "linked.md")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.ReadSource(ctx, "sources/linked.md"); err == nil {
		t.Fatal("source symlink resolving outside the workspace should be rejected")
	}
}

func TestSessionsAppendLoadAndList(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir())
	event := protocol.NewEvent(protocol.EventUserMessage, "sess_one", "hello", nil)

	if err := store.Append(ctx, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx, "sess_one")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Message != "hello" {
		t.Fatalf("unexpected loaded events: %+v", loaded)
	}
	summaries, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].ID != "sess_one" || summaries[0].EventCount != 1 {
		t.Fatalf("unexpected session summaries: %+v", summaries)
	}
	if err := store.Append(ctx, protocol.NewEvent(protocol.EventUserMessage, "../escape", "bad", nil)); err == nil {
		t.Fatal("session ids with path traversal should be rejected")
	}
}

func TestSessionAuthorizationBindIsIdempotentAndPersistent(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	first := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())

	if err := store.BindAuthorization(ctx, first); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, ".knote", "sessions", "sess_one.authorization.json")
	before := mustRead(t, path)
	expected, err := json.MarshalIndent(first, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if before != string(append(expected, '\n')) {
		t.Fatalf("authorization envelope is not deterministic:\n%s", before)
	}
	for _, forbidden := range []string{"request_id", "title", "body"} {
		if strings.Contains(before, forbidden) {
			t.Fatalf("authorization envelope contains forbidden field %q:\n%s", forbidden, before)
		}
	}

	second := testSessionAuthorizationEnvelope(t, "sess_one", "request-2", time.Unix(2, 0).UTC())
	if err := store.BindAuthorization(ctx, second); err != nil {
		t.Fatalf("exact durable rebinding should be idempotent: %v", err)
	}
	if after := mustRead(t, path); after != before {
		t.Fatalf("idempotent bind replaced the original envelope:\nbefore=%s\nafter=%s", before, after)
	}

	loaded, err := New(workspace).LoadAuthorization(ctx, "sess_one")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != first {
		t.Fatalf("persisted envelope changed: got %+v want %+v", loaded, first)
	}
}

func TestSessionAuthorizationListReturnsOnlyValidCompanionsInSessionIDOrder(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)

	missing, err := store.ListAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Fatalf("missing session directory returned envelopes: %+v", missing)
	}

	sessZ := testSessionAuthorizationEnvelope(t, "sess_z", "request-z", time.Unix(2, 0).UTC())
	sessA := testSessionAuthorizationEnvelope(t, "sess_a", "request-a", time.Unix(1, 0).UTC())
	if err := store.BindAuthorization(ctx, sessZ); err != nil {
		t.Fatal(err)
	}
	if err := store.BindAuthorization(ctx, sessA); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(workspace, ".knote", "sessions")
	corruptHistoryPath := filepath.Join(dir, "sess_a.jsonl")
	mustWrite(t, corruptHistoryPath, "not-jsonl\n")
	mustWrite(t, filepath.Join(dir, "sess_legacy.jsonl"), "also-not-jsonl\n")
	mustWrite(t, filepath.Join(dir, "sess_malformed.authorization.json"), "{not-json\n")
	mustWrite(t, filepath.Join(dir, "..authorization.json"), "{}\n")
	wrongPath := testSessionAuthorizationEnvelope(t, "sess_other", "request-other", time.Unix(3, 0).UTC())
	wrongPathJSON, err := json.Marshal(wrongPath)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "sess_wrong.authorization.json"), string(wrongPathJSON))

	validPath := filepath.Join(dir, "sess_a.authorization.json")
	malformedPath := filepath.Join(dir, "sess_malformed.authorization.json")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(validPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(malformedPath, 0o644); err != nil {
		t.Fatal(err)
	}

	envelopes, err := store.ListAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 2 || envelopes[0] != sessA || envelopes[1] != sessZ {
		t.Fatalf("authorization envelopes were not filtered and sorted: %+v", envelopes)
	}
	assertPermissions(t, dir, 0o700)
	assertPermissions(t, validPath, 0o600)
	assertPermissions(t, malformedPath, 0o600)
	assertPermissions(t, corruptHistoryPath, 0o644)
}

func TestSessionAuthorizationBindRejectsMismatch(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	original := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())
	if err := store.BindAuthorization(ctx, original); err != nil {
		t.Fatal(err)
	}

	mismatch := original
	mismatch.ACLWatermark = "acl-v2"
	mismatch.BoundAt = time.Unix(2, 0).UTC()
	if err := store.BindAuthorization(ctx, mismatch); err == nil {
		t.Fatal("mismatched durable authorization binding was accepted")
	}
	loaded, err := store.LoadAuthorization(ctx, original.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != original {
		t.Fatalf("mismatched bind replaced original envelope: got %+v want %+v", loaded, original)
	}
}

func TestSessionAuthorizationBindIsCreateOnceConcurrently(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	first := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())
	second := first
	second.PrincipalID = "principal-2"
	second.BoundAt = time.Unix(2, 0).UTC()

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, envelope := range []protocol.SessionAuthorizationEnvelope{first, second} {
		go func() {
			<-start
			results <- store.BindAuthorization(ctx, envelope)
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent mismatched binds succeeded %d times, want exactly one", successes)
	}
	loaded, err := store.LoadAuthorization(ctx, "sess_one")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != first && loaded != second {
		t.Fatalf("persisted envelope was not either complete candidate: %+v", loaded)
	}
}

func TestSessionAuthorizationBindIsIdempotentConcurrently(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	first := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())
	second := testSessionAuthorizationEnvelope(t, "sess_one", "request-2", time.Unix(2, 0).UTC())

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, envelope := range []protocol.SessionAuthorizationEnvelope{first, second} {
		go func() {
			<-start
			results <- store.BindAuthorization(ctx, envelope)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent idempotent bind failed: %v", err)
		}
	}
	loaded, err := store.LoadAuthorization(ctx, "sess_one")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != first && loaded != second {
		t.Fatalf("persisted envelope was not either complete candidate: %+v", loaded)
	}
	envelopes, err := store.ListAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 1 || envelopes[0] != loaded {
		t.Fatalf("concurrent bind created multiple envelopes: %+v", envelopes)
	}
}

func TestSessionAuthorizationStagesCompleteEnvelopeBeforeAtomicPublish(t *testing.T) {
	workspace := t.TempDir()
	if err := secureSessionDirectory(workspace, true); err != nil {
		t.Fatal(err)
	}
	envelope := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := sessionAuthorizationPath(workspace, envelope.SessionID)

	temporary, err := stageSessionAuthorization(path, data)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temporary)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging exposed durable authorization path: %v", err)
	}
	if staged := mustRead(t, temporary); staged != string(data) {
		t.Fatalf("staged authorization is incomplete:\n%s", staged)
	}
	assertPermissions(t, temporary, 0o600)

	created, err := publishSessionAuthorization(context.Background(), temporary, path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("complete staged authorization was not published")
	}
	if published := mustRead(t, path); published != string(data) {
		t.Fatalf("published authorization changed:\n%s", published)
	}
}

func TestSessionAuthorizationAtomicPublishCreatesExactlyOneConcurrentWinner(t *testing.T) {
	workspace := t.TempDir()
	if err := secureSessionDirectory(workspace, true); err != nil {
		t.Fatal(err)
	}
	path := sessionAuthorizationPath(workspace, "sess_one")
	first, err := stageSessionAuthorization(path, []byte("first\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(first)
	second, err := stageSessionAuthorization(path, []byte("second\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(second)

	start := make(chan struct{})
	type result struct {
		created bool
		err     error
	}
	results := make(chan result, 2)
	for _, temporary := range []string{first, second} {
		temporary := temporary
		go func() {
			<-start
			created, err := publishSessionAuthorization(context.Background(), temporary, path)
			results <- result{created: created, err: err}
		}()
	}
	close(start)
	created := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("atomic publish created %d envelopes, want exactly one", created)
	}
	if published := mustRead(t, path); published != "first\n" && published != "second\n" {
		t.Fatalf("published partial or unexpected envelope: %q", published)
	}
}

func TestSessionAuthorizationAtomicPublishRecoversStaleLock(t *testing.T) {
	workspace := t.TempDir()
	if err := secureSessionDirectory(workspace, true); err != nil {
		t.Fatal(err)
	}
	path := sessionAuthorizationPath(workspace, "sess_one")
	temporary, err := stageSessionAuthorization(path, []byte("complete\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temporary)
	lockPath := path + sessionAuthorizationLockSuffix
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-2 * sessionAuthorizationLockStale)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatal(err)
	}

	created, err := publishSessionAuthorization(context.Background(), temporary, path)
	if err != nil {
		t.Fatal(err)
	}
	if !created || mustRead(t, path) != "complete\n" {
		t.Fatal("stale publication lock did not recover to a complete envelope")
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication lock remained after recovery: %v", err)
	}
}

func TestSessionAuthorizationAtomicPublishHonorsContextCancellation(t *testing.T) {
	workspace := t.TempDir()
	if err := secureSessionDirectory(workspace, true); err != nil {
		t.Fatal(err)
	}
	path := sessionAuthorizationPath(workspace, "sess_one")
	temporary, err := stageSessionAuthorization(path, []byte("complete\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temporary)
	if err := os.Mkdir(path+sessionAuthorizationLockSuffix, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := publishSessionAuthorization(ctx, temporary, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("publish lock wait returned %v, want context deadline", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled publication created durable envelope: %v", err)
	}
}

func TestSessionAuthorizationMissingAndPathValidation(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir())
	if _, err := store.LoadAuthorization(ctx, "missing"); err != repository.ErrSessionAuthorizationEnvelopeNotFound {
		t.Fatalf("missing envelope error = %v, want stable not-found error", err)
	}

	invalidIDs := []string{"", " ", ".", "..", "../escape", "nested/session", `nested\session`, "line\nbreak"}
	for _, sessionID := range invalidIDs {
		t.Run(fmt.Sprintf("load_%q", sessionID), func(t *testing.T) {
			if _, err := store.LoadAuthorization(ctx, sessionID); err == nil {
				t.Fatal("invalid session id was accepted")
			}
		})
		t.Run(fmt.Sprintf("bind_%q", sessionID), func(t *testing.T) {
			envelope := testSessionAuthorizationEnvelope(t, "valid", "request-1", time.Unix(1, 0).UTC())
			envelope.SessionID = sessionID
			if err := store.BindAuthorization(ctx, envelope); err == nil {
				t.Fatal("invalid session id was accepted")
			}
		})
	}
}

func TestSessionStoragePermissionsArePrivateAndCorrectedOnAccess(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	envelope := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())
	if err := store.BindAuthorization(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, protocol.NewEvent(protocol.EventUserMessage, "sess_one", "hello", nil)); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(workspace, ".knote", "sessions")
	eventPath := filepath.Join(dir, "sess_one.jsonl")
	envelopePath := filepath.Join(dir, "sess_one.authorization.json")
	assertPermissions(t, dir, 0o700)
	assertPermissions(t, eventPath, 0o600)
	assertPermissions(t, envelopePath, 0o600)

	for path, mode := range map[string]os.FileMode{dir: 0o755, eventPath: 0o644, envelopePath: 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.LoadAuthorization(ctx, "sess_one"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "sess_one"); err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, dir, 0o700)
	assertPermissions(t, eventPath, 0o600)
	assertPermissions(t, envelopePath, 0o600)
}

func TestSessionAuthorizationLoadRejectsUnknownFields(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	envelope := testSessionAuthorizationEnvelope(t, "sess_one", "request-1", time.Unix(1, 0).UTC())
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	stored["title"] = "must not be persisted"
	data, err = json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, ".knote", "sessions", "sess_one.authorization.json"), string(data))

	if _, err := New(workspace).LoadAuthorization(ctx, "sess_one"); err == nil {
		t.Fatal("unknown content field was accepted")
	}
}

func TestArtifactsEvalAndGate(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "stable\n")

	manifest := protocol.ArtifactManifest{
		Version:      1,
		Workspace:    workspace,
		GeneratedAt:  time.Now().UTC(),
		SourceCount:  1,
		SummaryCount: 1,
	}
	if err := store.WriteArtifacts(ctx, repository.ArtifactSet{
		Manifest: manifest,
		Summaries: []protocol.Summary{
			{SummaryID: "b", Text: "second"},
			{SummaryID: "a", Text: "first"},
		},
		SchemaYAML:  "version: 1\n",
		BuildReport: "# report\n",
	}); err != nil {
		t.Fatal(err)
	}
	readManifest, err := store.ReadManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if readManifest.SourceCount != 1 || readManifest.SummaryCount != 1 {
		t.Fatalf("unexpected manifest: %+v", readManifest)
	}
	summaries, err := store.ReadSummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 || summaries[0].SummaryID != "a" {
		t.Fatalf("summaries should be sorted and readable: %+v", summaries)
	}

	if err := store.WriteEval(ctx, repository.EvalReport{
		Results: []repository.EvalResult{
			{ID: "smoke", Question: "What is here?", Answer: "stable", KnowledgeHash: "stale-hash"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.EvalGate(ctx); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "changed\n")
	if err := store.EvalGate(ctx); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale eval should block release gate, got %v", err)
	}
}

func TestArtifactBundleCutoverIsImmutableDeterministicAndKeepsV1Exports(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(workspace, "artifacts", "bundles", set.BundleManifest.ProjectionID)
	manifestBefore := mustRead(t, filepath.Join(bundleDir, "manifest.json"))
	pointerBefore := mustRead(t, filepath.Join(workspace, "artifacts", "current.json"))
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(bundleDir, "manifest.json")); got != manifestBefore {
		t.Fatal("no-op build changed immutable v2 manifest")
	}
	if got := mustRead(t, filepath.Join(workspace, "artifacts", "current.json")); got != pointerBefore {
		t.Fatal("no-op build changed serving pointer")
	}

	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 2 || current.ProjectionVersion != set.BundleManifest.ProjectionVersion ||
		current.Namespace != set.BundleManifest.Namespace || current.AuthorizationObject != set.BundleManifest.AuthorizationObject {
		t.Fatalf("unexpected current bundle manifest: %+v", current)
	}
	var compatibility protocol.ArtifactManifest
	if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(workspace, "artifacts", "manifest.json"))), &compatibility); err != nil {
		t.Fatal(err)
	}
	if compatibility.Version != 1 || compatibility.SummaryCount != 1 {
		t.Fatalf("v1 compatibility manifest changed contract: %+v", compatibility)
	}
	if got := mustRead(t, filepath.Join(workspace, "artifacts", "summaries.jsonl")); !strings.Contains(got, "first") {
		t.Fatalf("v1 summary compatibility export missing: %s", got)
	}

	// Flat compatibility files are not the serving source of truth.
	mustWrite(t, filepath.Join(workspace, "artifacts", "summaries.jsonl"), "{\"summary_id\":\"flat\",\"text\":\"wrong\",\"evidence_chunk_ids\":[]}\n")
	summaries, err := store.ReadSummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].Text != "first" {
		t.Fatalf("retrieval read flat compatibility export instead of bundle: %+v", summaries)
	}

	mustWrite(t, filepath.Join(bundleDir, "summaries.jsonl"), "tampered\n")
	if err := store.WriteArtifacts(ctx, set); err == nil || !strings.Contains(err.Error(), "immutable artifact bundle") {
		t.Fatalf("tampered immutable bundle was accepted: %v", err)
	}
}

func TestArtifactPointerFailurePreservesPreviouslyServingBundle(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	first := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	second := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second")
	store := New(workspace)
	if err := store.WriteArtifacts(ctx, first); err != nil {
		t.Fatal(err)
	}
	legacyBefore := mustRead(t, filepath.Join(workspace, "artifacts", "summaries.jsonl"))
	failing := Store{
		workspace: workspace,
		beforePointerWrite: func(protocol.ArtifactCurrentPointer) error {
			return errors.New("injected pointer failure")
		},
	}
	if err := failing.WriteArtifacts(ctx, second); err == nil || !strings.Contains(err.Error(), "injected pointer failure") {
		t.Fatalf("expected pointer failure, got %v", err)
	}
	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != first.BundleManifest.ProjectionID {
		t.Fatalf("failed build advanced current pointer: %+v", current)
	}
	summaries, err := store.ReadSummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].Text != "first" {
		t.Fatalf("failed build changed serving bundle: %+v", summaries)
	}
	if legacyAfter := mustRead(t, filepath.Join(workspace, "artifacts", "summaries.jsonl")); legacyAfter != legacyBefore {
		t.Fatalf("failed pointer publication changed v1 compatibility export:\nbefore=%s\nafter=%s", legacyBefore, legacyAfter)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "bundles", second.BundleManifest.ProjectionID)); err != nil {
		t.Fatalf("fully written failed candidate may remain immutable for retry: %v", err)
	}
}

func TestArtifactCompatibilityPreparationFailurePreservesCurrentPointer(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	first := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	second := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second")
	if err := store.WriteArtifacts(ctx, first); err != nil {
		t.Fatal(err)
	}
	pointerBefore := mustRead(t, filepath.Join(workspace, "artifacts", "current.json"))
	summariesPath := filepath.Join(workspace, "artifacts", "summaries.jsonl")
	if err := os.Remove(summariesPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(summariesPath, 0o755); err != nil {
		t.Fatal(err)
	}

	err := store.WriteArtifacts(ctx, second)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected compatibility preparation failure, got %v", err)
	}
	if pointerAfter := mustRead(t, filepath.Join(workspace, "artifacts", "current.json")); pointerAfter != pointerBefore {
		t.Fatalf("compatibility preparation failure advanced current pointer:\nbefore=%s\nafter=%s", pointerBefore, pointerAfter)
	}
	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != first.BundleManifest.ProjectionID {
		t.Fatalf("compatibility preparation failure selected candidate bundle: %+v", current)
	}
}

func TestArtifactCompatibilityPublishFailureIsNonFatalAfterPointerAdvance(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	first := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	second := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second")
	if err := store.WriteArtifacts(ctx, first); err != nil {
		t.Fatal(err)
	}
	legacyBefore := mustRead(t, filepath.Join(workspace, "artifacts", "summaries.jsonl"))
	failing := Store{
		workspace: workspace,
		beforeCompatibilityPublish: func() error {
			return errors.New("injected compatibility failure")
		},
	}
	if err := failing.WriteArtifacts(ctx, second); err != nil {
		t.Fatalf("post-pointer compatibility failure failed build: %v", err)
	}
	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != second.BundleManifest.ProjectionID {
		t.Fatalf("successful build did not advance current pointer: %+v", current)
	}
	if legacyAfter := mustRead(t, filepath.Join(workspace, "artifacts", "summaries.jsonl")); legacyAfter != legacyBefore {
		t.Fatalf("injected compatibility failure changed legacy export:\nbefore=%s\nafter=%s", legacyBefore, legacyAfter)
	}
}

func TestPublishArtifactsInitialBaseAllowsExactlyOneCompetingSuccessor(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	first := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	second := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second")
	if err := store.StageArtifacts(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.StageArtifacts(ctx, second); err != nil {
		t.Fatal(err)
	}

	expected := repository.ArtifactPublicationBase{Absent: true}
	assertOneArtifactPublicationSucceeds(t, workspace, expected, first, second)
}

func TestPublishArtifactsSameBaseAllowsExactlyOneDivergentSuccessor(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	base := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "base")
	first := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "first")
	second := testBundleArtifactSet(t, "prj_cccccccccccccccccccccccccccccccc", "second")
	if err := store.WriteArtifacts(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := store.StageArtifacts(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.StageArtifacts(ctx, second); err != nil {
		t.Fatal(err)
	}

	expected := repository.ArtifactPublicationBase{ProjectionVersion: base.BundleManifest.ProjectionVersion}
	assertOneArtifactPublicationSucceeds(t, workspace, expected, first, second)
}

func TestPublishArtifactsLockWaitHonorsContextCancellation(t *testing.T) {
	workspace := t.TempDir()
	store := New(workspace)
	candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "candidate")
	if err := store.StageArtifacts(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(workspace, "artifacts", artifactPublicationLockName)
	mustWrite(t, lockPath, `{"token":"active","created_at":"2026-01-01T00:00:00Z"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := store.PublishArtifacts(
		ctx,
		repository.ArtifactPublicationBase{Absent: true},
		candidate.BundleManifest,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("publication waiting on lock returned %v, want context deadline", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "current.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled publication changed current pointer: %v", err)
	}
}

func TestPublishArtifactsRecoversStaleLock(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "candidate")
	if err := store.StageArtifacts(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(workspace, "artifacts", artifactPublicationLockName)
	mustWrite(t, lockPath, `{"token":"abandoned","created_at":"2026-01-01T00:00:00Z"}`)
	staleTime := time.Now().Add(-2 * artifactPublicationLockStale)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	if err := store.PublishArtifacts(
		ctx,
		repository.ArtifactPublicationBase{Absent: true},
		candidate.BundleManifest,
	); err != nil {
		t.Fatalf("publish after stale lock recovery: %v", err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication lock remained after success: %v", err)
	}
}

func assertOneArtifactPublicationSucceeds(
	t *testing.T,
	workspace string,
	expected repository.ArtifactPublicationBase,
	first repository.ArtifactSet,
	second repository.ArtifactSet,
) {
	t.Helper()
	type result struct {
		projectionID string
		err          error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, candidate := range []repository.ArtifactSet{first, second} {
		candidate := candidate
		go func() {
			<-start
			err := New(workspace).PublishArtifacts(context.Background(), expected, candidate.BundleManifest)
			results <- result{projectionID: candidate.BundleManifest.ProjectionID, err: err}
		}()
	}
	close(start)

	var winner string
	staleFailures := 0
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			if winner != "" {
				t.Fatalf("both competing publications succeeded: %s and %s", winner, result.projectionID)
			}
			winner = result.projectionID
		case errors.Is(result.err, repository.ErrArtifactPublicationStaleBase):
			staleFailures++
		default:
			t.Fatalf("competing publication %s failed with unexpected error: %v", result.projectionID, result.err)
		}
	}
	if winner == "" || staleFailures != 1 {
		t.Fatalf("publication results winner=%q stale_failures=%d, want one each", winner, staleFailures)
	}
	current, err := New(workspace).ReadCurrentArtifactManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != winner {
		t.Fatalf("current projection = %s, want successful publication %s", current.ProjectionID, winner)
	}
}

func TestPublishArtifactsRejectsDamagedStagedBundleAndRecovers(t *testing.T) {
	for _, mutation := range []struct {
		name   string
		change func(t *testing.T, path string)
	}{
		{
			name: "corrupted",
			change: func(t *testing.T, path string) {
				t.Helper()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				mustWrite(t, path, string(append(data, []byte("corrupted\n")...)))
			},
		},
		{
			name: "deleted",
			change: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked",
			change: func(t *testing.T, path string) {
				t.Helper()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), filepath.Base(path))
				if err := os.WriteFile(target, data, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
		},
	} {
		for _, file := range []string{bundleManifestName, "summaries.jsonl", "projection.json"} {
			t.Run(mutation.name+"/"+file, func(t *testing.T) {
				ctx := context.Background()
				workspace := t.TempDir()
				store := New(workspace)
				first := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
				candidate := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second")
				if err := store.WriteArtifacts(ctx, first); err != nil {
					t.Fatal(err)
				}
				if err := store.StageArtifacts(ctx, candidate); err != nil {
					t.Fatal(err)
				}
				base, err := store.currentArtifactPublicationBase(ctx)
				if err != nil {
					t.Fatal(err)
				}
				pointerBefore := mustRead(t, filepath.Join(workspace, "artifacts", "current.json"))
				bundleDir := filepath.Join(workspace, "artifacts", "bundles", candidate.BundleManifest.ProjectionID)
				publishing := Store{
					workspace: workspace,
					beforePointerWrite: func(protocol.ArtifactCurrentPointer) error {
						mutation.change(t, filepath.Join(bundleDir, file))
						return nil
					},
				}

				if err := publishing.PublishArtifacts(ctx, base, candidate.BundleManifest); err == nil {
					t.Fatalf("published bundle with %s %s", mutation.name, file)
				}
				if pointerAfter := mustRead(t, filepath.Join(workspace, "artifacts", "current.json")); pointerAfter != pointerBefore {
					t.Fatalf("damaged candidate advanced current pointer:\nbefore=%s\nafter=%s", pointerBefore, pointerAfter)
				}

				if err := os.RemoveAll(bundleDir); err != nil {
					t.Fatal(err)
				}
				if err := store.StageArtifacts(ctx, candidate); err != nil {
					t.Fatalf("restage repaired candidate: %v", err)
				}
				if err := store.PublishArtifacts(ctx, base, candidate.BundleManifest); err != nil {
					t.Fatalf("publish repaired candidate: %v", err)
				}
				current, err := store.ReadCurrentArtifactManifest(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if current.ProjectionID != candidate.BundleManifest.ProjectionID {
					t.Fatalf("repaired candidate was not selected: %+v", current)
				}
			})
		}
	}
}

func TestKnowledgeHashUsesOnlyCurrentPointerAndSelectedBundle(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "stable\n")
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	before, err := store.KnowledgeHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "artifacts", "bundles", "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "orphan"), "ignored\n")
	mustWrite(t, filepath.Join(workspace, "artifacts", "summaries.jsonl"), "legacy compatibility changed\n")
	after, err := store.KnowledgeHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("orphan bundle or v1 compatibility export changed serving knowledge hash: before=%s after=%s", before, after)
	}
}

func TestArtifactReadsFailClosedWhenCurrentPointerIsMalformed(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "artifacts", "current.json"), "{}\n")
	if _, err := store.ReadManifest(ctx); err == nil {
		t.Fatal("malformed v2 current pointer fell back to flat v1 manifest")
	}
	if _, err := store.ReadSummaries(ctx); err == nil {
		t.Fatal("malformed v2 current pointer fell back to flat v1 summaries")
	}
}

func TestArtifactReadsFailClosedWhenSelectedBundleIsMissing(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(
		workspace, "artifacts", "bundles", set.BundleManifest.ProjectionID, "manifest.json",
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadManifest(ctx); err == nil {
		t.Fatal("missing selected bundle fell back to flat v1 manifest")
	}
	if _, err := store.ReadSummaries(ctx); err == nil {
		t.Fatal("missing selected bundle fell back to flat v1 summaries")
	}
	if _, err := store.KnowledgeHash(ctx); err == nil {
		t.Fatal("missing selected bundle produced a legacy knowledge hash")
	}
}

func TestArtifactBundleRejectsSymlinkedProjectionDirectory(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	bundlesDir := filepath.Join(workspace, "artifacts", "bundles")
	if err := os.MkdirAll(bundlesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(bundlesDir, set.BundleManifest.ProjectionID)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := New(workspace).WriteArtifacts(ctx, set); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlinked bundle directory was accepted: %v", err)
	}
}

func TestArtifactBundleRejectsSymlinkedParents(t *testing.T) {
	for _, parent := range []string{"artifacts", "bundles"} {
		t.Run(parent, func(t *testing.T) {
			ctx := context.Background()
			workspace := t.TempDir()
			outside := t.TempDir()
			link := filepath.Join(workspace, "artifacts")
			if parent == "bundles" {
				if err := os.Mkdir(link, 0o755); err != nil {
					t.Fatal(err)
				}
				link = filepath.Join(link, "bundles")
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
			if err := New(workspace).WriteArtifacts(ctx, set); err == nil || !strings.Contains(err.Error(), "real directory") {
				t.Fatalf("symlinked %s directory was accepted: %v", parent, err)
			}
			escapedBundle := filepath.Join(outside, set.BundleManifest.ProjectionID)
			if parent == "artifacts" {
				escapedBundle = filepath.Join(outside, "bundles", set.BundleManifest.ProjectionID)
			}
			if _, err := os.Stat(escapedBundle); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("bundle escaped through symlinked %s directory: %v", parent, err)
			}
		})
	}
}

func TestArtifactBundleReadRejectsSymlinkedBundlesParent(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	set := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first")
	if err := store.WriteArtifacts(ctx, set); err != nil {
		t.Fatal(err)
	}
	bundlesDir := filepath.Join(workspace, "artifacts", "bundles")
	outside := filepath.Join(t.TempDir(), "bundles")
	if err := os.Rename(bundlesDir, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, bundlesDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.ReadCurrentArtifactManifest(ctx); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("read accepted symlinked bundles directory: %v", err)
	}
}

func testBundleArtifactSet(t *testing.T, projectionID, summary string) repository.ArtifactSet {
	t.Helper()
	generatedAt := time.Unix(42, 0).UTC()
	scope := catalog.Scope{TenantID: "local", KnowledgeBaseID: "test"}
	resourceID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceDocument, "sources/test.md")
	if err != nil {
		t.Fatal(err)
	}
	versions := protocol.ResourceVersions{
		Source: "src_0123456789abcdef01234567", Content: "content_test_v1",
		ACL: "authz_0123456789abcdef01234567", Index: "index_" + projectionID,
		Graph: "graph_" + projectionID, Projection: projectionID,
	}
	metadata, err := catalog.NewResourceMetadata(
		scope, protocol.ResourceDocument, "sources/test.md", "document:"+string(resourceID), resourceID,
		protocol.NewContentDigest(summary), versions, catalog.SensitivityInternal, "local",
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata.ServingState = catalog.StatePublished
	metadata.ProjectionStatus = catalog.SucceededProjectionStatus()
	snapshot := catalog.SourceSnapshotRef{
		Scope: scope, SourceID: "workspace", Version: versions.Source, SecurityDomain: "local",
		Digest: protocol.ContentDigest("sha256:" + strings.Repeat("1", 64)), DocumentCount: 1,
	}
	projection, err := catalog.NewProjection(scope, projectionID, snapshot, catalog.StatePublished, []catalog.ResourceMetadata{metadata})
	if err != nil {
		t.Fatal(err)
	}
	graphBindings, claimBindings, err := catalog.ProjectionGraphBindings(projection)
	if err != nil {
		t.Fatal(err)
	}
	manifest := protocol.ArtifactManifest{
		Version: 1, Workspace: "test", GeneratedAt: generatedAt, SourceCount: 1,
		DocumentCount: 1, SummaryCount: 1,
	}
	set := repository.ArtifactSet{
		Manifest: manifest,
		Documents: []protocol.Document{{
			DocumentID: string(resourceID), Path: "sources/test.md", ContentHash: "content-test", Mtime: time.Unix(0, 0).UTC(),
		}},
		Summaries:     []protocol.Summary{{SummaryID: "summary", Text: summary, EvidenceChunkIDs: []string{}}},
		GraphBindings: graphBindings, ClaimBindings: claimBindings, BuildReport: "# report\n",
		BundleManifest: protocol.ArtifactBundleManifest{
			Version: 2, ProjectionID: projectionID, ProjectionVersion: projectionID,
			Namespace:                   "KnoteKB__" + projectionID,
			AuthorizationObject:         "knowledge-base:test:" + projectionID,
			AuthorizationVersion:        "authz_0123456789abcdef01234567",
			GraphBindingContractVersion: protocol.GraphBindingContractVersion,
			SourceSnapshot: protocol.ArtifactSourceSnapshot{
				Version: "src_0123456789abcdef01234567",
				Digest:  strings.Repeat("1", 64), DocumentCount: 1,
			},
			GeneratedAt: generatedAt, Compatibility: manifest,
		},
	}
	projectionJSON, err := json.MarshalIndent(projection, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	set.ProjectionJSON = append(projectionJSON, '\n')
	set.ProjectionResourceCount = len(projection.Resources)
	payloads, err := repository.CanonicalArtifactFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	set.BundleManifest.Files = repository.ArtifactFileDescriptors(payloads)
	return set
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEvalQuestionsFallbackAndSorting(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)

	questions, err := store.LoadQuestions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(questions) != 1 || questions[0].ID != "smoke" || questions[0].Question == "" {
		t.Fatalf("unexpected smoke question: %+v", questions)
	}

	mustWrite(t, filepath.Join(workspace, "evals", "questions.jsonl"), `{"id":"b","question":"second"}
{"question":"first"}
`)
	questions, err = store.LoadQuestions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := questions[0].ID + ":" + questions[1].ID; got != "b:q002" {
		t.Fatalf("questions not sorted or assigned as expected: %+v", questions)
	}
}

func TestVersionsContract(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "initial\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	status, err := store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Branch == "" || status.Dirty {
		t.Fatalf("unexpected clean status: %+v", status)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "updated\n")
	diff, err := store.Diff(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "sources/intro.md") {
		t.Fatalf("diff missing knowledge path:\n%s", diff)
	}
	commit, err := store.Commit(ctx, "knowledge update")
	if err != nil {
		t.Fatal(err)
	}
	if commit.Hash == "" || !strings.Contains(commit.Summary, "knowledge update") {
		t.Fatalf("unexpected commit result: %+v", commit)
	}
	versions, err := store.Versions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Subject != "knowledge update" || !versions[0].Current {
		t.Fatalf("unexpected versions: %+v", versions)
	}
	if err := store.Tag(ctx, "v0.0.1"); err != nil {
		t.Fatal(err)
	}
	versions, err = store.Versions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions[0].Tags) != 1 || versions[0].Tags[0] != "v0.0.1" {
		t.Fatalf("tag was not parsed from decorations: %+v", versions[0])
	}
	if err := store.Checkout(ctx, "HEAD", repository.CheckoutOptions{}); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "dirty\n")
	if err := store.Checkout(ctx, "HEAD", repository.CheckoutOptions{}); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("dirty checkout should require confirmation, got %v", err)
	}
}

func TestCommitOnlyIncludesKnowledgePaths(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "intro\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: changed\n")
	mustWrite(t, filepath.Join(workspace, "evals", "results.jsonl"), "{}\n")
	mustWrite(t, filepath.Join(workspace, "unrelated.txt"), "do not commit\n")
	runGit(t, workspace, "add", "unrelated.txt")

	if _, err := store.Commit(ctx, "knowledge update"); err != nil {
		t.Fatal(err)
	}
	show := runGit(t, workspace, "show", "--name-only", "--format=", "HEAD")
	if !strings.Contains(show, ".knote/config.yaml") || !strings.Contains(show, "evals/results.jsonl") {
		t.Fatalf("commit did not include knowledge paths:\n%s", show)
	}
	if strings.Contains(show, "unrelated.txt") {
		t.Fatalf("commit included unrelated staged file:\n%s", show)
	}
	cached := runGit(t, workspace, "diff", "--cached", "--name-only")
	if strings.TrimSpace(cached) != "unrelated.txt" {
		t.Fatalf("unrelated staged file should remain staged, got %q", cached)
	}
}

func TestCommitIncludesDeletedKnowledgePaths(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "intro\n")
	mustWrite(t, filepath.Join(workspace, "artifacts", "manifest.json"), "{}\n")
	runGit(t, workspace, "add", ".knote/config.yaml", "sources", "artifacts")
	runGit(t, workspace, "commit", "-m", "initial")

	if err := os.Remove(filepath.Join(workspace, ".knote", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(workspace, "artifacts")); err != nil {
		t.Fatal(err)
	}
	diff, err := store.Diff(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, ".knote/config.yaml") || !strings.Contains(diff, "artifacts/manifest.json") {
		t.Fatalf("diff should include deleted knowledge paths:\n%s", diff)
	}

	if _, err := store.Commit(ctx, "remove knowledge paths"); err != nil {
		t.Fatal(err)
	}
	show := runGit(t, workspace, "show", "--name-status", "--format=", "HEAD")
	if !strings.Contains(show, "D\t.knote/config.yaml") || !strings.Contains(show, "D\tartifacts/manifest.json") {
		t.Fatalf("commit did not include deleted knowledge paths:\n%s", show)
	}
	status := runGit(t, workspace, "status", "--short")
	if strings.Contains(status, ".knote/config.yaml") || strings.Contains(status, "artifacts/manifest.json") {
		t.Fatalf("deleted knowledge paths should be clean after commit:\n%s", status)
	}
}

func TestStatusDirtyIgnoresRuntimeSessionFiles(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	store := New(workspace)
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")

	mustWrite(t, filepath.Join(workspace, ".knote", "sessions", "sess.jsonl"), "{}\n")
	status, err := store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Dirty {
		t.Fatal("runtime session files should not make the knowledge workspace dirty")
	}
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "dirty\n")
	status, err = store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Dirty {
		t.Fatal("knowledge changes should still make the workspace dirty")
	}
}

func sourcePaths(sources []repository.Source) []string {
	paths := make([]string, 0, len(sources))
	for _, source := range sources {
		paths = append(paths, source.Path)
	}
	return paths
}

func testSessionAuthorizationEnvelope(t *testing.T, sessionID, requestID string, boundAt time.Time) protocol.SessionAuthorizationEnvelope {
	t.Helper()
	auth := protocol.AuthorizationContext{
		Version:              protocol.SecurityContractVersion,
		TenantID:             "tenant-1",
		KnowledgeBaseID:      "kb-1",
		PrincipalID:          "principal-1",
		SessionID:            sessionID,
		RequestID:            requestID,
		AuthorizationModelID: "model-1",
		IdentityWatermark:    "identity-v1",
		ACLWatermark:         "acl-v1",
		AgentID:              "agent-1",
		TaskID:               "task-1",
		Consistency:          protocol.ConsistencyHigherConsistency,
	}
	envelope, err := protocol.NewSessionAuthorizationEnvelope(auth, boundAt)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, want)
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	workspace := t.TempDir()
	runGit(t, workspace, "init")
	runGit(t, workspace, "config", "user.email", "knote@example.com")
	runGit(t, workspace, "config", "user.name", "knote")
	mustWrite(t, filepath.Join(workspace, ".gitignore"), ".knote/sessions/\n")
	return workspace
}

func mustWrite(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}
