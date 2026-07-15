package local

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func TestPublishArtifactsSerializesCompatibilityExportsWithPointerPublication(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store := New(workspace)
	base := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "base")
	older := testBundleArtifactSet(t, "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "older")
	newer := testBundleArtifactSet(t, "prj_cccccccccccccccccccccccccccccccc", "newer")

	if err := store.WriteArtifacts(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := store.StageArtifacts(ctx, older); err != nil {
		t.Fatal(err)
	}
	if err := store.StageArtifacts(ctx, newer); err != nil {
		t.Fatal(err)
	}

	olderAtCompatibility := make(chan struct{})
	releaseOlder := make(chan struct{})
	var releaseOlderOnce sync.Once
	release := func() { releaseOlderOnce.Do(func() { close(releaseOlder) }) }
	t.Cleanup(release)

	olderDone := make(chan error, 1)
	olderStore := Store{
		workspace: workspace,
		beforeCompatibilityPublish: func() error {
			close(olderAtCompatibility)
			<-releaseOlder
			return nil
		},
	}
	go func() {
		olderDone <- olderStore.PublishArtifacts(ctx, repository.ArtifactPublicationBase{
			ProjectionVersion: base.BundleManifest.ProjectionVersion,
		}, older.BundleManifest)
	}()
	awaitArtifactPublicationSignal(t, olderAtCompatibility, "older compatibility publication")

	_, lockErr := os.Stat(filepath.Join(workspace, "artifacts", artifactPublicationLockName))
	newerAtCompatibility := make(chan struct{})
	newerDone := make(chan error, 1)
	newerStore := Store{
		workspace: workspace,
		beforeCompatibilityPublish: func() error {
			close(newerAtCompatibility)
			return nil
		},
	}
	go func() {
		newerDone <- newerStore.PublishArtifacts(ctx, repository.ArtifactPublicationBase{
			ProjectionVersion: older.BundleManifest.ProjectionVersion,
		}, newer.BundleManifest)
	}()

	newerFinished := false
	switch {
	case lockErr == nil:
		// The corrected implementation keeps the newer publication blocked until
		// the older pointer and compatibility exports form one serialized update.
		release()
	case os.IsNotExist(lockErr):
		// Under the old ordering, force the newer publication to finish first;
		// releasing the older callback afterward reproduces the stale overwrite.
		awaitArtifactPublicationSignal(t, newerAtCompatibility, "newer compatibility publication")
		if err := awaitArtifactPublicationResult(t, newerDone, "newer publication"); err != nil {
			t.Fatalf("newer publication: %v", err)
		}
		newerFinished = true
		release()
	default:
		t.Fatalf("inspect artifact publication lock: %v", lockErr)
	}

	if err := awaitArtifactPublicationResult(t, olderDone, "older publication"); err != nil {
		t.Fatalf("older publication: %v", err)
	}
	if !newerFinished {
		if err := awaitArtifactPublicationResult(t, newerDone, "newer publication"); err != nil {
			t.Fatalf("newer publication: %v", err)
		}
	}

	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != newer.BundleManifest.ProjectionID {
		t.Fatalf("current projection = %s, want %s", current.ProjectionID, newer.BundleManifest.ProjectionID)
	}

	artifactsDir := filepath.Join(workspace, "artifacts")
	bundleDir := filepath.Join(artifactsDir, "bundles", current.ProjectionID)
	for _, descriptor := range current.Files {
		if descriptor.Path == "projection.json" {
			continue
		}
		assertArtifactFilesEqual(t,
			filepath.Join(artifactsDir, descriptor.Path),
			filepath.Join(bundleDir, descriptor.Path),
		)
	}
	expectedManifest, err := marshalIndentedJSON(current.Compatibility)
	if err != nil {
		t.Fatal(err)
	}
	actualManifest, err := os.ReadFile(filepath.Join(artifactsDir, bundleManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualManifest, expectedManifest) {
		t.Fatalf("flat compatibility manifest does not match current projection %s", current.ProjectionID)
	}
}

func TestPublishArtifactsWaitsForInitialPublicationLockBeforeCandidateAccess(t *testing.T) {
	t.Run("candidate read", func(t *testing.T) {
		ctx := context.Background()
		workspace := t.TempDir()
		store := New(workspace)
		candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "candidate")
		if err := store.StageArtifacts(ctx, candidate); err != nil {
			t.Fatal(err)
		}

		commitLock, err := (gitClient{workspace: workspace}).lockArtifactPublicationForCommit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer commitLock.release()

		var candidatePath string
		for _, descriptor := range candidate.BundleManifest.Files {
			if descriptor.Path != "projection.json" {
				candidatePath = filepath.Join(
					workspace, "artifacts", "bundles", candidate.BundleManifest.ProjectionID, descriptor.Path,
				)
				break
			}
		}
		if candidatePath == "" {
			t.Fatal("test candidate has no compatibility artifact to remove")
		}
		if err := os.Remove(candidatePath); err != nil {
			t.Fatal(err)
		}

		publishParent, cancelPublish := context.WithCancel(ctx)
		defer cancelPublish()
		publishCtx := newArtifactPublicationErrSignalContext(publishParent, 2)
		publishDone := make(chan error, 1)
		go func() {
			publishDone <- store.PublishArtifacts(
				publishCtx,
				repository.ArtifactPublicationBase{Absent: true},
				candidate.BundleManifest,
			)
		}()

		select {
		case <-publishCtx.reached:
			cancelPublish()
		case err := <-publishDone:
			cancelPublish()
			t.Fatalf("publication accessed candidate before acquiring the lock: %v", err)
		case <-time.After(5 * time.Second):
			cancelPublish()
			t.Fatal("timed out waiting for publication lock attempt")
		}
		if err := awaitArtifactPublicationResult(t, publishDone, "canceled initial publication"); !errors.Is(err, context.Canceled) {
			t.Fatalf("publication waiting for lock returned %v, want context cancellation", err)
		}
	})

	t.Run("candidate staging", func(t *testing.T) {
		ctx := context.Background()
		workspace := t.TempDir()
		store := New(workspace)
		candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "candidate")
		if err := store.StageArtifacts(ctx, candidate); err != nil {
			t.Fatal(err)
		}

		commitLock, err := (gitClient{workspace: workspace}).lockArtifactPublicationForCommit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer commitLock.release()

		publishParent, cancelPublish := context.WithCancel(ctx)
		defer cancelPublish()
		publishCtx := newArtifactPublicationErrSignalContext(publishParent, 3)
		publishDone := make(chan error, 1)
		go func() {
			publishDone <- store.PublishArtifacts(
				publishCtx,
				repository.ArtifactPublicationBase{Absent: true},
				candidate.BundleManifest,
			)
		}()
		awaitArtifactPublicationSignal(t, publishCtx.reached, "initial publication lock contention")

		temporary, err := filepath.Glob(filepath.Join(workspace, "artifacts", ".*.tmp"))
		if err != nil {
			cancelPublish()
			t.Fatal(err)
		}
		cancelPublish()
		publishErr := awaitArtifactPublicationResult(t, publishDone, "canceled initial publication")
		if len(temporary) != 0 {
			t.Fatalf("publication staged candidate-derived files before acquiring the lock: %v", temporary)
		}
		if !errors.Is(publishErr, context.Canceled) {
			t.Fatalf("publication waiting for lock returned %v, want context cancellation", publishErr)
		}
	})
}

func TestPublishArtifactsBlocksCommitPruningDuringInitialSelection(t *testing.T) {
	ctx := context.Background()
	workspace := initRepo(t)
	store := New(workspace)
	candidate := testBundleArtifactSet(t, "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "candidate")
	mustWrite(t, filepath.Join(workspace, ".knote", "config.yaml"), "workspace: test\n")
	mustWrite(t, filepath.Join(workspace, "sources", "intro.md"), "initial\n")
	runGit(t, workspace, "add", ".")
	runGit(t, workspace, "commit", "-m", "initial")
	if err := store.StageArtifacts(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "current.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("initial publication unexpectedly has current.json: %v", err)
	}

	publisherAtPointer := make(chan struct{})
	releasePublisher := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releasePublisher) }) }
	t.Cleanup(release)
	publishDone := make(chan error, 1)
	publishing := Store{
		workspace: workspace,
		beforePointerWrite: func(protocol.ArtifactCurrentPointer) error {
			close(publisherAtPointer)
			<-releasePublisher
			return nil
		},
	}
	go func() {
		publishDone <- publishing.PublishArtifacts(
			ctx,
			repository.ArtifactPublicationBase{Absent: true},
			candidate.BundleManifest,
		)
	}()
	awaitArtifactPublicationSignal(t, publisherAtPointer, "candidate pointer publication")

	commitCtx := newArtifactPublicationErrSignalContext(ctx, 2)
	commitDone := make(chan error, 1)
	go func() {
		_, err := (gitClient{workspace: workspace}).Commit(commitCtx, "select candidate")
		commitDone <- err
	}()
	awaitArtifactPublicationSignal(t, commitCtx.reached, "commit publication lock contention")
	select {
	case err := <-commitDone:
		t.Fatalf("commit completed before candidate selection: %v", err)
	default:
	}

	release()
	if err := awaitArtifactPublicationResult(t, publishDone, "candidate publication"); err != nil {
		t.Fatal(err)
	}
	if err := awaitArtifactPublicationResult(t, commitDone, "artifact commit"); err != nil {
		t.Fatal(err)
	}
	current, err := store.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProjectionID != candidate.BundleManifest.ProjectionID {
		t.Fatalf("current projection = %s, want %s", current.ProjectionID, candidate.BundleManifest.ProjectionID)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifacts", "bundles", candidate.BundleManifest.ProjectionID)); err != nil {
		t.Fatalf("selected candidate bundle missing after commit: %v", err)
	}
}

type artifactPublicationErrSignalContext struct {
	context.Context

	mu       sync.Mutex
	calls    int
	signalAt int
	reached  chan struct{}
}

func newArtifactPublicationErrSignalContext(parent context.Context, signalAt int) *artifactPublicationErrSignalContext {
	return &artifactPublicationErrSignalContext{
		Context:  parent,
		signalAt: signalAt,
		reached:  make(chan struct{}),
	}
}

func (c *artifactPublicationErrSignalContext) Err() error {
	err := c.Context.Err()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == c.signalAt {
		close(c.reached)
	}
	return err
}

func awaitArtifactPublicationSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func awaitArtifactPublicationResult(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}

func assertArtifactFilesEqual(t *testing.T, flatPath, bundlePath string) {
	t.Helper()
	flat, err := os.ReadFile(flatPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(flat, bundle) {
		t.Fatalf("flat compatibility export %s does not match current bundle %s", flatPath, bundlePath)
	}
}
