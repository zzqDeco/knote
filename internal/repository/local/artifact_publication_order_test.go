package local

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
