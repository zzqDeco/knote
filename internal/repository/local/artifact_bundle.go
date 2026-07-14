package local

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

const bundleManifestName = "manifest.json"

const (
	artifactPublicationLockName  = ".current.json.lock"
	artifactPublicationLockStale = time.Minute
	artifactPublicationLockPoll  = 10 * time.Millisecond
)

func (s Store) writeArtifactBundle(ctx context.Context, set repository.ArtifactSet) error {
	if set.BundleManifest.Version == 0 {
		payloads, err := repository.CanonicalArtifactFiles(set)
		if err != nil {
			return err
		}
		artifactsDir := filepath.Join(s.workspace, "artifacts")
		if err := ensureRealArtifactDirectory(artifactsDir); err != nil {
			return err
		}
		return writeCompatibilityExports(artifactsDir, set.Manifest, payloads)
	}
	base, err := s.currentArtifactPublicationBase(ctx)
	if err != nil {
		return err
	}
	if err := s.StageArtifacts(ctx, set); err != nil {
		return err
	}
	return s.PublishArtifacts(ctx, base, set.BundleManifest)
}

// StageArtifacts writes and verifies an immutable candidate bundle and the v1
// compatibility exports without changing the serving pointer.
func (s Store) StageArtifacts(ctx context.Context, set repository.ArtifactSet) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := set.BundleManifest.Validate(); err != nil {
		return fmt.Errorf("validate artifact bundle manifest: %w", err)
	}
	if !reflect.DeepEqual(set.Manifest, set.BundleManifest.Compatibility) {
		return fmt.Errorf("v1 compatibility manifest does not match the bundle contract")
	}
	payloads, err := repository.CanonicalArtifactFiles(set)
	if err != nil {
		return err
	}
	if got := repository.ArtifactFileDescriptors(payloads); !reflect.DeepEqual(got, set.BundleManifest.Files) {
		return fmt.Errorf("artifact payloads do not match bundle manifest file descriptors")
	}
	manifestData, err := marshalIndentedJSON(set.BundleManifest)
	if err != nil {
		return fmt.Errorf("marshal artifact bundle manifest: %w", err)
	}
	artifactsDir := filepath.Join(s.workspace, "artifacts")
	bundlesDir := filepath.Join(artifactsDir, "bundles")
	if err := ensureRealArtifactDirectory(artifactsDir); err != nil {
		return err
	}
	if err := ensureRealArtifactDirectory(bundlesDir); err != nil {
		return err
	}
	bundleDir := filepath.Join(bundlesDir, set.BundleManifest.ProjectionID)
	if err := ensureImmutableBundle(bundleDir, payloads, manifestData); err != nil {
		return err
	}
	return nil
}

// PublishArtifacts atomically selects a fully staged immutable bundle. The
// caller must only invoke this after the canonical ProjectionStore CAS has
// published the same projection version.
func (s Store) PublishArtifacts(
	ctx context.Context,
	base repository.ArtifactPublicationBase,
	manifest protocol.ArtifactBundleManifest,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := base.Validate(); err != nil {
		return fmt.Errorf("validate artifact publication base: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	manifestData, err := marshalIndentedJSON(manifest)
	if err != nil {
		return err
	}
	manifestSum := sha256.Sum256(manifestData)
	pointer := protocol.ArtifactCurrentPointer{
		Version: protocol.ArtifactBundleManifestVersion, ProjectionID: manifest.ProjectionID,
		ProjectionVersion: manifest.ProjectionVersion, ManifestSHA256: hex.EncodeToString(manifestSum[:]),
	}
	if err := pointer.Validate(); err != nil {
		return err
	}
	artifactsDir := filepath.Join(s.workspace, "artifacts")
	bundlesDir := filepath.Join(artifactsDir, "bundles")
	if err := validateArtifactBundleDirectory(artifactsDir); err != nil {
		return err
	}
	if err := validateArtifactBundleDirectory(bundlesDir); err != nil {
		return err
	}
	bundleDir := filepath.Join(bundlesDir, manifest.ProjectionID)
	if err := validateArtifactBundleDirectory(bundleDir); err != nil {
		return err
	}
	compatibility, err := stageCompatibilityExportsFromBundle(artifactsDir, manifest)
	if err != nil {
		return err
	}
	defer compatibility.cleanup()
	currentPath := filepath.Join(artifactsDir, "current.json")
	if err := validateArtifactFileDestination(currentPath); err != nil {
		return err
	}
	pointerData, err := marshalIndentedJSON(pointer)
	if err != nil {
		return err
	}
	pointerTemporary, err := stageArtifactBytes(currentPath, pointerData)
	if err != nil {
		return err
	}
	defer os.Remove(pointerTemporary)
	if s.beforePointerWrite != nil {
		if err := s.beforePointerWrite(pointer); err != nil {
			return err
		}
	}
	if err := verifyStagedArtifactBundle(bundleDir, manifest, manifestData); err != nil {
		return err
	}
	publicationLock, err := acquireArtifactPublicationLock(ctx, artifactsDir)
	if err != nil {
		return err
	}
	defer publicationLock.release()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := compareArtifactPublicationBase(currentPath, base); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replaceArtifactFile(pointerTemporary, currentPath); err != nil {
		return err
	}
	if err := syncArtifactDirectory(artifactsDir); err != nil {
		return err
	}
	// current.json is the serving commit point. Compatibility exports are
	// best-effort after it advances so a partial legacy refresh cannot turn a
	// successfully selected bundle into a failed build. Keep publication
	// serialized through the legacy refresh so an older publisher cannot
	// overwrite exports produced by a newer current pointer.
	if s.beforeCompatibilityPublish != nil {
		if err := s.beforeCompatibilityPublish(); err != nil {
			return nil
		}
	}
	_ = compatibility.publish()
	return nil
}

func (s Store) currentArtifactPublicationBase(ctx context.Context) (repository.ArtifactPublicationBase, error) {
	if err := ctx.Err(); err != nil {
		return repository.ArtifactPublicationBase{}, err
	}
	pointer, err := readArtifactCurrentPointer(filepath.Join(s.workspace, "artifacts", "current.json"))
	if errors.Is(err, os.ErrNotExist) {
		return repository.ArtifactPublicationBase{Absent: true}, nil
	}
	if err != nil {
		return repository.ArtifactPublicationBase{}, err
	}
	return repository.ArtifactPublicationBase{ProjectionVersion: pointer.ProjectionVersion}, nil
}

func compareArtifactPublicationBase(path string, expected repository.ArtifactPublicationBase) error {
	pointer, err := readArtifactCurrentPointer(path)
	if errors.Is(err, os.ErrNotExist) {
		if expected.Absent {
			return nil
		}
		return fmt.Errorf(
			"artifact publication expected base %s but current pointer is absent: %w",
			expected.ProjectionVersion, repository.ErrArtifactPublicationStaleBase,
		)
	}
	if err != nil {
		return err
	}
	if expected.Absent {
		return fmt.Errorf(
			"artifact publication expected no current pointer but found %s: %w",
			pointer.ProjectionVersion, repository.ErrArtifactPublicationStaleBase,
		)
	}
	if pointer.ProjectionVersion != expected.ProjectionVersion {
		return fmt.Errorf(
			"artifact publication expected base %s but found %s: %w",
			expected.ProjectionVersion, pointer.ProjectionVersion, repository.ErrArtifactPublicationStaleBase,
		)
	}
	return nil
}

func readArtifactCurrentPointer(path string) (protocol.ArtifactCurrentPointer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return protocol.ArtifactCurrentPointer{}, err
	}
	var pointer protocol.ArtifactCurrentPointer
	if err := json.Unmarshal(data, &pointer); err != nil {
		return protocol.ArtifactCurrentPointer{}, fmt.Errorf("decode artifact current pointer: %w", err)
	}
	if err := pointer.Validate(); err != nil {
		return protocol.ArtifactCurrentPointer{}, fmt.Errorf("validate artifact current pointer: %w", err)
	}
	return pointer, nil
}

func (s Store) ReadCurrentArtifactManifest(ctx context.Context) (protocol.ArtifactBundleManifest, error) {
	if err := ctx.Err(); err != nil {
		return protocol.ArtifactBundleManifest{}, err
	}
	artifactsDir := filepath.Join(s.workspace, "artifacts")
	if err := validateArtifactBundleDirectory(artifactsDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return protocol.ArtifactBundleManifest{}, repository.ErrArtifactCurrentNotFound
		}
		return protocol.ArtifactBundleManifest{}, err
	}
	pointerData, err := os.ReadFile(filepath.Join(artifactsDir, "current.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return protocol.ArtifactBundleManifest{}, repository.ErrArtifactCurrentNotFound
		}
		return protocol.ArtifactBundleManifest{}, err
	}
	var pointer protocol.ArtifactCurrentPointer
	if err := json.Unmarshal(pointerData, &pointer); err != nil {
		return protocol.ArtifactBundleManifest{}, fmt.Errorf("decode artifact current pointer: %w", err)
	}
	if err := pointer.Validate(); err != nil {
		return protocol.ArtifactBundleManifest{}, fmt.Errorf("validate artifact current pointer: %w", err)
	}
	bundlesDir := filepath.Join(artifactsDir, "bundles")
	if err := validateArtifactBundleDirectory(bundlesDir); err != nil {
		return protocol.ArtifactBundleManifest{}, err
	}
	manifestPath := filepath.Join(bundlesDir, pointer.ProjectionID, bundleManifestName)
	if err := validateArtifactBundleDirectory(filepath.Dir(manifestPath)); err != nil {
		return protocol.ArtifactBundleManifest{}, err
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return protocol.ArtifactBundleManifest{}, err
	}
	manifestSum := sha256.Sum256(manifestData)
	if got := hex.EncodeToString(manifestSum[:]); got != pointer.ManifestSHA256 {
		return protocol.ArtifactBundleManifest{}, fmt.Errorf("artifact bundle manifest digest does not match current pointer")
	}
	var manifest protocol.ArtifactBundleManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return protocol.ArtifactBundleManifest{}, fmt.Errorf("decode artifact bundle manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return protocol.ArtifactBundleManifest{}, fmt.Errorf("validate artifact bundle manifest: %w", err)
	}
	if manifest.ProjectionID != pointer.ProjectionID || manifest.ProjectionVersion != pointer.ProjectionVersion {
		return protocol.ArtifactBundleManifest{}, fmt.Errorf("artifact bundle manifest does not match current pointer projection")
	}
	bundleDir := filepath.Dir(manifestPath)
	if err := verifyStagedArtifactBundle(bundleDir, manifest, manifestData); err != nil {
		return protocol.ArtifactBundleManifest{}, err
	}
	files := make(map[string][]byte, len(manifest.Files))
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(bundleDir, file.Path))
		if err != nil {
			return protocol.ArtifactBundleManifest{}, err
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != file.SHA256 || int64(len(data)) != file.SizeBytes {
			return protocol.ArtifactBundleManifest{}, fmt.Errorf("artifact bundle file %q does not match manifest", file.Path)
		}
		files[file.Path] = data
		if file.Path == "projection.json" {
			var projection struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(data, &projection); err != nil {
				return protocol.ArtifactBundleManifest{}, fmt.Errorf("decode artifact projection: %w", err)
			}
			if projection.Version != manifest.ProjectionVersion {
				return protocol.ArtifactBundleManifest{}, fmt.Errorf("artifact projection does not match bundle manifest")
			}
		}
	}
	if err := repository.ValidateGraphArtifactPayloads(manifest, files); err != nil {
		return protocol.ArtifactBundleManifest{}, err
	}
	return manifest, nil
}

func (s Store) ReadCurrentProjection(ctx context.Context) ([]byte, error) {
	manifest, err := s.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(s.workspace, "artifacts", "bundles", manifest.ProjectionID, "projection.json"))
}

// committableArtifactPaths returns the exact selected serving snapshot. Other
// immutable bundles are runtime state and must not be added to Git.
func (s Store) committableArtifactPaths(ctx context.Context) ([]string, bool, error) {
	artifactsDir := filepath.Join(s.workspace, "artifacts")
	bundlesDir := filepath.Join(artifactsDir, "bundles")
	if _, err := os.Lstat(bundlesDir); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, true, err
	}
	if err := validateArtifactBundleDirectory(artifactsDir); err != nil {
		return nil, true, err
	}
	if err := validateArtifactBundleDirectory(bundlesDir); err != nil {
		return nil, true, err
	}
	manifest, err := s.ReadCurrentArtifactManifest(ctx)
	if errors.Is(err, repository.ErrArtifactCurrentNotFound) {
		return nil, true, nil
	}
	if err != nil {
		return nil, true, fmt.Errorf("validate selected artifacts for commit: %w", err)
	}

	paths := []string{
		"artifacts/current.json",
		filepath.ToSlash(filepath.Join("artifacts", "bundles", manifest.ProjectionID, bundleManifestName)),
		"artifacts/manifest.json",
	}
	bundleDir := filepath.Join(bundlesDir, manifest.ProjectionID)
	compatibilityManifest, err := marshalIndentedJSON(manifest.Compatibility)
	if err != nil {
		return nil, true, err
	}
	if err := requireArtifactExport(filepath.Join(artifactsDir, bundleManifestName), compatibilityManifest); err != nil {
		return nil, true, err
	}
	for _, descriptor := range manifest.Files {
		bundlePath := filepath.Join(bundleDir, descriptor.Path)
		paths = append(paths, filepath.ToSlash(filepath.Join("artifacts", "bundles", manifest.ProjectionID, descriptor.Path)))
		if descriptor.Path == "projection.json" {
			continue
		}
		data, err := os.ReadFile(bundlePath)
		if err != nil {
			return nil, true, err
		}
		if err := requireArtifactExport(filepath.Join(artifactsDir, descriptor.Path), data); err != nil {
			return nil, true, err
		}
		paths = append(paths, filepath.ToSlash(filepath.Join("artifacts", descriptor.Path)))
	}
	sort.Strings(paths)
	return paths, true, nil
}

func (s Store) pruneUnselectedArtifactBundles(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	artifactsDir := filepath.Join(s.workspace, "artifacts")
	bundlesDir := filepath.Join(artifactsDir, "bundles")
	if _, err := os.Lstat(bundlesDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	manifest, err := s.ReadCurrentArtifactManifest(ctx)
	if err != nil {
		return fmt.Errorf("validate selected artifacts before pruning: %w", err)
	}
	entries, err := os.ReadDir(bundlesDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == manifest.ProjectionID {
			continue
		}
		if err := os.RemoveAll(filepath.Join(bundlesDir, entry.Name())); err != nil {
			return fmt.Errorf("remove unselected artifact bundle %q: %w", entry.Name(), err)
		}
	}
	return syncArtifactDirectory(bundlesDir)
}

func requireArtifactExport(path string, expected []byte) error {
	if err := validateArtifactFileDestination(path); err != nil {
		return fmt.Errorf("validate selected artifact export for commit: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read selected artifact export for commit: %w", err)
	}
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("selected artifact export %q does not match current bundle", filepath.Base(path))
	}
	return nil
}

func ensureImmutableBundle(bundleDir string, payloads []repository.ArtifactFilePayload, manifestData []byte) error {
	if err := validateArtifactBundleDirectory(bundleDir); err == nil {
		if err := verifyImmutableBundle(bundleDir, payloads, manifestData); err != nil {
			return err
		}
		return syncArtifactDirectory(bundleDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(bundleDir)
	tmpDir, err := os.MkdirTemp(parent, ".bundle-"+filepath.Base(bundleDir)+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	for _, payload := range payloads {
		if err := writeArtifactFileDurably(filepath.Join(tmpDir, payload.Descriptor.Path), payload.Data); err != nil {
			return err
		}
	}
	if err := writeArtifactFileDurably(filepath.Join(tmpDir, bundleManifestName), manifestData); err != nil {
		return err
	}
	if err := syncArtifactDirectory(tmpDir); err != nil {
		return err
	}
	if err := os.Rename(tmpDir, bundleDir); err != nil {
		if _, statErr := os.Stat(bundleDir); statErr == nil {
			return verifyImmutableBundle(bundleDir, payloads, manifestData)
		}
		return err
	}
	return syncArtifactDirectory(parent)
}

func validateArtifactBundleDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("artifact bundle path is not a real directory: %s", path)
	}
	return nil
}

func ensureRealArtifactDirectory(path string) error {
	if err := validateArtifactBundleDirectory(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return validateArtifactBundleDirectory(path)
}

func verifyImmutableBundle(bundleDir string, payloads []repository.ArtifactFilePayload, manifestData []byte) error {
	expected := map[string][]byte{bundleManifestName: manifestData}
	for _, payload := range payloads {
		expected[payload.Descriptor.Path] = payload.Data
	}
	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(bundleDir, entry.Name()))
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("immutable artifact bundle contains non-regular file %q", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	expectedNames := make([]string, 0, len(expected))
	for name := range expected {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(expectedNames)
	if !reflect.DeepEqual(names, expectedNames) {
		return fmt.Errorf("immutable artifact bundle contents differ from projection %s", filepath.Base(bundleDir))
	}
	for _, name := range expectedNames {
		data, err := os.ReadFile(filepath.Join(bundleDir, name))
		if err != nil {
			return err
		}
		if !bytes.Equal(data, expected[name]) {
			return fmt.Errorf("immutable artifact bundle file %q differs from projection %s", name, filepath.Base(bundleDir))
		}
	}
	return nil
}

func verifyStagedArtifactBundle(
	bundleDir string,
	manifest protocol.ArtifactBundleManifest,
	manifestData []byte,
) error {
	expectedNames := make([]string, 0, len(manifest.Files)+1)
	expectedNames = append(expectedNames, bundleManifestName)
	for _, descriptor := range manifest.Files {
		expectedNames = append(expectedNames, descriptor.Path)
	}
	sort.Strings(expectedNames)

	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(bundleDir, entry.Name()))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("immutable artifact bundle contains non-regular file %q", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, expectedNames) {
		return fmt.Errorf("immutable artifact bundle contents differ from projection %s", filepath.Base(bundleDir))
	}

	onDiskManifest, err := os.ReadFile(filepath.Join(bundleDir, bundleManifestName))
	if err != nil {
		return err
	}
	onDiskManifestSum := sha256.Sum256(onDiskManifest)
	expectedManifestSum := sha256.Sum256(manifestData)
	if onDiskManifestSum != expectedManifestSum {
		return fmt.Errorf("immutable artifact bundle manifest digest differs from projection %s", filepath.Base(bundleDir))
	}
	if !bytes.Equal(onDiskManifest, manifestData) {
		return fmt.Errorf("immutable artifact bundle file %q differs from projection %s", bundleManifestName, filepath.Base(bundleDir))
	}
	for _, descriptor := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(bundleDir, descriptor.Path))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != descriptor.SHA256 || int64(len(data)) != descriptor.SizeBytes {
			return fmt.Errorf("immutable artifact bundle file %q differs from projection %s", descriptor.Path, filepath.Base(bundleDir))
		}
	}
	return nil
}

func writeCompatibilityExports(artifactsDir string, manifest protocol.ArtifactManifest, payloads []repository.ArtifactFilePayload) error {
	for _, payload := range payloads {
		if payload.Descriptor.Path == "projection.json" {
			continue
		}
		if err := atomicWriteBytes(filepath.Join(artifactsDir, payload.Descriptor.Path), payload.Data); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(artifactsDir, "manifest.json"), manifest)
}

type stagedArtifactFile struct {
	destination string
	temporary   string
}

type stagedCompatibilityExports struct {
	files []stagedArtifactFile
}

func stageCompatibilityExportsFromBundle(
	artifactsDir string,
	manifest protocol.ArtifactBundleManifest,
) (stagedCompatibilityExports, error) {
	bundleDir := filepath.Join(artifactsDir, "bundles", manifest.ProjectionID)
	exports := make([]repository.ArtifactFilePayload, 0, len(manifest.Files))
	for _, descriptor := range manifest.Files {
		if descriptor.Path == "projection.json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(bundleDir, descriptor.Path))
		if err != nil {
			return stagedCompatibilityExports{}, err
		}
		exports = append(exports, repository.ArtifactFilePayload{Descriptor: descriptor, Data: data})
	}
	manifestData, err := marshalIndentedJSON(manifest.Compatibility)
	if err != nil {
		return stagedCompatibilityExports{}, err
	}
	exports = append(exports, repository.ArtifactFilePayload{
		Descriptor: protocol.ArtifactBundleFile{Path: bundleManifestName},
		Data:       manifestData,
	})

	staged := stagedCompatibilityExports{files: make([]stagedArtifactFile, 0, len(exports))}
	for _, export := range exports {
		destination := filepath.Join(artifactsDir, export.Descriptor.Path)
		if err := validateArtifactFileDestination(destination); err != nil {
			staged.cleanup()
			return stagedCompatibilityExports{}, err
		}
		temporary, err := stageArtifactBytes(destination, export.Data)
		if err != nil {
			staged.cleanup()
			return stagedCompatibilityExports{}, err
		}
		staged.files = append(staged.files, stagedArtifactFile{destination: destination, temporary: temporary})
	}
	return staged, nil
}

func (s stagedCompatibilityExports) publish() error {
	for _, file := range s.files {
		if err := replaceArtifactFile(file.temporary, file.destination); err != nil {
			return err
		}
	}
	if len(s.files) == 0 {
		return nil
	}
	return syncArtifactDirectory(filepath.Dir(s.files[0].destination))
}

func (s stagedCompatibilityExports) cleanup() {
	for _, file := range s.files {
		_ = os.Remove(file.temporary)
	}
}

func validateArtifactFileDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("artifact compatibility export is not a regular file: %s", path)
	}
	return nil
}

func marshalIndentedJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func atomicWriteBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmpPath, err := stageArtifactBytes(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	return replaceArtifactFile(tmpPath, path)
}

func stageArtifactBytes(path string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

func writeArtifactFileDurably(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
