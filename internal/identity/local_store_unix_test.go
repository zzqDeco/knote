//go:build darwin || linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLocalStoreCreatesPrivateRootBeforeChildren(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")

	if _, err := OpenLocalStore(root); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		root,
		filepath.Join(root, tenantDirectory),
		filepath.Join(root, publicationDirectory),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("%s mode = %o, want 700", path, got)
		}
	}
}

func TestOpenLocalStoreRejectsPermissiveRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenLocalStore(root); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("OpenLocalStore() error = %v, want %v", err, ErrStoreUnavailable)
	}
	assertRejectedStoreRootUnchanged(t, root, 0o755)
}

func TestOpenLocalStoreRejectsPermissiveSymlinkTargetWithoutMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "shared-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o775); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "identity-alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenLocalStore(alias); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("OpenLocalStore() error = %v, want %v", err, ErrStoreUnavailable)
	}
	assertRejectedStoreRootUnchanged(t, target, 0o775)
	info, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("identity root alias was replaced: mode=%v", info.Mode())
	}
}

func assertRejectedStoreRootUnchanged(t *testing.T, root string, wantMode os.FileMode) {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != wantMode {
		t.Fatalf("identity store root mode = %o, want unchanged %o", got, wantMode)
	}
	for _, name := range []string{
		tenantDirectory,
		publicationDirectory,
		processLockFileName,
		registryFileName,
	} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected identity store created %s: %v", name, err)
		}
	}
}
