//go:build darwin || linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStoreRejectsSymlinkProcessLock(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "lock-target")
	if err := os.Symlink(target, filepath.Join(root, processLockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocalStore(root); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("symlink process lock error = %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity process lock followed symlink: %v", err)
	}
}

func TestLocalStoreCanonicalizesRootAliasesForInProcessLocking(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "identity-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	first, err := OpenLocalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLocalStore(alias)
	if err != nil {
		t.Fatal(err)
	}
	if first.root != second.root || first.lock != second.lock {
		t.Fatalf("identity store aliases did not share synchronization: first=%q second=%q", first.root, second.root)
	}
}
