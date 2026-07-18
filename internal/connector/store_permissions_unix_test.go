//go:build darwin || linux

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewStoreRejectsPermissiveExistingRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStore(root); err == nil {
		t.Fatal("NewStore accepted a permissive existing root")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("NewStore changed existing root permissions to %04o", got)
	}
	if _, err := os.Stat(filepath.Join(root, "tenants")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore created children in rejected root: %v", err)
	}
}

func TestNewStoreCreatesPrivateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "connector", "store")
	if _, err := NewStore(root); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	for _, path := range []string{filepath.Dir(root), root, filepath.Join(root, "tenants")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("created directory %s permissions = %04o, want 0700", path, got)
		}
	}
}
