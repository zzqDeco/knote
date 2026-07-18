//go:build darwin || linux

package identity

import (
	"path/filepath"
	"testing"
)

func TestSyncIdentityDirectoryAndMissingPath(t *testing.T) {
	root := t.TempDir()
	if err := syncIdentityDirectory(root); err != nil {
		t.Fatalf("sync directory: %v", err)
	}
	if err := syncIdentityDirectory(filepath.Join(root, "missing")); err == nil {
		t.Fatal("syncing a missing directory unexpectedly succeeded")
	}
}
