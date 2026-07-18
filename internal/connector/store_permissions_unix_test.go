//go:build darwin || linux

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

func TestNewStoreRejectsExistingRootThroughAncestorSymlinkWithoutMutation(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(target, "store")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStore(filepath.Join(link, "store")); err == nil {
		t.Fatal("NewStore accepted an existing root reached through an ancestor symlink")
	}
	if _, err := os.Stat(filepath.Join(realRoot, "tenants")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore created children in the symlink target: %v", err)
	}
	if info, err := os.Stat(realRoot); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("NewStore changed the symlink target permissions to %04o", got)
	}
}

func TestNewStoreAcceptsMacOSTrustedVarAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS system alias compatibility")
	}
	base := t.TempDir()
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	const privateVarPrefix = "/private/var/"
	if !strings.HasPrefix(resolved, privateVarPrefix) {
		t.Skipf("temporary directory is not under /private/var: %s", resolved)
	}
	aliasedBase := filepath.Join("/var", strings.TrimPrefix(resolved, privateVarPrefix))
	root := filepath.Join(aliasedBase, "connector", "store")

	store, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore through trusted /var alias: %v", err)
	}
	if got := store.Root(); got != root {
		t.Fatalf("store root = %s, want %s", got, root)
	}
	if _, err := os.Stat(filepath.Join(root, "tenants")); err != nil {
		t.Fatalf("trusted alias store was not initialized: %v", err)
	}
}

func TestConnectorDirectoryUIDOwnershipCheck(t *testing.T) {
	current := uint32(os.Geteuid())
	if !connectorDirectoryUIDOwnedByCurrentUser(current) {
		t.Fatal("current effective UID was rejected")
	}
	if connectorDirectoryUIDOwnedByCurrentUser(current + 1) {
		t.Fatal("foreign UID was accepted")
	}
}

func TestNewStoreRejectsForeignOwnedExistingRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("directory owner metadata is unavailable")
	}
	currentUID := os.Geteuid()
	foreignUID := currentUID + 1
	if err := os.Chown(root, foreignUID, int(stat.Gid)); err != nil {
		t.Skipf("cannot create a foreign-owned fixture: %v", err)
	}
	defer func() {
		if err := os.Chown(root, currentUID, int(stat.Gid)); err != nil {
			t.Errorf("restore fixture owner: %v", err)
		}
	}()

	if _, err := NewStore(root); err == nil {
		t.Fatal("NewStore accepted a foreign-owned existing root")
	}
	if _, err := os.Stat(filepath.Join(root, "tenants")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore created children in the foreign-owned root: %v", err)
	}
	after, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("directory owner metadata is unavailable after rejection")
	}
	if got := int(afterStat.Uid); got != foreignUID {
		t.Fatalf("NewStore changed existing root owner to %d", got)
	}
	if got := after.Mode().Perm(); got != 0o700 {
		t.Fatalf("NewStore changed existing root permissions to %04o", got)
	}
}
