//go:build windows

package catalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestProjectionStoreUsesProtectedOwnerOnlyACLs(t *testing.T) {
	store, current, plan := testProjectionStorePlan(t, filepath.Join(t.TempDir(), "store"), "projection-v2")
	if err := store.Stage(plan); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(context.Background(), plan, current, successfulCountingExecutor(nil)); err != nil {
		t.Fatal(err)
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(store.Root(), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		descriptor, err := windows.GetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			t.Fatalf("read DACL for %s: %v", path, err)
		}
		control, _, err := descriptor.Control()
		if err != nil {
			t.Fatalf("read DACL control for %s: %v", path, err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("DACL for %s inherits access from its parent", path)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatalf("read DACL entries for %s: %v", path, err)
		}
		if dacl == nil {
			t.Fatalf("DACL for %s is missing", path)
		}
		if dacl.AceCount != 1 {
			t.Fatalf("DACL for %s has %d entries, want one owner entry", path, dacl.AceCount)
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, 0, &ace); err != nil {
			t.Fatalf("read DACL owner entry for %s: %v", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			t.Fatalf("DACL for %s is not restricted to the current user", path)
		}
		if ace.Mask != windows.GENERIC_ALL {
			t.Fatalf("DACL permissions for %s = %#x, want GENERIC_ALL", path, ace.Mask)
		}
		wantInheritance := uint8(windows.NO_INHERITANCE)
		if info.IsDir() {
			wantInheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		}
		if ace.Header.AceFlags&windows.VALID_INHERIT_FLAGS != wantInheritance {
			t.Fatalf("DACL inheritance for %s = %#x, want %#x", path, ace.Header.AceFlags, wantInheritance)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
