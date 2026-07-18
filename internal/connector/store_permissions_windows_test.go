//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNewStoreCreatesProtectedOwnerOnlyRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "connector", "store")
	if _, err := NewStore(root); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	for _, path := range []string{filepath.Dir(root), root, filepath.Join(root, "tenants")} {
		if err := validateConnectorDirectory(path); err != nil {
			t.Fatalf("created directory %s is not private: %v", path, err)
		}
	}
}

func TestNewStoreRejectsPermissiveExistingRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	setConnectorDirectoryEveryoneACL(t, root)
	if err := validateConnectorDirectory(root); err == nil {
		t.Fatal("test root unexpectedly has an owner-only DACL")
	}

	if _, err := NewStore(root); err == nil {
		t.Fatal("NewStore accepted a permissive existing root")
	}
	if err := validateConnectorDirectory(root); err == nil {
		t.Fatal("NewStore replaced the existing permissive DACL")
	}
	if _, err := os.Stat(filepath.Join(root, "tenants")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore created children in rejected root: %v", err)
	}
}

func setConnectorDirectoryEveryoneACL(t *testing.T, path string) {
	t.Helper()
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathPointer, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	setErr := windows.SetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	if closeErr := windows.CloseHandle(handle); setErr == nil {
		setErr = closeErr
	}
	if setErr != nil {
		t.Fatal(setErr)
	}
}
