//go:build windows

package connector

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

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

func TestValidateConnectorDACLAcceptsEquivalentNormalizedInheritance(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, sddl := range []string{
		"D:P(A;OICI;GA;;;" + sid + ")",
		"D:P(A;;GA;;;" + sid + ")(A;OICIIO;GA;;;" + sid + ")",
		"D:P(A;;GA;;;" + sid + ")(A;OIIO;GA;;;" + sid + ")(A;CIIO;GA;;;" + sid + ")",
	} {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := validateConnectorDACL(dacl, user.User.Sid, true); err != nil {
			t.Fatalf("validate normalized DACL %q: %v", sddl, err)
		}
	}
}

func TestValidateConnectorDACLRejectsIncompleteInheritanceCoverage(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, sddl := range []string{
		"D:P(A;;GA;;;" + sid + ")",
		"D:P(A;OICIIO;GA;;;" + sid + ")",
		"D:P(A;OI;GA;;;" + sid + ")",
		"D:P(A;CI;GA;;;" + sid + ")",
		"D:P(A;OICINP;GA;;;" + sid + ")",
	} {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := validateConnectorDACL(dacl, user.User.Sid, true); err == nil {
			t.Fatalf("validateConnectorDACL accepted incomplete DACL %q", sddl)
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

func TestNewStoreRejectsExistingRootThroughAncestorJunctionWithoutMutation(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(target, "store")
	if err := createConnectorDirectory(realRoot); err != nil {
		t.Fatal(err)
	}
	if err := secureConnectorDirectory(realRoot); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction fixture: %v: %s", err, output)
	}

	if _, err := NewStore(filepath.Join(link, "store")); err == nil {
		t.Fatal("NewStore accepted an existing root reached through an ancestor junction")
	}
	if _, err := os.Stat(filepath.Join(realRoot, "tenants")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore created children in the junction target: %v", err)
	}
	if err := validateConnectorDirectory(realRoot); err != nil {
		t.Fatalf("NewStore mutated the junction target: %v", err)
	}
}

func TestNewStoreRejectsForeignOwnedExistingRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "foreign")
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Equals(current.User.Sid) {
		t.Skip("administrator SID unexpectedly matches the current user SID")
	}
	if err := createConnectorDirectoryWithOwner(root, foreign, current.User.Sid); err != nil {
		t.Skipf("cannot create a foreign-owned fixture: %v", err)
	}
	wantOwner := foreign.String()

	if _, err := NewStore(root); err == nil {
		t.Fatal("NewStore accepted a foreign-owned existing root")
	}
	if _, err := os.Stat(filepath.Join(root, "tenants")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore created children in the foreign-owned root: %v", err)
	}
	if got := connectorDirectoryOwnerSID(t, root); got != wantOwner {
		t.Fatalf("NewStore changed existing root owner to %s", got)
	}
}

func createConnectorDirectoryWithOwner(path string, owner, allowed *windows.SID) error {
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + owner.String() + "D:P(A;OICI;GA;;;" + allowed.String() + ")",
	)
	if err != nil {
		return err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(pathPointer, &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	})
}

func connectorDirectoryOwnerSID(t *testing.T, path string) string {
	t.Helper()
	handle, err := openConnectorDirectoryHandle(path, windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, queryErr := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
	)
	if closeErr := windows.CloseHandle(handle); queryErr == nil {
		queryErr = closeErr
	}
	if queryErr != nil {
		t.Fatal(queryErr)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil {
		t.Fatal("directory has no owner SID")
	}
	return owner.String()
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
