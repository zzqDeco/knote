//go:build windows

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectTestStoreRoot(path string) error {
	return protectPrivateDirectory(path)
}

func TestOpenLocalStoreCreatesProtectedOwnerOnlyDirectoryACLs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	if _, err := OpenLocalStore(root); err != nil {
		t.Fatalf("%v; %s", err, describeWindowsIdentityDirectoryACL(root))
	}
	for _, path := range []string{
		root,
		filepath.Join(root, tenantDirectory),
		filepath.Join(root, publicationDirectory),
	} {
		assertOwnerOnlyIdentityDirectoryACL(t, path)
	}
}

func describeWindowsIdentityDirectoryACL(path string) string {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Sprintf("read ACL for %s: %v", path, err)
	}
	control, _, controlErr := descriptor.Control()
	owner, _, ownerErr := descriptor.Owner()
	dacl, _, daclErr := descriptor.DACL()
	parts := []string{
		fmt.Sprintf("path=%s", path),
		fmt.Sprintf("control=%#x error=%v", control, controlErr),
		fmt.Sprintf("owner=%v error=%v", owner, ownerErr),
	}
	if daclErr != nil || dacl == nil {
		return strings.Join(append(parts, fmt.Sprintf("dacl=%v error=%v", dacl, daclErr)), "; ")
	}
	parts = append(parts, fmt.Sprintf("ace_count=%d", dacl.AceCount))
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			parts = append(parts, fmt.Sprintf("ace[%d]=error:%v", index, err))
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		parts = append(parts, fmt.Sprintf(
			"ace[%d]=type:%#x flags:%#x mask:%#x sid:%s",
			index,
			ace.Header.AceType,
			ace.Header.AceFlags,
			ace.Mask,
			sid.String(),
		))
	}
	return strings.Join(parts, "; ")
}

func TestOpenLocalStoreRejectsPermissiveWindowsRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	inheritance := uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(world),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		root,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenLocalStore(root); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("OpenLocalStore() error = %v, want %v", err, ErrStoreUnavailable)
	}
	assertWindowsDirectoryHasSID(t, root, world)
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

func TestWindowsIdentityDirectoryRejectsForeignOwner(t *testing.T) {
	user, err := currentWindowsIdentitySID()
	if err != nil {
		t.Fatal(err)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + world.String() + "D:P(A;OICI;GA;;;" + user.String() + ")",
	)
	if err != nil {
		t.Fatal(err)
	}
	tooBroad, err := windowsIdentitySecurityDescriptorTooBroad(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !tooBroad {
		t.Fatal("current-user-only DACL with a foreign owner was accepted")
	}
}

func assertOwnerOnlyIdentityDirectoryACL(t *testing.T, path string) {
	t.Helper()
	user, err := currentWindowsIdentitySID()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL for %s inherits access from its parent", path)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil || !owner.Equals(user) {
		t.Fatalf("owner for %s = %v, want current user %s", path, owner, user.String())
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatalf("DACL for %s is missing", path)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL for %s has %d entries, want one", path, dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user) ||
		ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
		t.Fatalf("DACL for %s is not protected current-user-only access", path)
	}
}

func assertWindowsDirectoryHasSID(t *testing.T, path string, want *windows.SID) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatalf("DACL for %s is missing", path)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatal(err)
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(want) {
			return
		}
	}
	t.Fatalf("DACL for %s no longer contains SID %s", path, want.String())
}
