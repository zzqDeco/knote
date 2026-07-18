//go:build windows

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivateDirectoryTree(path string) error {
	path = filepath.Clean(path)
	missing := make([]string, 0, 4)
	current := path
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() {
				return os.ErrInvalid
			}
			if err := validateWindowsDirectoryAncestors(current); err != nil {
				return err
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return os.ErrInvalid
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := createPrivateWindowsDirectory(missing[index]); err != nil {
			if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				return err
			}
			if err := validateWindowsDirectoryShape(missing[index]); err != nil {
				return err
			}
		}
	}
	return validateWindowsDirectoryAncestors(path)
}

func createPrivateWindowsDirectory(path string) error {
	user, err := currentWindowsIdentitySID()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + user.String() + "D:P(A;OICI;GA;;;" + user.String() + ")",
	)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	return windows.CreateDirectory(pointer, attributes)
}

func validatePrivateStoreRootAlias(path, _ string) error {
	return validateWindowsDirectoryAncestors(path)
}

func validateWindowsDirectoryShape(path string) error {
	handle, err := openWindowsIdentityDirectory(path, 0)
	if err != nil {
		return err
	}
	validationErr := validateWindowsIdentityDirectoryHandle(handle)
	return errors.Join(validationErr, windows.CloseHandle(handle))
}

func validateWindowsDirectoryAncestors(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return os.ErrInvalid
	}
	current := volume + string(os.PathSeparator)
	if err := validateWindowsDirectoryShape(current); err != nil {
		return err
	}
	remainder := strings.TrimLeft(strings.TrimPrefix(clean, volume), `\/`)
	for _, component := range strings.FieldsFunc(remainder, func(value rune) bool {
		return value == '\\' || value == '/'
	}) {
		current = filepath.Join(current, component)
		if err := validateWindowsDirectoryShape(current); err != nil {
			return err
		}
	}
	return nil
}

func directoryPermissionsTooBroad(path string, _ os.FileMode) (bool, error) {
	handle, err := openWindowsIdentityDirectory(path, windows.READ_CONTROL)
	if err != nil {
		return false, err
	}
	tooBroad, validationErr := windowsIdentityDirectoryPermissionsTooBroad(handle)
	return tooBroad, errors.Join(validationErr, windows.CloseHandle(handle))
}

func protectPrivateDirectory(path string) error {
	handle, err := openWindowsIdentityDirectory(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	if err := validateWindowsIdentityDirectoryHandle(handle); err != nil {
		return errors.Join(err, windows.CloseHandle(handle))
	}
	ownerMatches, err := windowsIdentityDirectoryOwnerMatches(handle)
	if err != nil || !ownerMatches {
		if err == nil {
			err = os.ErrPermission
		}
		return errors.Join(err, windows.CloseHandle(handle))
	}
	user, err := currentWindowsIdentitySID()
	if err != nil {
		return errors.Join(err, windows.CloseHandle(handle))
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user),
		},
	}}, nil)
	if err != nil {
		return errors.Join(err, windows.CloseHandle(handle))
	}
	secureErr := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
	return errors.Join(secureErr, windows.CloseHandle(handle))
}

func openWindowsIdentityDirectory(path string, access uint32) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		pointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
}

func validateWindowsIdentityDirectoryHandle(handle windows.Handle) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return os.ErrInvalid
	}
	return nil
}

func windowsIdentityDirectoryPermissionsTooBroad(handle windows.Handle) (bool, error) {
	if err := validateWindowsIdentityDirectoryHandle(handle); err != nil {
		return false, err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	return windowsIdentitySecurityDescriptorTooBroad(descriptor)
}

func windowsIdentityDirectoryOwnerMatches(handle windows.Handle) (bool, error) {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	user, err := currentWindowsIdentitySID()
	if err != nil {
		return false, err
	}
	return owner.Equals(user), nil
}

func windowsIdentitySecurityDescriptorTooBroad(descriptor *windows.SECURITY_DESCRIPTOR) (bool, error) {
	if descriptor == nil {
		return false, os.ErrInvalid
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil {
		return true, nil
	}
	user, err := currentWindowsIdentitySID()
	if err != nil {
		return false, err
	}
	if !owner.Equals(user) {
		return true, nil
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return true, nil
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil || dacl.AceCount != 1 {
		return true, nil
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return false, err
	}
	flags := ace.Header.AceFlags
	wantInheritance := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	wantPermissions := windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user) ||
		flags&windows.INHERITED_ACE != 0 ||
		flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != wantInheritance ||
		ace.Mask != windows.GENERIC_ALL && ace.Mask != wantPermissions {
		return true, nil
	}
	return false, nil
}

func currentWindowsIdentitySID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user.User.Sid == nil {
		return nil, os.ErrInvalid
	}
	return user.User.Sid, nil
}
