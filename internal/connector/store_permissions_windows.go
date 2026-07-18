//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func secureConnectorDirectory(path string) error { return secureConnectorPath(path, true) }

func validateConnectorPathComponent(path string) error {
	handle, err := openConnectorDirectoryHandle(path, 0)
	if err != nil {
		return err
	}
	validateErr := validateConnectorHandleType(handle, true)
	return errors.Join(validateErr, windows.CloseHandle(handle))
}

func validateConnectorDirectory(path string) error {
	handle, err := openConnectorDirectoryHandle(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	validateErr := validateConnectorHandle(handle, true)
	return errors.Join(validateErr, windows.CloseHandle(handle))
}

func createConnectorDirectory(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;GA;;;" + sid + ")")
	if err != nil {
		return err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	return windows.CreateDirectory(pathPointer, attributes)
}

func secureConnectorFile(file *os.File) error { return secureConnectorPath(file.Name(), false) }

func secureConnectorPath(path string, directory bool) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	if directory {
		access |= windows.WRITE_OWNER
	}
	handle, err := windows.CreateFile(
		pathPointer, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, flags, 0,
	)
	if err != nil {
		return err
	}
	secureErr := secureConnectorHandle(handle, directory)
	return errors.Join(secureErr, windows.CloseHandle(handle))
}

func secureConnectorHandle(handle windows.Handle, directory bool) error {
	if err := validateConnectorHandleType(handle, directory); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;" + inheritance + ";GA;;;" + user.User.Sid.String() + ")",
	)
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	securityInformation := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	var owner *windows.SID
	if directory {
		securityInformation |= windows.OWNER_SECURITY_INFORMATION
		owner = user.User.Sid
	}
	return windows.SetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		securityInformation,
		owner, nil, acl, nil,
	)
}

func validateConnectorHandle(handle windows.Handle, directory bool) error {
	if err := validateConnectorHandleType(handle, directory); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("connector store directory DACL must be protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("connector store directory DACL must contain an owner entry")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return fmt.Errorf("connector store directory must be owned by the current user")
	}
	wantPermissions := windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff,
	)
	wantInheritance := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			return fmt.Errorf("connector store directory DACL is not restricted to the current user")
		}
		if ace.Mask != windows.GENERIC_ALL && ace.Mask != wantPermissions {
			return fmt.Errorf("connector store directory DACL does not grant owner full access")
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 ||
			ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != wantInheritance {
			return fmt.Errorf("connector store directory DACL has invalid inheritance")
		}
	}
	return nil
}

func openConnectorDirectoryHandle(path string, access uint32) (windows.Handle, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		pathPointer, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0,
	)
}

func validateConnectorHandleType(handle windows.Handle, directory bool) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return os.ErrInvalid
	}
	if directory != (information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return os.ErrInvalid
	}
	return nil
}
