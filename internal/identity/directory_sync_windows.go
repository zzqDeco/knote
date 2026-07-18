//go:build windows

package identity

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func syncIdentityDirectory(path string) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return errors.Join(fmt.Errorf("inspect directory handle: %w", err), windows.CloseHandle(handle))
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.Join(errors.New("identity sync target is not a directory"), windows.CloseHandle(handle))
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("identity sync target is a reparse point"), windows.CloseHandle(handle))
	}
	flushErr := ignoreUnsupportedDirectoryFlushError(
		windows.FlushFileBuffers(handle),
		windows.ERROR_INVALID_FUNCTION,
		windows.ERROR_INVALID_HANDLE,
		windows.ERROR_NOT_SUPPORTED,
	)
	return errors.Join(flushErr, windows.CloseHandle(handle))
}
