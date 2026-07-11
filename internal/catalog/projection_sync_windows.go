//go:build windows

package catalog

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func syncDirectory(path string) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Windows has no fsync(2) directory primitive. A write-capable directory
	// handle plus FlushFileBuffers is the strongest supported handle-level flush;
	// failures are returned rather than weakening the durability contract.
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
		return errors.Join(errors.New("directory sync target is not a directory"), windows.CloseHandle(handle))
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("directory sync target is a reparse point"), windows.CloseHandle(handle))
	}
	flushErr := windows.FlushFileBuffers(handle)
	closeErr := windows.CloseHandle(handle)
	return errors.Join(flushErr, closeErr)
}
