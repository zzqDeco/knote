//go:build windows

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type auditFileLock struct {
	handle     windows.Handle
	overlapped windows.Overlapped
}

func acquireAuditFileLock(ctx context.Context, path string, create bool) (*auditFileLock, error) {
	if ctx == nil {
		return nil, ErrStoreUnavailable
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.OPEN_ALWAYS
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open audit process lock: %w", err)
	}
	if err := validateWindowsAuditHandle(handle); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("validate audit process lock: %w", err)
	}
	lock := &auditFileLock{handle: handle}
	for {
		err = windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			&lock.overlapped,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			windows.CloseHandle(handle)
			return nil, fmt.Errorf("acquire audit process lock: %w", err)
		}
		if err := waitForAuditLock(ctx); err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
	}
	return lock, nil
}

func (l *auditFileLock) Close() error {
	if l == nil || l.handle == 0 {
		return nil
	}
	unlockErr := windows.UnlockFileEx(l.handle, 0, 1, 0, &l.overlapped)
	closeErr := windows.CloseHandle(l.handle)
	return errors.Join(unlockErr, closeErr)
}

func openAuditRead(path string) (*os.File, error) {
	return openWindowsAuditFile(path, windows.GENERIC_READ)
}

func openAuditAppend(path string) (*os.File, error) {
	return openWindowsAuditFile(path, windows.GENERIC_READ|windows.FILE_APPEND_DATA)
}

func openAuditReadWrite(path string) (*os.File, error) {
	return openWindowsAuditFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE)
}

func openWindowsAuditFile(path string, access uint32) (*os.File, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsAuditHandle(handle); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("create Go audit file handle")
	}
	return file, nil
}

func validateWindowsAuditHandle(handle windows.Handle) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("audit file is a directory or reparse point")
	}
	if information.NumberOfLinks != 1 {
		return fmt.Errorf("audit file is not a single-link regular file")
	}
	return nil
}
