//go:build windows

package catalog

import (
	"fmt"

	"golang.org/x/sys/windows"
)

type projectionFileLock struct {
	handle     windows.Handle
	overlapped windows.Overlapped
}

func acquireProjectionFileLock(path string) (*projectionFileLock, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	lock := &projectionFileLock{handle: handle}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect lock file: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("lock file is a reparse point")
	}
	if err := windows.LockFileEx(
		handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &lock.overlapped,
	); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("acquire exclusive lock: %w", err)
	}
	return lock, nil
}

func (l *projectionFileLock) Close() error {
	unlockErr := windows.UnlockFileEx(l.handle, 0, 1, 0, &l.overlapped)
	closeErr := windows.CloseHandle(l.handle)
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
