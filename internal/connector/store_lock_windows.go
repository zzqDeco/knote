//go:build windows

package connector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

type connectorFileLock struct {
	handle     windows.Handle
	overlapped windows.Overlapped
}

func acquireConnectorFileLock(path string) (*connectorFileLock, error) {
	return acquireConnectorFileLockMode(context.Background(), path, false)
}

func acquireConnectorFileLockContext(ctx context.Context, path string) (*connectorFileLock, error) {
	return acquireConnectorFileLockMode(ctx, path, true)
}

func acquireConnectorFileLockMode(ctx context.Context, path string, interruptible bool) (*connectorFileLock, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	lock := &connectorFileLock{handle: handle}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect lock file: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("lock file is a reparse point")
	}
	if err := secureConnectorHandle(handle, false); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("secure lock file: %w", err)
	}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if interruptible {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
		err := windows.LockFileEx(handle, flags, 0, 1, 0, &lock.overlapped)
		if err == nil {
			return lock, nil
		}
		if !interruptible || !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			windows.CloseHandle(handle)
			return nil, fmt.Errorf("acquire exclusive lock: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			windows.CloseHandle(handle)
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *connectorFileLock) Close() error {
	unlockErr := windows.UnlockFileEx(l.handle, 0, 1, 0, &l.overlapped)
	closeErr := windows.CloseHandle(l.handle)
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
