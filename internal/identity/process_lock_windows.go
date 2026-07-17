//go:build windows

package identity

import (
	"context"
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type processLock struct {
	path string
}

func newProcessLock(root string) *processLock {
	return newProcessLockAt(filepath.Join(root, processLockFileName))
}

func newProcessLockAt(path string) *processLock {
	return &processLock{path: path}
}

func (l *processLock) acquire(ctx context.Context) (func(), error) {
	if l == nil || l.path == "" || ctx == nil {
		return nil, ErrStoreUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(l.path)
	if err != nil {
		return nil, storeFailure("open identity process lock", err)
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, storeFailure("open identity process lock", err)
	}
	closeOnError := func() { _ = windows.CloseHandle(handle) }
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 ||
		info.NumberOfLinks != 1 {
		closeOnError()
		return nil, storeFailure("validate identity process lock", err)
	}
	overlapped := &windows.Overlapped{}
	for {
		err = windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			overlapped,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			closeOnError()
			return nil, storeFailure("acquire identity process lock", err)
		}
		if err := waitForProcessLock(ctx); err != nil {
			closeOnError()
			return nil, err
		}
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = windows.CloseHandle(handle)
	}, nil
}
