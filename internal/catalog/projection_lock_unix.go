//go:build darwin || linux

package catalog

import (
	"fmt"
	"os"
	"syscall"
)

type projectionFileLock struct {
	file *os.File
}

func acquireProjectionFileLock(path string) (*projectionFileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure lock file: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire exclusive lock: %w", err)
	}
	return &projectionFileLock{file: file}, nil
}

func (l *projectionFileLock) Close() error {
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
