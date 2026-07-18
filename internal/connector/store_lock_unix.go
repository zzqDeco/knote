//go:build darwin || linux

package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

type connectorFileLock struct {
	file *os.File
}

func acquireConnectorFileLock(path string) (*connectorFileLock, error) {
	return acquireConnectorFileLockMode(context.Background(), path, false)
}

func acquireConnectorFileLockContext(ctx context.Context, path string) (*connectorFileLock, error) {
	return acquireConnectorFileLockMode(ctx, path, true)
}

func acquireConnectorFileLockMode(ctx context.Context, path string, interruptible bool) (*connectorFileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := secureConnectorFile(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure lock file: %w", err)
	}
	if !interruptible {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
			file.Close()
			return nil, fmt.Errorf("acquire exclusive lock: %w", err)
		}
		return &connectorFileLock{file: file}, nil
	}
	for {
		if err := ctx.Err(); err != nil {
			file.Close()
			return nil, err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &connectorFileLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			file.Close()
			return nil, fmt.Errorf("acquire exclusive lock: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *connectorFileLock) Close() error {
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
