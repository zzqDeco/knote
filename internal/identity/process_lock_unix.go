//go:build darwin || linux

package identity

import (
	"context"
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
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
	fd, err := unix.Open(l.path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, storeFailure("open identity process lock", err)
	}
	closeOnError := func() { _ = unix.Close(fd) }
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		closeOnError()
		return nil, storeFailure("validate identity process lock", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		closeOnError()
		return nil, storeFailure("protect identity process lock", err)
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			closeOnError()
			return nil, storeFailure("acquire identity process lock", err)
		}
		if err := waitForProcessLock(ctx); err != nil {
			closeOnError()
			return nil, err
		}
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}
