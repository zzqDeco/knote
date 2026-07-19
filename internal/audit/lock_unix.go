//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type auditFileLock struct {
	file *os.File
}

func acquireAuditFileLock(ctx context.Context, path string, create bool) (*auditFileLock, error) {
	if ctx == nil {
		return nil, ErrStoreUnavailable
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit process lock: %w", err)
	}
	closeOnError := func() { _ = unix.Close(fd) }
	if err := validateUnixAuditFD(fd); err != nil {
		closeOnError()
		return nil, fmt.Errorf("validate audit process lock: %w", err)
	}
	if create {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			closeOnError()
			return nil, fmt.Errorf("protect audit process lock: %w", err)
		}
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			closeOnError()
			return nil, fmt.Errorf("acquire audit process lock: %w", err)
		}
		if err := waitForAuditLock(ctx); err != nil {
			closeOnError()
			return nil, err
		}
	}
	return &auditFileLock{file: os.NewFile(uintptr(fd), path)}, nil
}

func (l *auditFileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	return errors.Join(unlockErr, closeErr)
}

func openAuditRead(path string) (*os.File, error) {
	return openUnixAuditFile(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
}

func openAuditAppend(path string) (*os.File, error) {
	file, err := openUnixAuditFile(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func openAuditReadWrite(path string) (*os.File, error) {
	return openUnixAuditFile(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW)
}

func openUnixAuditFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	if err := validateUnixAuditFD(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validateUnixAuditFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return fmt.Errorf("audit file is not a single-link regular file")
	}
	if stat.Mode&0o077 != 0 {
		return fmt.Errorf("audit file permissions are not private")
	}
	return nil
}
