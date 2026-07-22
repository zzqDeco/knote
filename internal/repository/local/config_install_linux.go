//go:build linux

package local

import (
	"os"

	"golang.org/x/sys/unix"
)

func installConfigFile(source, target string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		if err == unix.EEXIST {
			return os.ErrExist
		}
		return err
	}
	return nil
}
