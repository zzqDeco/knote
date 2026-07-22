//go:build darwin

package local

import (
	"os"

	"golang.org/x/sys/unix"
)

func installConfigFile(source, target string) error {
	if err := unix.RenamexNp(source, target, unix.RENAME_EXCL); err != nil {
		if err == unix.EEXIST {
			return os.ErrExist
		}
		return err
	}
	return nil
}
