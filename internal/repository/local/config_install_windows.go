//go:build windows

package local

import (
	"os"

	"golang.org/x/sys/windows"
)

func installConfigFile(source, target string) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPath, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(sourcePath, targetPath, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_FILE_EXISTS {
			return os.ErrExist
		}
		return err
	}
	return nil
}
