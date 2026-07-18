//go:build !windows && !plan9

package identity

import (
	"os"
	"syscall"
)

func createPrivateDirectoryTree(path string) error {
	return os.MkdirAll(path, 0o700)
}

func validatePrivateStoreRootAlias(_, _ string) error {
	return nil
}

func protectPrivateDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func directoryPermissionsTooBroad(path string, _ os.FileMode) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if err := validateIdentityDirectoryOwner(info); err != nil {
		return false, err
	}
	return info.Mode().Perm()&0o077 != 0, nil
}

func validateIdentityDirectoryOwner(info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uint32(os.Geteuid()) {
		return os.ErrPermission
	}
	return nil
}
