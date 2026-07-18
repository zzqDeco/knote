//go:build plan9

package identity

import "os"

func createPrivateDirectoryTree(path string) error {
	return os.MkdirAll(path, 0o700)
}

func validatePrivateStoreRootAlias(_, _ string) error {
	return nil
}

func protectPrivateDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func directoryPermissionsTooBroad(_ string, mode os.FileMode) (bool, error) {
	return mode.Perm()&0o077 != 0, nil
}
