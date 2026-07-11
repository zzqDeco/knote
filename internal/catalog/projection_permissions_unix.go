//go:build darwin || linux

package catalog

import (
	"os"
)

func secureProjectionDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func createProjectionDirectory(path string) error {
	return os.Mkdir(path, 0o700)
}

func secureProjectionFile(file *os.File) error {
	return file.Chmod(0o600)
}
