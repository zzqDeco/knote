//go:build darwin || linux

package connector

import (
	"fmt"
	"os"
)

func secureConnectorDirectory(path string) error { return os.Chmod(path, 0o700) }
func createConnectorDirectory(path string) error { return os.Mkdir(path, 0o700) }
func secureConnectorFile(file *os.File) error    { return file.Chmod(0o600) }

func validateConnectorDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("connector store directory is not a real directory: %s", path)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("connector store directory permissions must be 0700: %s", path)
	}
	return nil
}
