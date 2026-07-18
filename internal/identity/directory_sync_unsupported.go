//go:build !darwin && !linux && !windows

package identity

import "os"

func syncIdentityDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
