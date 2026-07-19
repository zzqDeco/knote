//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package audit

import "os"

func syncAuditDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
