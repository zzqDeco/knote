//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package audit

import "os"

func installAuditFile(source, target string) error {
	if err := os.Link(source, target); err != nil {
		return err
	}
	return os.Remove(source)
}

func replaceAuditFile(source, target string) error {
	return os.Rename(source, target)
}
