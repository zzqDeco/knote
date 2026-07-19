//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package audit

func installAuditFile(string, string) error { return ErrUnsupportedPlatform }

func replaceAuditFile(string, string) error { return ErrUnsupportedPlatform }
