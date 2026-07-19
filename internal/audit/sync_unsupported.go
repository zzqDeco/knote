//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package audit

func syncAuditDirectory(string) error { return ErrUnsupportedPlatform }
