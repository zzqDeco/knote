//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package audit

import (
	"context"
	"os"
)

type auditFileLock struct{}

func acquireAuditFileLock(context.Context, string, bool) (*auditFileLock, error) {
	return nil, ErrUnsupportedPlatform
}

func (l *auditFileLock) Close() error { return nil }

func openAuditRead(string) (*os.File, error) { return nil, ErrUnsupportedPlatform }

func openAuditAppend(string) (*os.File, error) { return nil, ErrUnsupportedPlatform }

func openAuditReadWrite(string) (*os.File, error) { return nil, ErrUnsupportedPlatform }
