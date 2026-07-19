package audit

import (
	"context"
	"time"
)

const auditLockRetry = 10 * time.Millisecond

func waitForAuditLock(ctx context.Context) error {
	timer := time.NewTimer(auditLockRetry)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
