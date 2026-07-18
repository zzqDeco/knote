package identity

import (
	"context"
	"time"
)

const (
	processLockFileName = ".identity.lock"
	processLockRetry    = 10 * time.Millisecond
)

func waitForProcessLock(ctx context.Context) error {
	timer := time.NewTimer(processLockRetry)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
