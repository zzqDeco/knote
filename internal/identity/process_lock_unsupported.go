//go:build !darwin && !linux && !windows

package identity

import "context"

type processLock struct{}

func newProcessLock(string) *processLock { return &processLock{} }

func newProcessLockAt(string) *processLock { return &processLock{} }

func (*processLock) acquire(context.Context) (func(), error) {
	return nil, ErrStoreUnavailable
}
