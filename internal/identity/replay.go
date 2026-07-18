package identity

import (
	"context"
	"errors"
	"os"
	"slices"
)

func (s *LocalStore) Consume(ctx context.Context, use NonceUse) error {
	if s == nil || s.lock == nil || s.processLock == nil || s.clock == nil || ctx == nil {
		return ErrStoreUnavailable
	}
	if validateCanonicalID("tenant_id", use.TenantID) != nil || validateReplayDigest(use.Digest) != nil ||
		validateUTC("expires_at", use.ExpiresAt) != nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := s.acquireStoreLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return err
	}
	position := registrationIndex(registry, use.TenantID)
	if position < 0 {
		return ErrIdentityUnavailable
	}
	registration := registry.Tenants[position]
	state, err := s.loadTenantByRegistrationLocked(registration)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrIdentityUnavailable
		}
		return err
	}
	now, err := s.now()
	if err != nil {
		return err
	}
	if !use.ExpiresAt.After(now) {
		return ErrReplayDetected
	}
	retained := state.Replays[:0]
	for _, replay := range state.Replays {
		if replay.ExpiresAt.After(now) {
			retained = append(retained, replay)
		}
	}
	state.Replays = retained
	index, found := slices.BinarySearchFunc(state.Replays, use.Digest, func(record replayRecord, digest ReplayDigest) int {
		switch {
		case record.Digest < digest:
			return -1
		case record.Digest > digest:
			return 1
		default:
			return 0
		}
	})
	if found {
		return ErrReplayDetected
	}
	state.Replays = slices.Insert(state.Replays, index, replayRecord{Digest: use.Digest, ExpiresAt: use.ExpiresAt})
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.writeTenantLocked(registration, state)
}
