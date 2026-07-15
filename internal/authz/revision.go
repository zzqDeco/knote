package authz

import (
	"context"
	"fmt"
	"strconv"
	"sync"
)

// AtomicRevisionPublisher is an in-process compare-and-swap publication point.
// A durable implementation can satisfy RevisionPublisher without changing the
// reconciler contract.
type AtomicRevisionPublisher struct {
	mu              sync.RWMutex
	current         AuthorizationRevision
	pending         *RevisionReservation
	nextReservation uint64
}

func NewAtomicRevisionPublisher(initial AuthorizationRevision) (*AtomicRevisionPublisher, error) {
	if err := initial.Validate(); err != nil {
		return nil, err
	}
	return &AtomicRevisionPublisher{current: initial}, nil
}

func (p *AtomicRevisionPublisher) Current(ctx context.Context) (AuthorizationRevision, error) {
	if p == nil || ctx == nil {
		return AuthorizationRevision{}, ErrRevisionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return AuthorizationRevision{}, contextFailure(err)
	}
	p.mu.RLock()
	current := p.current
	p.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return AuthorizationRevision{}, contextFailure(err)
	}
	return current, nil
}

func (p *AtomicRevisionPublisher) Reserve(
	ctx context.Context,
	expected AuthorizationRevision,
	next AuthorizationRevision,
) (RevisionReservation, error) {
	if p == nil || ctx == nil {
		return RevisionReservation{}, ErrRevisionUnavailable
	}
	if err := next.validateAdvance(expected); err != nil {
		return RevisionReservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return RevisionReservation{}, contextFailure(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending != nil {
		return RevisionReservation{}, ErrRevisionPending
	}
	if p.current != expected {
		return RevisionReservation{}, fmt.Errorf("%w: expected epoch %d, found %d", ErrRevisionSkew, expected.Epoch, p.current.Epoch)
	}
	if err := ctx.Err(); err != nil {
		return RevisionReservation{}, contextFailure(err)
	}
	p.nextReservation++
	reservation := RevisionReservation{
		ID:       "revision-" + strconv.FormatUint(p.nextReservation, 10),
		Expected: expected,
		Target:   next,
	}
	p.pending = &reservation
	return reservation, nil
}

func (p *AtomicRevisionPublisher) Publish(ctx context.Context, reservation RevisionReservation) error {
	if p == nil || ctx == nil {
		return ErrRevisionUnavailable
	}
	if err := reservation.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return contextFailure(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil || *p.pending != reservation || p.current != reservation.Expected {
		return ErrRevisionSkew
	}
	if err := ctx.Err(); err != nil {
		return contextFailure(err)
	}
	p.current = reservation.Target
	p.pending = nil
	return nil
}

func (p *AtomicRevisionPublisher) Abort(reservation RevisionReservation) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.pending != nil && *p.pending == reservation {
		p.pending = nil
	}
	p.mu.Unlock()
}

var _ RevisionPublisher = (*AtomicRevisionPublisher)(nil)
