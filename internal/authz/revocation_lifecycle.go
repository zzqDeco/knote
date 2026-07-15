package authz

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/zzqDeco/knote/internal/protocol"
)

type InvalidationRequest struct {
	Revision    AuthorizationRevision `json:"revision"`
	ResourceIDs []protocol.ResourceID `json:"resource_ids"`
}

func (r InvalidationRequest) Validate() error {
	if err := r.Revision.Validate(); err != nil {
		return err
	}
	if len(r.ResourceIDs) == 0 {
		return fmt.Errorf("%w: invalidation requires at least one resource", ErrInvalidRequest)
	}
	return validateCanonicalResourceIDs("invalidation resource IDs", r.ResourceIDs)
}

// ResourceInvalidator must synchronously remove or tombstone stale protected
// evidence for every requested opaque resource ID. Repeating a request must be
// safe.
type ResourceInvalidator interface {
	Invalidate(context.Context, InvalidationRequest) error
}

type ResourceInvalidatorFunc func(context.Context, InvalidationRequest) error

func (f ResourceInvalidatorFunc) Invalidate(ctx context.Context, request InvalidationRequest) error {
	if f == nil {
		return fmt.Errorf("%w: resource invalidator is not initialized", ErrInvalidRequest)
	}
	return f(ctx, request)
}

type RevocationTransition struct {
	BaseRevision       AuthorizationRevision `json:"base_revision"`
	TargetRevision     AuthorizationRevision `json:"target_revision"`
	RetiredResourceIDs []protocol.ResourceID `json:"retired_resource_ids,omitempty"`
	GrantedResourceIDs []protocol.ResourceID `json:"granted_resource_ids,omitempty"`
}

func (t RevocationTransition) Validate() error {
	if err := t.TargetRevision.validateAdvance(t.BaseRevision); err != nil {
		return err
	}
	if err := validateCanonicalResourceIDs("retired resource IDs", t.RetiredResourceIDs); err != nil {
		return err
	}
	if err := validateCanonicalResourceIDs("granted resource IDs", t.GrantedResourceIDs); err != nil {
		return err
	}
	if len(t.RetiredResourceIDs) == 0 && len(t.GrantedResourceIDs) == 0 {
		return fmt.Errorf("%w: revocation transition has no resources", ErrInvalidRequest)
	}
	return nil
}

type RevocationLifecycle interface {
	Prepare(context.Context, RevocationTransition) error
	Commit(context.Context, RevocationTransition) error
	Allows(AuthorizationRevision, protocol.ResourceID) (bool, error)
}

type lifecycleResourceKey struct {
	storeID    string
	resourceID protocol.ResourceID
}

type lifecycleResourceState struct {
	revision     AuthorizationRevision
	blocked      bool
	pendingGrant bool
}

// EpochRevocationLifecycle gates touched resources before cache invalidation
// starts. A committed grant is usable only with the exact target revision (or
// a later epoch), so old decisions cannot become valid after a regrant.
type EpochRevocationLifecycle struct {
	mu          sync.RWMutex
	invalidator ResourceInvalidator
	states      map[lifecycleResourceKey]lifecycleResourceState
}

func NewEpochRevocationLifecycle(invalidator ResourceInvalidator) (*EpochRevocationLifecycle, error) {
	if invalidator == nil {
		return nil, fmt.Errorf("%w: resource invalidator is required", ErrInvalidRequest)
	}
	return &EpochRevocationLifecycle{
		invalidator: invalidator,
		states:      make(map[lifecycleResourceKey]lifecycleResourceState),
	}, nil
}

func (l *EpochRevocationLifecycle) Prepare(ctx context.Context, transition RevocationTransition) error {
	if l == nil || l.invalidator == nil || ctx == nil {
		return fmt.Errorf("%w: revocation lifecycle is not initialized", ErrInvalidRequest)
	}
	if err := transition.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return contextFailure(err)
	}
	granted := resourceIDSet(transition.GrantedResourceIDs)
	touched := canonicalResourceIDUnion(transition.RetiredResourceIDs, transition.GrantedResourceIDs)

	l.mu.Lock()
	for _, resourceID := range touched {
		key := lifecycleResourceKey{storeID: transition.TargetRevision.StoreID, resourceID: resourceID}
		state, exists := l.states[key]
		_, willGrant := granted[resourceID]
		if exists && state.revision.Epoch > transition.TargetRevision.Epoch {
			l.mu.Unlock()
			return fmt.Errorf("%w: resource has a newer lifecycle epoch", ErrRevisionSkew)
		}
		if exists && willGrant && state.blocked && !state.pendingGrant &&
			transition.TargetRevision.Epoch <= state.revision.Epoch {
			l.mu.Unlock()
			return ErrRegrantRevision
		}
		if exists && willGrant && !state.blocked && state.revision.Epoch == transition.TargetRevision.Epoch &&
			transition.BaseRevision.Epoch >= transition.TargetRevision.Epoch {
			l.mu.Unlock()
			return ErrRegrantRevision
		}
	}
	for _, resourceID := range touched {
		key := lifecycleResourceKey{storeID: transition.TargetRevision.StoreID, resourceID: resourceID}
		_, willGrant := granted[resourceID]
		l.states[key] = lifecycleResourceState{
			revision:     transition.TargetRevision,
			blocked:      true,
			pendingGrant: willGrant,
		}
	}
	l.mu.Unlock()

	request := InvalidationRequest{
		Revision:    transition.TargetRevision,
		ResourceIDs: touched,
	}
	if err := l.invalidator.Invalidate(ctx, request); err != nil {
		// The gate remains closed after an invalidation failure. A retry of the
		// same transition is idempotent and may complete it later.
		return fmt.Errorf("invalidate protected resources: %w", err)
	}
	return nil
}

func (l *EpochRevocationLifecycle) Commit(ctx context.Context, transition RevocationTransition) error {
	if l == nil || ctx == nil {
		return fmt.Errorf("%w: revocation lifecycle is not initialized", ErrInvalidRequest)
	}
	if err := transition.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return contextFailure(err)
	}
	touched := canonicalResourceIDUnion(transition.RetiredResourceIDs, transition.GrantedResourceIDs)
	granted := resourceIDSet(transition.GrantedResourceIDs)

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, resourceID := range touched {
		key := lifecycleResourceKey{storeID: transition.TargetRevision.StoreID, resourceID: resourceID}
		state, exists := l.states[key]
		if !exists || state.revision != transition.TargetRevision {
			return fmt.Errorf("%w: lifecycle transition is not prepared", ErrRevisionSkew)
		}
		if _, willGrant := granted[resourceID]; willGrant && !state.blocked && !state.pendingGrant {
			continue
		}
		if !state.blocked {
			return fmt.Errorf("%w: lifecycle transition is not blocked", ErrRevisionSkew)
		}
	}
	for _, resourceID := range transition.GrantedResourceIDs {
		key := lifecycleResourceKey{storeID: transition.TargetRevision.StoreID, resourceID: resourceID}
		state := l.states[key]
		state.blocked = false
		state.pendingGrant = false
		l.states[key] = state
	}
	return nil
}

// Allows reports whether a reader holding revision may use protected evidence
// for resourceID. Integrations must pair revision publication with this gate.
func (l *EpochRevocationLifecycle) Allows(
	revision AuthorizationRevision,
	resourceID protocol.ResourceID,
) (bool, error) {
	if l == nil {
		return false, fmt.Errorf("%w: revocation lifecycle is not initialized", ErrInvalidRequest)
	}
	if err := revision.Validate(); err != nil {
		return false, err
	}
	if err := resourceID.Validate(); err != nil {
		return false, err
	}
	key := lifecycleResourceKey{storeID: revision.StoreID, resourceID: resourceID}
	l.mu.RLock()
	state, exists := l.states[key]
	l.mu.RUnlock()
	if !exists {
		return true, nil
	}
	if state.blocked || revision.Epoch < state.revision.Epoch {
		return false, nil
	}
	if revision.Epoch == state.revision.Epoch && revision != state.revision {
		return false, nil
	}
	return true, nil
}

func validateCanonicalResourceIDs(name string, resourceIDs []protocol.ResourceID) error {
	for index, resourceID := range resourceIDs {
		if err := resourceID.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if index > 0 && resourceIDs[index-1] >= resourceID {
			return fmt.Errorf("%w: %s must be unique and in canonical order", ErrInvalidRequest, name)
		}
	}
	return nil
}

func resourceIDSet(resourceIDs []protocol.ResourceID) map[protocol.ResourceID]struct{} {
	set := make(map[protocol.ResourceID]struct{}, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		set[resourceID] = struct{}{}
	}
	return set
}

func canonicalResourceIDUnion(groups ...[]protocol.ResourceID) []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{})
	for _, group := range groups {
		for _, resourceID := range group {
			seen[resourceID] = struct{}{}
		}
	}
	result := make([]protocol.ResourceID, 0, len(seen))
	for resourceID := range seen {
		result = append(result, resourceID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

var _ RevocationLifecycle = (*EpochRevocationLifecycle)(nil)
