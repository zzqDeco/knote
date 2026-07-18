package authz

import (
	"context"
	"fmt"

	"github.com/zzqDeco/knote/internal/identity"
)

// IdentityMembershipStore is the narrow durable identity surface needed by
// production authorization composition.
type IdentityMembershipStore interface {
	PublishMembershipProjection(
		context.Context,
		identity.MembershipPublicationTarget,
		identity.MembershipPublicationBackend,
	) (identity.MembershipPublicationReceipt, error)
}

// IdentityMembershipPublisher reconciles the latest tenant membership
// projection through the existing OpenFGA tuple writer.
type IdentityMembershipPublisher struct {
	store   IdentityMembershipStore
	backend identity.MembershipPublicationBackend
	target  identity.MembershipPublicationTarget
}

func NewIdentityMembershipPublisher(
	store IdentityMembershipStore,
	backend identity.MembershipPublicationBackend,
	tenantID string,
	storeID string,
	authorizationModelID string,
) (*IdentityMembershipPublisher, error) {
	target := identity.MembershipPublicationTarget{
		TenantID: tenantID, StoreID: storeID, AuthorizationModelID: authorizationModelID,
	}
	if store == nil || backend == nil {
		return nil, fmt.Errorf("%w: identity membership publisher is not initialized", ErrInvalidRequest)
	}
	if err := target.Validate(); err != nil || validateStoreID(storeID) != nil || validateModelID(authorizationModelID) != nil {
		return nil, fmt.Errorf("%w: identity membership publication target is invalid", ErrInvalidRequest)
	}
	return &IdentityMembershipPublisher{store: store, backend: backend, target: target}, nil
}

func (p *IdentityMembershipPublisher) PublishLatest(
	ctx context.Context,
) (identity.MembershipPublicationReceipt, error) {
	if p == nil || p.store == nil || p.backend == nil || ctx == nil {
		return identity.MembershipPublicationReceipt{}, identity.ErrPublicationUnavailable
	}
	return p.store.PublishMembershipProjection(ctx, p.target, p.backend)
}
