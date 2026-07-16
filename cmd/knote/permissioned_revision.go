package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/protocol"
)

var errPermissionedRevisionUnavailable = errors.New("permissioned authorization revision is unavailable")

type permissionedRevisionState struct {
	publisher     authz.RevisionPublisher
	lifecycle     authz.RevocationLifecycle
	scopeMu       sync.RWMutex
	scope         authorized.ArtifactAuthorizationScope
	scopeProvider func(context.Context) (authorized.ArtifactAuthorizationScope, error)
}

func newPermissionedRevisionState(
	config permissionedRuntimeConfig,
	scope authorized.ArtifactAuthorizationScope,
	cache *authorized.QueryCache,
	scopeProvider func(context.Context) (authorized.ArtifactAuthorizationScope, error),
) (*permissionedRevisionState, error) {
	if scopeProvider == nil {
		return nil, errPermissionedRevisionUnavailable
	}
	initial := authz.AuthorizationRevision{
		StoreID:              config.OpenFGA.StoreID,
		AuthorizationModelID: config.OpenFGA.AuthorizationModelID,
		IdentityWatermark:    config.IdentityWatermark,
		ACLWatermark:         scope.ACLWatermark,
		Epoch:                1,
	}
	publisher, err := authz.NewAtomicRevisionPublisher(initial)
	if err != nil {
		return nil, err
	}
	lifecycle, err := authz.NewEpochRevocationLifecycle(authz.ResourceInvalidatorFunc(
		func(ctx context.Context, request authz.InvalidationRequest) error {
			if err := request.Validate(); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if cache == nil {
				return nil
			}
			revokedAt := time.Now().UTC()
			for _, resourceID := range request.ResourceIDs {
				if _, err := cache.InvalidateResource(resourceID, revokedAt); err != nil {
					return err
				}
			}
			return nil
		},
	))
	if err != nil {
		return nil, err
	}
	return &permissionedRevisionState{
		publisher: publisher, lifecycle: lifecycle, scope: scope, scopeProvider: scopeProvider,
	}, nil
}

func (s *permissionedRevisionState) currentForScope(
	ctx context.Context,
	config permissionedRuntimeConfig,
	scope authorized.ArtifactAuthorizationScope,
) (authz.AuthorizationRevision, error) {
	if s == nil || s.publisher == nil || s.lifecycle == nil || s.scopeProvider == nil || ctx == nil {
		return authz.AuthorizationRevision{}, errPermissionedRevisionUnavailable
	}
	current, err := s.publisher.Current(ctx)
	boundScope := s.boundScope()
	if err != nil || current.StoreID != config.OpenFGA.StoreID ||
		current.AuthorizationModelID != config.OpenFGA.AuthorizationModelID ||
		current.IdentityWatermark != config.IdentityWatermark ||
		current.ACLWatermark != scope.ACLWatermark || scope != boundScope {
		return authz.AuthorizationRevision{}, errPermissionedRevisionUnavailable
	}
	return current, nil
}

func (s *permissionedRevisionState) boundScope() authorized.ArtifactAuthorizationScope {
	s.scopeMu.RLock()
	defer s.scopeMu.RUnlock()
	return s.scope
}

func (s *permissionedRevisionState) refreshScope(ctx context.Context) error {
	if s == nil || s.publisher == nil || s.lifecycle == nil || s.scopeProvider == nil || ctx == nil {
		return errPermissionedRevisionUnavailable
	}
	nextScope, err := s.scopeProvider(ctx)
	if err != nil {
		return errPermissionedRevisionUnavailable
	}

	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	if nextScope == s.scope {
		return nil
	}
	current, err := s.publisher.Current(ctx)
	if err != nil {
		return errPermissionedRevisionUnavailable
	}
	target := current
	target.ACLWatermark = nextScope.ACLWatermark
	target.Epoch++
	reservation, err := s.publisher.Reserve(ctx, current, target)
	if err != nil {
		return errPermissionedRevisionUnavailable
	}
	if err := s.publisher.Publish(ctx, reservation); err != nil {
		s.publisher.Abort(reservation)
		return errPermissionedRevisionUnavailable
	}
	s.scope = nextScope
	return nil
}

func (s *permissionedRevisionState) verifyCurrentScope(ctx context.Context) error {
	if s == nil || s.scopeProvider == nil || ctx == nil {
		return errPermissionedRevisionUnavailable
	}
	current, err := s.scopeProvider(ctx)
	if err != nil || current != s.boundScope() {
		return errPermissionedRevisionUnavailable
	}
	return nil
}

func (s *permissionedRevisionState) begin(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) (authz.AuthorizationRevision, error) {
	if s == nil || s.publisher == nil || s.lifecycle == nil || ctx == nil {
		return authz.AuthorizationRevision{}, errPermissionedRevisionUnavailable
	}
	if err := s.verifyCurrentScope(ctx); err != nil {
		return authz.AuthorizationRevision{}, err
	}
	if err := authorization.Validate(); err != nil {
		return authz.AuthorizationRevision{}, errPermissionedRevisionUnavailable
	}
	current, err := s.publisher.Current(ctx)
	if err != nil || current.AuthorizationModelID != authorization.AuthorizationModelID ||
		current.IdentityWatermark != authorization.IdentityWatermark ||
		current.ACLWatermark != authorization.ACLWatermark {
		return authz.AuthorizationRevision{}, errPermissionedRevisionUnavailable
	}
	return current, nil
}

func (s *permissionedRevisionState) finish(
	ctx context.Context,
	expected authz.AuthorizationRevision,
	resourceIDs []protocol.ResourceID,
) error {
	if s == nil || s.publisher == nil || s.lifecycle == nil || ctx == nil {
		return errPermissionedRevisionUnavailable
	}
	if err := s.verifyCurrentScope(ctx); err != nil {
		return err
	}
	current, err := s.publisher.Current(ctx)
	if err != nil || current != expected {
		return errPermissionedRevisionUnavailable
	}
	for _, resourceID := range canonicalPermissionedResourceIDs(resourceIDs) {
		allowed, err := s.lifecycle.Allows(current, resourceID)
		if err != nil || !allowed {
			return errPermissionedRevisionUnavailable
		}
	}
	return nil
}

func permissionedEvidenceResourceIDs(evidence protocol.EvidencePackage) []protocol.ResourceID {
	resourceIDs := make([]protocol.ResourceID, 0, len(evidence.Items)+len(evidence.Decisions)*2)
	for _, item := range evidence.Items {
		resourceIDs = append(resourceIDs, item.Resource.ResourceID)
		for _, support := range item.Supports {
			resourceIDs = append(resourceIDs, support.Resource.ResourceID)
			for _, resource := range support.Evidence {
				resourceIDs = append(resourceIDs, resource.ResourceID)
			}
		}
	}
	for _, decision := range evidence.Decisions {
		resourceIDs = append(resourceIDs, decision.Resource.ResourceID, decision.AuthorizationResource.ResourceID)
	}
	return canonicalPermissionedResourceIDs(resourceIDs)
}

func permissionedBindingResourceIDs(binding protocol.ProtectedContentBinding) []protocol.ResourceID {
	resourceIDs := make([]protocol.ResourceID, 0, len(binding.EvidenceRoots)+len(binding.Resources)*2)
	for _, resource := range binding.EvidenceRoots {
		resourceIDs = append(resourceIDs, resource.ResourceID)
	}
	for _, resource := range binding.Resources {
		resourceIDs = append(
			resourceIDs,
			resource.Resource.ResourceID,
			resource.AuthorizationResource.ResourceID,
		)
	}
	return canonicalPermissionedResourceIDs(resourceIDs)
}

func permissionedDerivedArtifactResourceIDs(item protocol.EvidenceItem) []protocol.ResourceID {
	resourceIDs := []protocol.ResourceID{item.Resource.ResourceID, item.Resource.AuthorizationResourceID}
	for _, support := range item.Supports {
		resourceIDs = append(
			resourceIDs,
			support.Resource.ResourceID,
			support.Resource.AuthorizationResourceID,
		)
		for _, resource := range support.Evidence {
			resourceIDs = append(resourceIDs, resource.ResourceID, resource.AuthorizationResourceID)
		}
	}
	return canonicalPermissionedResourceIDs(resourceIDs)
}

func canonicalPermissionedResourceIDs(resourceIDs []protocol.ResourceID) []protocol.ResourceID {
	seen := make(map[protocol.ResourceID]struct{}, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		if resourceID != "" {
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
