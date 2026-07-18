package identity

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func (s *LocalStore) UpsertProvider(
	ctx context.Context,
	scope protocol.TenantScope,
	spec ProviderSpec,
) (Provider, Change, error) {
	canonical, err := canonicalProviderSpec(spec)
	if err != nil {
		return Provider{}, Change{}, err
	}
	var result Provider
	state, change, err := s.updateTenant(ctx, scope, RevisionProviderChanged, func(
		state *tenantState,
		_ time.Time,
		_ uint64,
	) (bool, error) {
		candidate := Provider{
			Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
			ProviderID: canonical.ProviderID, Issuer: canonical.Issuer,
			Audiences: append([]string(nil), canonical.Audiences...),
		}
		index := providerIndex(*state, candidate.ProviderID)
		if index >= 0 {
			existing := state.Providers[index]
			if existing.Issuer == candidate.Issuer && slices.Equal(existing.Audiences, candidate.Audiences) {
				result = copyProvider(existing)
				return false, nil
			}
			state.Providers[index] = candidate
			result = copyProvider(candidate)
			return true, nil
		}
		state.Providers = append(state.Providers, candidate)
		canonicalizeTenantState(state)
		result = copyProvider(candidate)
		return true, nil
	})
	if err != nil {
		return Provider{}, Change{}, err
	}
	if result.ProviderID == "" {
		index := providerIndex(state, canonical.ProviderID)
		if index < 0 {
			return Provider{}, Change{}, ErrStoreUnavailable
		}
		result = copyProvider(state.Providers[index])
	}
	return result, change, nil
}

func (s *LocalStore) UpsertUser(
	ctx context.Context,
	scope protocol.TenantScope,
	request UserUpsert,
) (User, Change, error) {
	if err := validateUserUpsert(request); err != nil {
		return User{}, Change{}, err
	}
	reason := RevisionUserChanged
	if !request.Active {
		reason = RevisionDeprovisioned
	}
	var result User
	state, change, err := s.updateTenant(ctx, scope, reason, func(
		state *tenantState,
		now time.Time,
		nextRevision uint64,
	) (bool, error) {
		if providerIndex(*state, request.ProviderID) < 0 {
			return false, ErrIdentityUnavailable
		}
		index := userIndex(*state, request.ProviderID, request.ExternalID)
		if index >= 0 {
			existing := state.Users[index]
			if existing.ExternalSubjectID != request.ExternalSubjectID ||
				existing.PrincipalID != request.PrincipalID {
				return false, ErrConflict
			}
			if existing.State == protocol.IdentityDeprovisioned {
				if !request.Active {
					result = existing
					return false, nil
				}
				return false, ErrDeprovisioned
			}
			if err := validateUserUniqueness(*state, request, existing.ID); err != nil {
				return false, err
			}
			if request.Active {
				result = existing
				return false, nil
			}
			existing.UpdatedAt = now
			existing.UpdatedRevision = nextRevision
			if !request.Active {
				existing.State = protocol.IdentityDeprovisioned
				removeUserMemberships(state, existing.ID, now, nextRevision)
				appendTombstone(state, TombstoneUser, existing.ID, existing.ProviderID, existing.ExternalID, now, nextRevision)
			}
			state.Users[index] = existing
			result = existing
			return true, nil
		}
		if err := validateUserUniqueness(*state, request, ""); err != nil {
			return false, err
		}
		user := User{
			Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
			ID:         stableResourceID("identity_user_", scope.TenantID, request.ProviderID, request.ExternalID),
			ProviderID: request.ProviderID, ExternalID: request.ExternalID,
			ExternalSubjectID: request.ExternalSubjectID, PrincipalID: request.PrincipalID,
			State: protocol.IdentityActive, CreatedAt: now, UpdatedAt: now, UpdatedRevision: nextRevision,
		}
		if !request.Active {
			user.State = protocol.IdentityDeprovisioned
			appendTombstone(state, TombstoneUser, user.ID, user.ProviderID, user.ExternalID, now, nextRevision)
		}
		state.Users = append(state.Users, user)
		canonicalizeTenantState(state)
		result = user
		return true, nil
	})
	if err != nil {
		return User{}, Change{}, err
	}
	if result.ID == "" {
		index := userIndex(state, request.ProviderID, request.ExternalID)
		if index < 0 {
			return User{}, Change{}, ErrStoreUnavailable
		}
		result = state.Users[index]
	}
	return result, change, nil
}

func (s *LocalStore) UpsertGroup(
	ctx context.Context,
	scope protocol.TenantScope,
	request GroupUpsert,
) (Group, Change, error) {
	if err := validateGroupUpsert(request); err != nil {
		return Group{}, Change{}, err
	}
	reason := RevisionGroupChanged
	if !request.Active {
		reason = RevisionDeprovisioned
	}
	var result Group
	state, change, err := s.updateTenant(ctx, scope, reason, func(
		state *tenantState,
		now time.Time,
		nextRevision uint64,
	) (bool, error) {
		if providerIndex(*state, request.ProviderID) < 0 {
			return false, ErrIdentityUnavailable
		}
		index := groupIndex(*state, request.ProviderID, request.ExternalID)
		if index >= 0 {
			existing := state.Groups[index]
			if existing.GroupID != request.GroupID {
				return false, ErrConflict
			}
			if existing.State == protocol.IdentityDeprovisioned {
				if !request.Active && existing.DisplayName == request.DisplayName {
					result = copyGroups([]Group{existing})[0]
					return false, nil
				}
				return false, ErrDeprovisioned
			}
			if err := validateGroupUniqueness(*state, request, existing.ID); err != nil {
				return false, err
			}
			if request.Active && existing.DisplayName == request.DisplayName {
				result = copyGroups([]Group{existing})[0]
				return false, nil
			}
			existing.DisplayName = request.DisplayName
			existing.UpdatedAt = now
			existing.UpdatedRevision = nextRevision
			if !request.Active {
				existing.State = protocol.IdentityDeprovisioned
				existing.MemberUserIDs = []string{}
				appendTombstone(state, TombstoneGroup, existing.ID, existing.ProviderID, existing.ExternalID, now, nextRevision)
			}
			state.Groups[index] = existing
			result = copyGroups([]Group{existing})[0]
			return true, nil
		}
		if err := validateGroupUniqueness(*state, request, ""); err != nil {
			return false, err
		}
		group := Group{
			Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
			ID:         stableResourceID("identity_group_", scope.TenantID, request.ProviderID, request.ExternalID),
			ProviderID: request.ProviderID, ExternalID: request.ExternalID,
			GroupID: request.GroupID, DisplayName: request.DisplayName,
			MemberUserIDs: []string{}, State: protocol.IdentityActive,
			CreatedAt: now, UpdatedAt: now, UpdatedRevision: nextRevision,
		}
		if !request.Active {
			group.State = protocol.IdentityDeprovisioned
			appendTombstone(state, TombstoneGroup, group.ID, group.ProviderID, group.ExternalID, now, nextRevision)
		}
		state.Groups = append(state.Groups, group)
		canonicalizeTenantState(state)
		result = group
		return true, nil
	})
	if err != nil {
		return Group{}, Change{}, err
	}
	if result.ID == "" {
		index := groupIndex(state, request.ProviderID, request.ExternalID)
		if index < 0 {
			return Group{}, Change{}, ErrStoreUnavailable
		}
		result = copyGroups([]Group{state.Groups[index]})[0]
	}
	return result, change, nil
}

func (s *LocalStore) UpsertMembership(
	ctx context.Context,
	scope protocol.TenantScope,
	request MembershipUpsert,
) (Group, Change, error) {
	if err := validateMembershipUpsert(request); err != nil {
		return Group{}, Change{}, err
	}
	var result Group
	state, change, err := s.updateTenant(ctx, scope, RevisionMembershipChanged, func(
		state *tenantState,
		now time.Time,
		nextRevision uint64,
	) (bool, error) {
		groupPosition := groupIndex(*state, request.ProviderID, request.GroupExternalID)
		userPosition := userIndex(*state, request.ProviderID, request.UserExternalID)
		if groupPosition < 0 || userPosition < 0 {
			return false, ErrIdentityUnavailable
		}
		group := state.Groups[groupPosition]
		user := state.Users[userPosition]
		if group.State != protocol.IdentityActive {
			return false, ErrIdentityUnavailable
		}
		memberPosition, member := findString(group.MemberUserIDs, user.ID)
		if request.Active {
			if user.State != protocol.IdentityActive {
				return false, ErrIdentityUnavailable
			}
			if member {
				result = copyGroups([]Group{group})[0]
				return false, nil
			}
			group.MemberUserIDs = append(group.MemberUserIDs, user.ID)
			slices.Sort(group.MemberUserIDs)
		} else {
			if !member {
				result = copyGroups([]Group{group})[0]
				return false, nil
			}
			group.MemberUserIDs = slices.Delete(group.MemberUserIDs, memberPosition, memberPosition+1)
		}
		group.UpdatedAt = now
		group.UpdatedRevision = nextRevision
		state.Groups[groupPosition] = group
		result = copyGroups([]Group{group})[0]
		return true, nil
	})
	if err != nil {
		return Group{}, Change{}, err
	}
	if result.ID == "" {
		position := groupIndex(state, request.ProviderID, request.GroupExternalID)
		if position < 0 {
			return Group{}, Change{}, ErrStoreUnavailable
		}
		result = copyGroups([]Group{state.Groups[position]})[0]
	}
	return result, change, nil
}

func (s *LocalStore) ReplaceGroupMembers(
	ctx context.Context,
	scope protocol.TenantScope,
	request MembershipReplace,
) (Group, Change, error) {
	canonical, err := canonicalMembershipReplace(request)
	if err != nil {
		return Group{}, Change{}, err
	}
	var result Group
	state, change, err := s.updateTenant(ctx, scope, RevisionMembershipChanged, func(
		state *tenantState,
		now time.Time,
		nextRevision uint64,
	) (bool, error) {
		groupPosition := groupIndex(*state, canonical.ProviderID, canonical.GroupExternalID)
		if groupPosition < 0 || state.Groups[groupPosition].State != protocol.IdentityActive {
			return false, ErrIdentityUnavailable
		}
		memberIDs := make([]string, 0, len(canonical.UserExternalIDs))
		for _, externalID := range canonical.UserExternalIDs {
			userPosition := userIndex(*state, canonical.ProviderID, externalID)
			if userPosition < 0 || state.Users[userPosition].State != protocol.IdentityActive {
				return false, ErrIdentityUnavailable
			}
			memberIDs = append(memberIDs, state.Users[userPosition].ID)
		}
		slices.Sort(memberIDs)
		group := state.Groups[groupPosition]
		if slices.Equal(group.MemberUserIDs, memberIDs) {
			result = copyGroups([]Group{group})[0]
			return false, nil
		}
		group.MemberUserIDs = memberIDs
		group.UpdatedAt = now
		group.UpdatedRevision = nextRevision
		state.Groups[groupPosition] = group
		result = copyGroups([]Group{group})[0]
		return true, nil
	})
	if err != nil {
		return Group{}, Change{}, err
	}
	if result.ID == "" {
		position := groupIndex(state, canonical.ProviderID, canonical.GroupExternalID)
		if position < 0 {
			return Group{}, Change{}, ErrStoreUnavailable
		}
		result = copyGroups([]Group{state.Groups[position]})[0]
	}
	return result, change, nil
}

func (s *LocalStore) DeprovisionUser(
	ctx context.Context,
	scope protocol.TenantScope,
	providerID string,
	externalID string,
) (User, Change, error) {
	if validateCanonicalID("provider_id", providerID) != nil || validateCanonicalID("external_id", externalID) != nil {
		return User{}, Change{}, ErrIdentityUnavailable
	}
	var result User
	state, change, err := s.updateTenant(ctx, scope, RevisionDeprovisioned, func(
		state *tenantState,
		now time.Time,
		nextRevision uint64,
	) (bool, error) {
		position := userIndex(*state, providerID, externalID)
		if position < 0 {
			return false, ErrIdentityUnavailable
		}
		user := state.Users[position]
		if user.State == protocol.IdentityDeprovisioned {
			result = user
			return false, nil
		}
		user.State = protocol.IdentityDeprovisioned
		user.UpdatedAt = now
		user.UpdatedRevision = nextRevision
		state.Users[position] = user
		removeUserMemberships(state, user.ID, now, nextRevision)
		appendTombstone(state, TombstoneUser, user.ID, user.ProviderID, user.ExternalID, now, nextRevision)
		result = user
		return true, nil
	})
	if err != nil {
		return User{}, Change{}, err
	}
	if result.ID == "" {
		position := userIndex(state, providerID, externalID)
		if position < 0 {
			return User{}, Change{}, ErrStoreUnavailable
		}
		result = state.Users[position]
	}
	return result, change, nil
}

func (s *LocalStore) DeprovisionGroup(
	ctx context.Context,
	scope protocol.TenantScope,
	providerID string,
	externalID string,
) (Group, Change, error) {
	if validateCanonicalID("provider_id", providerID) != nil || validateCanonicalID("external_id", externalID) != nil {
		return Group{}, Change{}, ErrIdentityUnavailable
	}
	var result Group
	state, change, err := s.updateTenant(ctx, scope, RevisionDeprovisioned, func(
		state *tenantState,
		now time.Time,
		nextRevision uint64,
	) (bool, error) {
		position := groupIndex(*state, providerID, externalID)
		if position < 0 {
			return false, ErrIdentityUnavailable
		}
		group := state.Groups[position]
		if group.State == protocol.IdentityDeprovisioned {
			result = copyGroups([]Group{group})[0]
			return false, nil
		}
		group.State = protocol.IdentityDeprovisioned
		group.MemberUserIDs = []string{}
		group.UpdatedAt = now
		group.UpdatedRevision = nextRevision
		state.Groups[position] = group
		appendTombstone(state, TombstoneGroup, group.ID, group.ProviderID, group.ExternalID, now, nextRevision)
		result = copyGroups([]Group{group})[0]
		return true, nil
	})
	if err != nil {
		return Group{}, Change{}, err
	}
	if result.ID == "" {
		position := groupIndex(state, providerID, externalID)
		if position < 0 {
			return Group{}, Change{}, ErrStoreUnavailable
		}
		result = copyGroups([]Group{state.Groups[position]})[0]
	}
	return result, change, nil
}

func (s *LocalStore) ResolveActiveIdentity(
	ctx context.Context,
	scope protocol.TenantScope,
	providerID string,
	externalSubjectID string,
) (ResolvedIdentity, error) {
	if validateCanonicalID("provider_id", providerID) != nil ||
		validateCanonicalID("external_subject_id", externalSubjectID) != nil {
		return ResolvedIdentity{}, ErrIdentityUnavailable
	}
	state, err := s.readTenant(ctx, scope)
	if err != nil {
		return ResolvedIdentity{}, err
	}
	var user User
	found := false
	for _, candidate := range state.Users {
		if candidate.ProviderID == providerID && candidate.ExternalSubjectID == externalSubjectID {
			user = candidate
			found = true
			break
		}
	}
	if !found || user.State != protocol.IdentityActive {
		return ResolvedIdentity{}, ErrIdentityUnavailable
	}
	groupIDs := make([]string, 0)
	for _, group := range state.Groups {
		if group.State != protocol.IdentityActive || group.ProviderID != providerID {
			continue
		}
		if _, member := findString(group.MemberUserIDs, user.ID); member {
			groupIDs = append(groupIDs, group.GroupID)
		}
	}
	slices.Sort(groupIDs)
	return ResolvedIdentity{
		TenantID: scope.TenantID, ProviderID: providerID, ExternalSubjectID: externalSubjectID,
		PrincipalID: user.PrincipalID, GroupIDs: groupIDs, State: user.State,
		Watermark: currentRevision(state).Watermark,
	}, nil
}

func (s *LocalStore) MembershipProjection(
	ctx context.Context,
	scope protocol.TenantScope,
) (MembershipProjection, error) {
	state, err := s.readTenant(ctx, scope)
	if err != nil {
		return MembershipProjection{}, err
	}
	users := make(map[string]User, len(state.Users))
	for _, user := range state.Users {
		users[user.ID] = user
	}
	members := make([]Membership, 0)
	for _, group := range state.Groups {
		if group.State != protocol.IdentityActive {
			continue
		}
		for _, userID := range group.MemberUserIDs {
			user, ok := users[userID]
			if !ok || user.State != protocol.IdentityActive {
				return MembershipProjection{}, ErrStoreUnavailable
			}
			members = append(members, Membership{
				TenantID: scope.TenantID, PrincipalID: user.PrincipalID, GroupID: group.GroupID,
			})
		}
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].GroupID != members[j].GroupID {
			return members[i].GroupID < members[j].GroupID
		}
		return members[i].PrincipalID < members[j].PrincipalID
	})
	return MembershipProjection{
		Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
		Watermark: currentRevision(state).Watermark, Members: members,
	}, nil
}

func validateUserUpsert(request UserUpsert) error {
	for name, value := range map[string]string{
		"provider_id": request.ProviderID, "external_id": request.ExternalID,
		"external_subject_id": request.ExternalSubjectID,
	} {
		if err := validateCanonicalID(name, value); err != nil {
			return err
		}
	}
	return validateAuthorizationID("principal_id", request.PrincipalID)
}

func (r UserUpsert) Validate() error {
	return validateUserUpsert(r)
}

func validateGroupUpsert(request GroupUpsert) error {
	if err := validateCanonicalID("provider_id", request.ProviderID); err != nil {
		return err
	}
	if err := validateCanonicalID("external_id", request.ExternalID); err != nil {
		return err
	}
	if err := validateAuthorizationID("group_id", request.GroupID); err != nil {
		return err
	}
	return validateDisplayName(request.DisplayName)
}

func (r GroupUpsert) Validate() error {
	return validateGroupUpsert(r)
}

func validateMembershipUpsert(request MembershipUpsert) error {
	for name, value := range map[string]string{
		"provider_id": request.ProviderID, "group_external_id": request.GroupExternalID,
		"user_external_id": request.UserExternalID,
	} {
		if err := validateCanonicalID(name, value); err != nil {
			return err
		}
	}
	return nil
}

func (r MembershipUpsert) Validate() error {
	return validateMembershipUpsert(r)
}

func canonicalMembershipReplace(request MembershipReplace) (MembershipReplace, error) {
	if err := validateCanonicalID("provider_id", request.ProviderID); err != nil {
		return MembershipReplace{}, err
	}
	if err := validateCanonicalID("group_external_id", request.GroupExternalID); err != nil {
		return MembershipReplace{}, err
	}
	request.UserExternalIDs = append([]string(nil), request.UserExternalIDs...)
	for _, externalID := range request.UserExternalIDs {
		if err := validateCanonicalID("user_external_id", externalID); err != nil {
			return MembershipReplace{}, err
		}
	}
	slices.Sort(request.UserExternalIDs)
	request.UserExternalIDs = slices.Compact(request.UserExternalIDs)
	return request, nil
}

func (r MembershipReplace) Validate() error {
	_, err := canonicalMembershipReplace(r)
	return err
}

func validateUserUniqueness(state tenantState, request UserUpsert, ownID string) error {
	for _, user := range state.Users {
		if user.ID == ownID {
			continue
		}
		if user.PrincipalID == request.PrincipalID ||
			user.ProviderID == request.ProviderID && user.ExternalSubjectID == request.ExternalSubjectID {
			return ErrConflict
		}
	}
	return nil
}

func validateGroupUniqueness(state tenantState, request GroupUpsert, ownID string) error {
	for _, group := range state.Groups {
		if group.ID != ownID && group.GroupID == request.GroupID {
			return ErrConflict
		}
	}
	return nil
}

func removeUserMemberships(state *tenantState, userID string, now time.Time, revision uint64) {
	for index, group := range state.Groups {
		position, member := findString(group.MemberUserIDs, userID)
		if !member {
			continue
		}
		group.MemberUserIDs = slices.Delete(group.MemberUserIDs, position, position+1)
		group.UpdatedAt = now
		group.UpdatedRevision = revision
		state.Groups[index] = group
	}
}

func appendTombstone(
	state *tenantState,
	kind TombstoneKind,
	resourceID string,
	providerID string,
	externalID string,
	now time.Time,
	revision uint64,
) {
	state.Tombstones = append(state.Tombstones, Tombstone{
		Version: protocol.EnterpriseContractVersion, TenantID: state.Scope.TenantID,
		Kind: kind, ResourceID: resourceID, ProviderID: providerID, ExternalID: externalID,
		IdentityRevision: revision, DeprovisionedAt: now,
	})
}

func findString(values []string, target string) (int, bool) {
	index, found := slices.BinarySearch(values, target)
	return index, found
}
