package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type identityStateMaterial struct {
	Version    string               `json:"version"`
	Scope      protocol.TenantScope `json:"scope"`
	Providers  []Provider           `json:"providers"`
	Users      []User               `json:"users"`
	Groups     []Group              `json:"groups"`
	Tombstones []Tombstone          `json:"tombstones"`
}

func appendRevision(state *tenantState, reason RevisionReason, committedAt time.Time) error {
	if state == nil {
		return ErrStoreUnavailable
	}
	if err := validateRevisionReason(reason); err != nil {
		return err
	}
	if err := validateUTC("committed_at", committedAt); err != nil {
		return err
	}
	canonicalizeTenantState(state)
	digest, err := tenantStateDigest(*state)
	if err != nil {
		return err
	}
	number := uint64(len(state.Revisions) + 1)
	previous := ""
	if len(state.Revisions) > 0 {
		previous = state.Revisions[len(state.Revisions)-1].Watermark
	}
	revision := TenantRevision{
		Version: protocol.EnterpriseContractVersion, TenantID: state.Scope.TenantID,
		Number: number, PreviousWatermark: previous, StateDigest: digest,
		Reason: reason, CommittedAt: committedAt,
	}
	revision.Watermark = watermarkFor(revision.TenantID, revision.Number, revision.PreviousWatermark, revision.StateDigest)
	state.Revisions = append(state.Revisions, revision)
	return nil
}

func tenantStateDigest(state tenantState) (string, error) {
	material := identityStateMaterial{
		Version: state.Version, Scope: state.Scope,
		Providers: state.Providers, Users: state.Users, Groups: state.Groups, Tombstones: state.Tombstones,
	}
	data, err := json.Marshal(material)
	if err != nil {
		return "", storeFailure("encode identity revision digest", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateRegistry(registry registryState) error {
	if registry.Version != localStoreVersion {
		return ErrStoreUnavailable
	}
	seen := make(map[string]struct{}, len(registry.Tenants))
	for index, tenant := range registry.Tenants {
		if tenant.Version != protocol.EnterpriseContractVersion ||
			validateCanonicalID("tenant_id", tenant.TenantID) != nil ||
			tenant.FileKey != tenantFileKey(tenant.TenantID) ||
			validateUTC("registered_at", tenant.RegisteredAt) != nil {
			return ErrStoreUnavailable
		}
		scope := protocol.TenantScope{
			Version: protocol.EnterpriseContractVersion, TenantID: tenant.TenantID, Region: tenant.Region,
		}
		if scope.Validate() != nil {
			return ErrStoreUnavailable
		}
		if index > 0 && tenant.TenantID <= registry.Tenants[index-1].TenantID {
			return ErrStoreUnavailable
		}
		if _, duplicate := seen[tenant.TenantID]; duplicate {
			return ErrStoreUnavailable
		}
		seen[tenant.TenantID] = struct{}{}
	}
	return nil
}

func validateTenantState(state tenantState) error {
	if state.Version != localStoreVersion || state.Scope.Validate() != nil || len(state.Revisions) == 0 {
		return ErrStoreUnavailable
	}
	providers := make(map[string]Provider, len(state.Providers))
	maxRevision := uint64(len(state.Revisions))
	for index, provider := range state.Providers {
		if provider.Version != protocol.EnterpriseContractVersion || provider.TenantID != state.Scope.TenantID {
			return ErrStoreUnavailable
		}
		if validateProviderSpec(ProviderSpec{
			ProviderID: provider.ProviderID, Issuer: provider.Issuer, Audiences: provider.Audiences,
		}) != nil {
			return ErrStoreUnavailable
		}
		if index > 0 && provider.ProviderID <= state.Providers[index-1].ProviderID {
			return ErrStoreUnavailable
		}
		providers[provider.ProviderID] = provider
	}

	usersByID := make(map[string]User, len(state.Users))
	userSubjects := make(map[string]struct{}, len(state.Users))
	principals := make(map[string]struct{}, len(state.Users))
	for index, user := range state.Users {
		if err := validateUserRecord(state.Scope.TenantID, user, providers, maxRevision); err != nil {
			return ErrStoreUnavailable
		}
		if index > 0 && !userLess(state.Users[index-1], user) {
			return ErrStoreUnavailable
		}
		subjectKey := user.ProviderID + "\x00" + user.ExternalSubjectID
		if _, duplicate := userSubjects[subjectKey]; duplicate {
			return ErrStoreUnavailable
		}
		if _, duplicate := principals[user.PrincipalID]; duplicate {
			return ErrStoreUnavailable
		}
		if _, duplicate := usersByID[user.ID]; duplicate {
			return ErrStoreUnavailable
		}
		userSubjects[subjectKey] = struct{}{}
		principals[user.PrincipalID] = struct{}{}
		usersByID[user.ID] = user
	}

	groupIDs := make(map[string]struct{}, len(state.Groups))
	for index, group := range state.Groups {
		if err := validateGroupRecord(state.Scope.TenantID, group, providers, usersByID, maxRevision); err != nil {
			return ErrStoreUnavailable
		}
		if index > 0 && !groupLess(state.Groups[index-1], group) {
			return ErrStoreUnavailable
		}
		if _, duplicate := groupIDs[group.GroupID]; duplicate {
			return ErrStoreUnavailable
		}
		groupIDs[group.GroupID] = struct{}{}
	}

	tombstones := make(map[string]struct{}, len(state.Tombstones))
	for index, tombstone := range state.Tombstones {
		if err := validateTombstone(state.Scope.TenantID, tombstone, uint64(len(state.Revisions))); err != nil {
			return ErrStoreUnavailable
		}
		if index > 0 && !tombstoneLess(state.Tombstones[index-1], tombstone) {
			return ErrStoreUnavailable
		}
		key := string(tombstone.Kind) + "\x00" + tombstone.ResourceID
		if _, duplicate := tombstones[key]; duplicate {
			return ErrStoreUnavailable
		}
		tombstones[key] = struct{}{}
	}
	for _, user := range state.Users {
		if user.State == protocol.IdentityDeprovisioned {
			if _, ok := tombstones[string(TombstoneUser)+"\x00"+user.ID]; !ok {
				return ErrStoreUnavailable
			}
		}
	}
	for _, group := range state.Groups {
		if group.State == protocol.IdentityDeprovisioned {
			if _, ok := tombstones[string(TombstoneGroup)+"\x00"+group.ID]; !ok {
				return ErrStoreUnavailable
			}
		}
	}

	for index, replay := range state.Replays {
		if validateReplayDigest(replay.Digest) != nil || validateUTC("replay expires_at", replay.ExpiresAt) != nil {
			return ErrStoreUnavailable
		}
		if index > 0 && replay.Digest <= state.Replays[index-1].Digest {
			return ErrStoreUnavailable
		}
	}
	if err := validateRevisionHistory(state); err != nil {
		return err
	}
	return nil
}

func validateUserRecord(tenantID string, user User, providers map[string]Provider, maxRevision uint64) error {
	if user.Version != protocol.EnterpriseContractVersion || user.TenantID != tenantID ||
		validateCanonicalID("user id", user.ID) != nil ||
		validateCanonicalID("provider_id", user.ProviderID) != nil ||
		validateCanonicalID("external_id", user.ExternalID) != nil ||
		validateCanonicalID("external_subject_id", user.ExternalSubjectID) != nil ||
		validateAuthorizationID("principal_id", user.PrincipalID) != nil ||
		validateUTC("created_at", user.CreatedAt) != nil || validateUTC("updated_at", user.UpdatedAt) != nil ||
		user.UpdatedAt.Before(user.CreatedAt) || user.UpdatedRevision == 0 || user.UpdatedRevision > maxRevision {
		return ErrStoreUnavailable
	}
	if _, ok := providers[user.ProviderID]; !ok {
		return ErrStoreUnavailable
	}
	if user.ID != stableResourceID("identity_user_", tenantID, user.ProviderID, user.ExternalID) {
		return ErrStoreUnavailable
	}
	switch user.State {
	case protocol.IdentityActive, protocol.IdentityDeprovisioned:
		return nil
	default:
		return ErrStoreUnavailable
	}
}

func validateGroupRecord(
	tenantID string,
	group Group,
	providers map[string]Provider,
	users map[string]User,
	maxRevision uint64,
) error {
	if group.Version != protocol.EnterpriseContractVersion || group.TenantID != tenantID ||
		validateCanonicalID("group id", group.ID) != nil ||
		validateCanonicalID("provider_id", group.ProviderID) != nil ||
		validateCanonicalID("external_id", group.ExternalID) != nil ||
		validateAuthorizationID("group_id", group.GroupID) != nil ||
		validateDisplayName(group.DisplayName) != nil ||
		validateUTC("created_at", group.CreatedAt) != nil || validateUTC("updated_at", group.UpdatedAt) != nil ||
		group.UpdatedAt.Before(group.CreatedAt) || group.UpdatedRevision == 0 || group.UpdatedRevision > maxRevision {
		return ErrStoreUnavailable
	}
	if _, ok := providers[group.ProviderID]; !ok ||
		group.ID != stableResourceID("identity_group_", tenantID, group.ProviderID, group.ExternalID) {
		return ErrStoreUnavailable
	}
	if group.State != protocol.IdentityActive && group.State != protocol.IdentityDeprovisioned {
		return ErrStoreUnavailable
	}
	if group.State == protocol.IdentityDeprovisioned && len(group.MemberUserIDs) != 0 {
		return ErrStoreUnavailable
	}
	for index, userID := range group.MemberUserIDs {
		if validateCanonicalID("member user id", userID) != nil || index > 0 && userID <= group.MemberUserIDs[index-1] {
			return ErrStoreUnavailable
		}
		user, ok := users[userID]
		if !ok || user.ProviderID != group.ProviderID || user.State != protocol.IdentityActive {
			return ErrStoreUnavailable
		}
	}
	return nil
}

func validateTombstone(tenantID string, tombstone Tombstone, maxRevision uint64) error {
	if tombstone.Version != protocol.EnterpriseContractVersion || tombstone.TenantID != tenantID ||
		validateCanonicalID("resource_id", tombstone.ResourceID) != nil ||
		validateCanonicalID("provider_id", tombstone.ProviderID) != nil ||
		validateCanonicalID("external_id", tombstone.ExternalID) != nil ||
		tombstone.IdentityRevision == 0 || tombstone.IdentityRevision > maxRevision ||
		validateUTC("deprovisioned_at", tombstone.DeprovisionedAt) != nil {
		return ErrStoreUnavailable
	}
	if tombstone.Kind != TombstoneUser && tombstone.Kind != TombstoneGroup {
		return ErrStoreUnavailable
	}
	return nil
}

func validateRevisionHistory(state tenantState) error {
	previous := ""
	var previousCommittedAt time.Time
	for index, revision := range state.Revisions {
		number := uint64(index + 1)
		if revision.Version != protocol.EnterpriseContractVersion || revision.TenantID != state.Scope.TenantID ||
			revision.Number != number || revision.PreviousWatermark != previous ||
			validateCanonicalID("identity watermark", revision.Watermark) != nil ||
			validateDigest("state digest", revision.StateDigest) != nil ||
			validateRevisionReason(revision.Reason) != nil || validateUTC("committed_at", revision.CommittedAt) != nil ||
			revision.Watermark != watermarkFor(revision.TenantID, revision.Number, revision.PreviousWatermark, revision.StateDigest) {
			return ErrStoreUnavailable
		}
		if index == 0 && revision.Reason != RevisionTenantRegistered ||
			index > 0 && (revision.Reason == RevisionTenantRegistered || revision.CommittedAt.Before(previousCommittedAt)) {
			return ErrStoreUnavailable
		}
		previous = revision.Watermark
		previousCommittedAt = revision.CommittedAt
	}
	digest, err := tenantStateDigest(state)
	if err != nil || state.Revisions[len(state.Revisions)-1].StateDigest != digest {
		return ErrStoreUnavailable
	}
	return nil
}

func validateRevisionReason(reason RevisionReason) error {
	switch reason {
	case RevisionTenantRegistered, RevisionProviderChanged, RevisionUserChanged,
		RevisionGroupChanged, RevisionMembershipChanged, RevisionDeprovisioned:
		return nil
	default:
		return ErrStoreUnavailable
	}
}

func validateReplayDigest(digest ReplayDigest) error {
	value := string(digest)
	const prefix = "replay_"
	if len(value) != len(prefix)+sha256.Size*2 || value[:len(prefix)] != prefix {
		return ErrInvalidInput
	}
	if _, err := hex.DecodeString(value[len(prefix):]); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func canonicalizeRegistry(registry *registryState) {
	if registry == nil {
		return
	}
	if registry.Tenants == nil {
		registry.Tenants = []tenantRegistration{}
	}
	sort.Slice(registry.Tenants, func(i, j int) bool {
		return registry.Tenants[i].TenantID < registry.Tenants[j].TenantID
	})
}

func canonicalizeTenantState(state *tenantState) {
	if state == nil {
		return
	}
	state.Providers = nonNilProviders(state.Providers)
	state.Users = nonNilUsers(state.Users)
	state.Groups = nonNilGroups(state.Groups)
	state.Tombstones = nonNilTombstones(state.Tombstones)
	state.Replays = nonNilReplays(state.Replays)
	state.Revisions = nonNilRevisions(state.Revisions)
	for index := range state.Providers {
		state.Providers[index].Audiences = append([]string(nil), state.Providers[index].Audiences...)
		slices.Sort(state.Providers[index].Audiences)
	}
	for index := range state.Groups {
		state.Groups[index].MemberUserIDs = append([]string(nil), state.Groups[index].MemberUserIDs...)
		slices.Sort(state.Groups[index].MemberUserIDs)
		state.Groups[index].MemberUserIDs = slices.Compact(state.Groups[index].MemberUserIDs)
	}
	sort.Slice(state.Providers, func(i, j int) bool { return state.Providers[i].ProviderID < state.Providers[j].ProviderID })
	sort.Slice(state.Users, func(i, j int) bool { return userLess(state.Users[i], state.Users[j]) })
	sort.Slice(state.Groups, func(i, j int) bool { return groupLess(state.Groups[i], state.Groups[j]) })
	sort.Slice(state.Tombstones, func(i, j int) bool { return tombstoneLess(state.Tombstones[i], state.Tombstones[j]) })
	sort.Slice(state.Replays, func(i, j int) bool { return state.Replays[i].Digest < state.Replays[j].Digest })
}

func userLess(left, right User) bool {
	if left.ProviderID != right.ProviderID {
		return left.ProviderID < right.ProviderID
	}
	return left.ExternalID < right.ExternalID
}

func groupLess(left, right Group) bool {
	if left.ProviderID != right.ProviderID {
		return left.ProviderID < right.ProviderID
	}
	return left.ExternalID < right.ExternalID
}

func tombstoneLess(left, right Tombstone) bool {
	if left.IdentityRevision != right.IdentityRevision {
		return left.IdentityRevision < right.IdentityRevision
	}
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return left.ResourceID < right.ResourceID
}

func registrationIndex(registry registryState, tenantID string) int {
	index := sort.Search(len(registry.Tenants), func(index int) bool {
		return registry.Tenants[index].TenantID >= tenantID
	})
	if index == len(registry.Tenants) || registry.Tenants[index].TenantID != tenantID {
		return -1
	}
	return index
}

func providerIndex(state tenantState, providerID string) int {
	index := sort.Search(len(state.Providers), func(index int) bool {
		return state.Providers[index].ProviderID >= providerID
	})
	if index == len(state.Providers) || state.Providers[index].ProviderID != providerID {
		return -1
	}
	return index
}

func userIndex(state tenantState, providerID, externalID string) int {
	index := sort.Search(len(state.Users), func(index int) bool {
		candidate := state.Users[index]
		return candidate.ProviderID > providerID || candidate.ProviderID == providerID && candidate.ExternalID >= externalID
	})
	if index == len(state.Users) || state.Users[index].ProviderID != providerID || state.Users[index].ExternalID != externalID {
		return -1
	}
	return index
}

func groupIndex(state tenantState, providerID, externalID string) int {
	index := sort.Search(len(state.Groups), func(index int) bool {
		candidate := state.Groups[index]
		return candidate.ProviderID > providerID || candidate.ProviderID == providerID && candidate.ExternalID >= externalID
	})
	if index == len(state.Groups) || state.Groups[index].ProviderID != providerID || state.Groups[index].ExternalID != externalID {
		return -1
	}
	return index
}

func currentRevision(state tenantState) TenantRevision {
	if len(state.Revisions) == 0 {
		return TenantRevision{}
	}
	return state.Revisions[len(state.Revisions)-1]
}

func snapshotFromState(state tenantState) TenantSnapshot {
	return TenantSnapshot{
		Scope:     state.Scope,
		Providers: copyProviders(state.Providers), Users: copyUsers(state.Users), Groups: copyGroups(state.Groups),
		Tombstones: append([]Tombstone(nil), state.Tombstones...), Revision: currentRevision(state),
	}
}

func copyProvider(provider Provider) Provider {
	provider.Audiences = append([]string(nil), provider.Audiences...)
	return provider
}

func copyProviders(providers []Provider) []Provider {
	result := make([]Provider, len(providers))
	for index, provider := range providers {
		result[index] = copyProvider(provider)
	}
	return result
}

func copyUsers(users []User) []User { return append([]User(nil), users...) }

func copyGroups(groups []Group) []Group {
	result := make([]Group, len(groups))
	for index, group := range groups {
		group.MemberUserIDs = append([]string(nil), group.MemberUserIDs...)
		result[index] = group
	}
	return result
}

func nonNilProviders(values []Provider) []Provider {
	if values == nil {
		return []Provider{}
	}
	return values
}

func nonNilUsers(values []User) []User {
	if values == nil {
		return []User{}
	}
	return values
}

func nonNilGroups(values []Group) []Group {
	if values == nil {
		return []Group{}
	}
	return values
}

func nonNilTombstones(values []Tombstone) []Tombstone {
	if values == nil {
		return []Tombstone{}
	}
	return values
}

func nonNilReplays(values []replayRecord) []replayRecord {
	if values == nil {
		return []replayRecord{}
	}
	return values
}

func nonNilRevisions(values []TenantRevision) []TenantRevision {
	if values == nil {
		return []TenantRevision{}
	}
	return values
}
