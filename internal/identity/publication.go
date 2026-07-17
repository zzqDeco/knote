package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	publicationDirectory      = "publications"
	publicationStateVersion   = "v1"
	maxPublicationConvergence = 8
)

type membershipPublicationState struct {
	Version   string                         `json:"version"`
	TenantID  string                         `json:"tenant_id"`
	StoreID   string                         `json:"store_id"`
	Published *membershipPublicationSnapshot `json:"published,omitempty"`
	Pending   *membershipPublicationIntent   `json:"pending,omitempty"`
}

type membershipPublicationSnapshot struct {
	AuthorizationModelID string       `json:"authorization_model_id"`
	IdentityWatermark    string       `json:"identity_watermark"`
	ProjectionDigest     string       `json:"projection_digest"`
	Members              []Membership `json:"members"`
	PublishedAt          time.Time    `json:"published_at"`
}

type membershipPublicationIntent struct {
	AuthorizationModelID string       `json:"authorization_model_id"`
	IdentityWatermark    string       `json:"identity_watermark"`
	CandidateDigest      string       `json:"candidate_digest"`
	Candidates           []Membership `json:"candidates"`
	PreparedAt           time.Time    `json:"prepared_at"`
}

var membershipPublicationLocks sync.Map

// PublishMembershipProjection converges the bound OpenFGA store to the latest
// canonical tenant projection. The durable intent makes an uncertain external
// write safe to retry after a crash.
func (s *LocalStore) PublishMembershipProjection(
	ctx context.Context,
	target MembershipPublicationTarget,
	backend MembershipPublicationBackend,
) (MembershipPublicationReceipt, error) {
	if s == nil || s.clock == nil || ctx == nil || backend == nil {
		return MembershipPublicationReceipt{}, ErrPublicationUnavailable
	}
	if err := target.Validate(); err != nil {
		return MembershipPublicationReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return MembershipPublicationReceipt{}, err
	}
	release, err := s.acquirePublicationLock(ctx, target.StoreID)
	if err != nil {
		return MembershipPublicationReceipt{}, publicationFailure(err)
	}
	defer release()

	state, err := s.loadPublicationState(target)
	if err != nil {
		return MembershipPublicationReceipt{}, err
	}
	for range maxPublicationConvergence {
		projection, err := s.latestMembershipProjection(ctx, target.TenantID)
		if err != nil {
			return MembershipPublicationReceipt{}, publicationFailure(err)
		}
		if err := rejectPublicationRollback(state, projection.Watermark); err != nil {
			return MembershipPublicationReceipt{}, err
		}
		remote, err := inspectBoundMembershipState(ctx, target, backend)
		if err != nil {
			return MembershipPublicationReceipt{}, err
		}
		if state.Pending == nil && publishedProjectionMatches(state.Published, target, projection) &&
			slices.Equal(remote.Members, projection.Members) {
			return publicationReceipt(state.Published, target), nil
		}

		known := canonicalMembershipUnion(
			remote.Members,
			projection.Members,
		)
		now, err := s.now()
		if err != nil {
			return MembershipPublicationReceipt{}, publicationFailure(err)
		}
		state.Pending = &membershipPublicationIntent{
			AuthorizationModelID: target.AuthorizationModelID,
			IdentityWatermark:    projection.Watermark,
			CandidateDigest:      membershipProjectionDigest(target.TenantID, known),
			Candidates:           slices.Clone(known),
			PreparedAt:           now,
		}
		if err := s.writePublicationState(target, state); err != nil {
			return MembershipPublicationReceipt{}, err
		}

		request := MembershipWriteRequest{
			Target: target, IdentityWatermark: projection.Watermark,
			Writes:  membershipDifference(projection.Members, remote.Members),
			Deletes: membershipDifference(remote.Members, projection.Members),
		}
		if err := request.Validate(); err != nil {
			return MembershipPublicationReceipt{}, ErrPublicationUnavailable
		}
		if err := backend.ApplyMembershipChanges(ctx, request); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return MembershipPublicationReceipt{}, ctxErr
			}
			return MembershipPublicationReceipt{}, ErrPublicationUnavailable
		}

		current, err := s.latestMembershipProjection(ctx, target.TenantID)
		if err != nil {
			return MembershipPublicationReceipt{}, publicationFailure(err)
		}
		if current.Watermark != projection.Watermark || !slices.Equal(current.Members, projection.Members) {
			continue
		}
		remote, err = backend.InspectMembershipState(ctx, target)
		if err != nil {
			return MembershipPublicationReceipt{}, publicationFailure(err)
		}
		if err := requireExpectedRemoteBinding(target, remote); err != nil {
			return MembershipPublicationReceipt{}, err
		}
		if !slices.Equal(remote.Members, projection.Members) {
			continue
		}
		publishedAt, err := s.now()
		if err != nil {
			return MembershipPublicationReceipt{}, publicationFailure(err)
		}
		state.Published = &membershipPublicationSnapshot{
			AuthorizationModelID: target.AuthorizationModelID,
			IdentityWatermark:    projection.Watermark,
			ProjectionDigest:     membershipProjectionDigest(target.TenantID, projection.Members),
			Members:              slices.Clone(projection.Members),
			PublishedAt:          publishedAt,
		}
		state.Pending = nil
		if err := s.writePublicationState(target, state); err != nil {
			return MembershipPublicationReceipt{}, err
		}
		return publicationReceipt(state.Published, target), nil
	}
	return MembershipPublicationReceipt{}, ErrPublicationUnavailable
}

func inspectBoundMembershipState(
	ctx context.Context,
	target MembershipPublicationTarget,
	backend MembershipPublicationBackend,
) (MembershipRemoteState, error) {
	remote, err := backend.InspectMembershipState(ctx, target)
	if err != nil {
		return MembershipRemoteState{}, publicationFailure(err)
	}
	if len(remote.TenantIDs) == 1 && remote.TenantIDs[0] != target.TenantID {
		return MembershipRemoteState{}, ErrPublicationTargetMismatch
	}
	if err := remote.Validate(target); err != nil {
		return MembershipRemoteState{}, publicationFailure(err)
	}
	if !remote.Claimed && len(remote.TenantIDs) == 0 {
		if len(remote.Members) != 0 {
			return MembershipRemoteState{}, ErrPublicationUnavailable
		}
		// A duplicate fixed claim tuple is expected when another publisher won
		// the race. The authoritative reread below decides the outcome.
		_ = backend.ClaimMembershipStore(ctx, target)
		if err := ctx.Err(); err != nil {
			return MembershipRemoteState{}, err
		}
		remote, err = backend.InspectMembershipState(ctx, target)
		if err != nil {
			return MembershipRemoteState{}, publicationFailure(err)
		}
	}
	if err := requireExpectedRemoteBinding(target, remote); err != nil {
		return MembershipRemoteState{}, err
	}
	return remote, nil
}

func requireExpectedRemoteBinding(target MembershipPublicationTarget, remote MembershipRemoteState) error {
	if len(remote.TenantIDs) == 1 && remote.TenantIDs[0] != target.TenantID {
		return ErrPublicationTargetMismatch
	}
	if err := remote.Validate(target); err != nil {
		return publicationFailure(err)
	}
	if !remote.Claimed || len(remote.TenantIDs) != 1 || remote.TenantIDs[0] != target.TenantID {
		return ErrPublicationUnavailable
	}
	return nil
}

func (s *LocalStore) latestMembershipProjection(ctx context.Context, tenantID string) (MembershipProjection, error) {
	scope, err := s.Tenant(ctx, tenantID)
	if err != nil {
		return MembershipProjection{}, err
	}
	projection, err := s.MembershipProjection(ctx, scope)
	if err != nil {
		return MembershipProjection{}, err
	}
	if err := projection.Validate(); err != nil {
		return MembershipProjection{}, ErrStoreUnavailable
	}
	return projection, nil
}

func (s *LocalStore) acquirePublicationLock(ctx context.Context, storeID string) (func(), error) {
	if s == nil || s.root == "" || ctx == nil {
		return nil, ErrPublicationUnavailable
	}
	directory := filepath.Join(s.root, publicationDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(directory, publicationFileKey(storeID)+".lock")
	value, _ := membershipPublicationLocks.LoadOrStore(lockPath, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	if err := ctx.Err(); err != nil {
		lock.Unlock()
		return nil, err
	}
	releaseProcess, err := newProcessLockAt(lockPath).acquire(ctx)
	if err != nil {
		lock.Unlock()
		return nil, err
	}
	return func() {
		releaseProcess()
		lock.Unlock()
	}, nil
}

func (s *LocalStore) loadPublicationState(target MembershipPublicationTarget) (membershipPublicationState, error) {
	path := s.publicationStatePath(target.StoreID)
	var state membershipPublicationState
	err := readStrictJSON(path, &state)
	if errors.Is(err, os.ErrNotExist) {
		return membershipPublicationState{
			Version: publicationStateVersion, TenantID: target.TenantID, StoreID: target.StoreID,
		}, nil
	}
	if err != nil {
		return membershipPublicationState{}, publicationFailure(err)
	}
	if state.TenantID != target.TenantID || state.StoreID != target.StoreID {
		return membershipPublicationState{}, ErrPublicationTargetMismatch
	}
	if err := validateMembershipPublicationState(state); err != nil {
		return membershipPublicationState{}, err
	}
	return state, nil
}

func (s *LocalStore) writePublicationState(
	target MembershipPublicationTarget,
	state membershipPublicationState,
) error {
	if state.TenantID != target.TenantID || state.StoreID != target.StoreID {
		return ErrPublicationTargetMismatch
	}
	if err := validateMembershipPublicationState(state); err != nil {
		return err
	}
	if err := atomicWriteJSON(s.publicationStatePath(target.StoreID), state); err != nil {
		return publicationFailure(err)
	}
	return nil
}

func (s *LocalStore) publicationStatePath(storeID string) string {
	return filepath.Join(s.root, publicationDirectory, publicationFileKey(storeID)+".json")
}

func publicationFileKey(storeID string) string {
	digest := sha256.Sum256([]byte(storeID))
	return hex.EncodeToString(digest[:])
}

func validateMembershipPublicationState(state membershipPublicationState) error {
	if state.Version != publicationStateVersion || validateCanonicalID("tenant_id", state.TenantID) != nil ||
		validateCanonicalID("store_id", state.StoreID) != nil {
		return ErrPublicationUnavailable
	}
	if state.Published != nil {
		published := state.Published
		if validateCanonicalID("authorization_model_id", published.AuthorizationModelID) != nil ||
			validateCanonicalID("identity_watermark", published.IdentityWatermark) != nil ||
			validateUTC("published_at", published.PublishedAt) != nil ||
			validatePublicationMembers(state.TenantID, published.Members) != nil ||
			published.ProjectionDigest != membershipProjectionDigest(state.TenantID, published.Members) {
			return ErrPublicationUnavailable
		}
	}
	if state.Pending != nil {
		pending := state.Pending
		if validateCanonicalID("authorization_model_id", pending.AuthorizationModelID) != nil ||
			validateCanonicalID("identity_watermark", pending.IdentityWatermark) != nil ||
			validateUTC("prepared_at", pending.PreparedAt) != nil ||
			validatePublicationMembers(state.TenantID, pending.Candidates) != nil ||
			pending.CandidateDigest != membershipProjectionDigest(state.TenantID, pending.Candidates) {
			return ErrPublicationUnavailable
		}
	}
	return nil
}

func validatePublicationMembers(tenantID string, members []Membership) error {
	for index, member := range members {
		if member.TenantID != tenantID || validateAuthorizationID("principal_id", member.PrincipalID) != nil ||
			validateAuthorizationID("group_id", member.GroupID) != nil {
			return ErrPublicationUnavailable
		}
		if index > 0 && !membershipLess(members[index-1], member) {
			return ErrPublicationUnavailable
		}
	}
	return nil
}

func publishedProjectionMatches(
	published *membershipPublicationSnapshot,
	target MembershipPublicationTarget,
	projection MembershipProjection,
) bool {
	return published != nil && published.AuthorizationModelID == target.AuthorizationModelID &&
		published.IdentityWatermark == projection.Watermark &&
		published.ProjectionDigest == membershipProjectionDigest(target.TenantID, projection.Members) &&
		slices.Equal(published.Members, projection.Members)
}

func publicationReceipt(
	published *membershipPublicationSnapshot,
	target MembershipPublicationTarget,
) MembershipPublicationReceipt {
	if published == nil {
		return MembershipPublicationReceipt{}
	}
	return MembershipPublicationReceipt{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: target.TenantID, StoreID: target.StoreID,
		AuthorizationModelID: target.AuthorizationModelID,
		IdentityWatermark:    published.IdentityWatermark,
		ProjectionDigest:     published.ProjectionDigest,
		MemberCount:          len(published.Members), PublishedAt: published.PublishedAt,
	}
}

func rejectPublicationRollback(state membershipPublicationState, watermark string) error {
	desired, err := identityWatermarkRevision(watermark)
	if err != nil {
		return ErrPublicationUnavailable
	}
	for _, existing := range []string{
		publishedWatermark(state.Published), pendingWatermark(state.Pending),
	} {
		if existing == "" {
			continue
		}
		revision, err := identityWatermarkRevision(existing)
		if err != nil || revision > desired || revision == desired && existing != watermark {
			return ErrPublicationUnavailable
		}
	}
	return nil
}

func identityWatermarkRevision(watermark string) (uint64, error) {
	parts := strings.Split(watermark, "_")
	if len(parts) != 3 || parts[0] != "identity" || len(parts[1]) != 20 || len(parts[2]) != 32 {
		return 0, ErrPublicationUnavailable
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return 0, ErrPublicationUnavailable
	}
	revision, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || revision == 0 {
		return 0, ErrPublicationUnavailable
	}
	return revision, nil
}

func membershipProjectionDigest(tenantID string, members []Membership) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(tenantID))
	for _, member := range members {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(member.PrincipalID))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(member.GroupID))
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func canonicalMembershipUnion(groups ...[]Membership) []Membership {
	unique := make(map[Membership]struct{})
	for _, group := range groups {
		for _, member := range group {
			unique[member] = struct{}{}
		}
	}
	result := make([]Membership, 0, len(unique))
	for member := range unique {
		result = append(result, member)
	}
	sort.Slice(result, func(i, j int) bool { return membershipLess(result[i], result[j]) })
	return result
}

func membershipDifference(known, desired []Membership) []Membership {
	desiredSet := make(map[Membership]struct{}, len(desired))
	for _, member := range desired {
		desiredSet[member] = struct{}{}
	}
	result := make([]Membership, 0, len(known))
	for _, member := range known {
		if _, retained := desiredSet[member]; !retained {
			result = append(result, member)
		}
	}
	return result
}

func membershipLess(left, right Membership) bool {
	if left.GroupID != right.GroupID {
		return left.GroupID < right.GroupID
	}
	return left.PrincipalID < right.PrincipalID
}

func publishedWatermark(published *membershipPublicationSnapshot) string {
	if published == nil {
		return ""
	}
	return published.IdentityWatermark
}

func pendingWatermark(pending *membershipPublicationIntent) string {
	if pending == nil {
		return ""
	}
	return pending.IdentityWatermark
}

func publicationFailure(error) error {
	return fmt.Errorf("%w", ErrPublicationUnavailable)
}
