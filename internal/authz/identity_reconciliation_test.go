package authz

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/protocol"
)

const identityPublicationStoreID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

type memoryIdentityBackend struct {
	mu        sync.Mutex
	claimed   bool
	tenantIDs []string
	fence     *identity.MembershipPublicationFence
	members   map[identity.Membership]struct{}
	requests  []identity.MembershipWriteRequest
}

func newMemoryIdentityBackend() *memoryIdentityBackend {
	return &memoryIdentityBackend{members: make(map[identity.Membership]struct{})}
}

func (b *memoryIdentityBackend) InspectMembershipState(
	_ context.Context,
	_ identity.MembershipPublicationTarget,
) (identity.MembershipRemoteState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	members := make([]identity.Membership, 0, len(b.members))
	for member := range b.members {
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].GroupID != members[j].GroupID {
			return members[i].GroupID < members[j].GroupID
		}
		return members[i].PrincipalID < members[j].PrincipalID
	})
	state := identity.MembershipRemoteState{
		Claimed: b.claimed, TenantIDs: slices.Clone(b.tenantIDs), Members: members,
	}
	if b.fence != nil {
		fence := *b.fence
		state.PublicationFence = &fence
	}
	return state, nil
}

func (b *memoryIdentityBackend) ClaimMembershipStore(
	_ context.Context,
	target identity.MembershipPublicationTarget,
	fence identity.MembershipPublicationFence,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.claimed {
		return errors.New("duplicate remote claim")
	}
	b.claimed = true
	b.tenantIDs = []string{target.TenantID}
	b.fence = &fence
	return nil
}

func (b *memoryIdentityBackend) ApplyMembershipChanges(
	_ context.Context,
	request identity.MembershipWriteRequest,
) error {
	if err := request.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fence == nil || *b.fence != request.ExpectedFence {
		return errors.New("remote publication fence changed")
	}
	request.Writes = slices.Clone(request.Writes)
	request.Deletes = slices.Clone(request.Deletes)
	b.requests = append(b.requests, request)
	for _, member := range request.Deletes {
		delete(b.members, member)
	}
	for _, member := range request.Writes {
		b.members[member] = struct{}{}
	}
	b.fence = &identity.MembershipPublicationFence{
		State: identity.MembershipPublicationFencePublished, IdentityWatermark: request.IdentityWatermark,
		ProjectionDigest: request.ProjectionDigest,
	}
	return nil
}

func (b *memoryIdentityBackend) tupleSnapshot() []Tuple {
	b.mu.Lock()
	defer b.mu.Unlock()
	members := make([]identity.Membership, 0, len(b.members))
	for member := range b.members {
		members = append(members, member)
	}
	tuples := identityMembershipTuples(members)
	sort.Slice(tuples, func(i, j int) bool { return tupleLess(tuples[i], tuples[j]) })
	return tuples
}

func TestIdentityMembershipPublisherAddsAndRevokesGroupAuthorization(t *testing.T) {
	ctx := context.Background()
	store, err := identity.OpenLocalStore(filepath.Join(t.TempDir(), "identity-store"))
	if err != nil {
		t.Fatal(err)
	}
	scope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: "tenant-authz-publication", Region: "cn-east",
	}
	if _, err := store.RegisterTenant(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertProvider(ctx, scope, identity.ProviderSpec{
		ProviderID: "provider-main", Issuer: "https://identity.example.test", Audiences: []string{"knote-cli"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertUser(ctx, scope, identity.UserUpsert{
		ProviderID: "provider-main", ExternalID: "user-alice", ExternalSubjectID: "subject-alice",
		PrincipalID: "alice", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertGroup(ctx, scope, identity.GroupUpsert{
		ProviderID: "provider-main", ExternalID: "group-engineering", GroupID: "engineering",
		DisplayName: "Engineering", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMembership(ctx, scope, identity.MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-engineering",
		UserExternalID: "user-alice", Active: true,
	}); err != nil {
		t.Fatal(err)
	}

	backend := newMemoryIdentityBackend()
	publisher, err := NewIdentityMembershipPublisher(
		store, backend, scope.TenantID, identityPublicationStoreID, localTestModelID,
	)
	if err != nil {
		t.Fatal(err)
	}
	added, err := publisher.PublishLatest(ctx)
	if err != nil || added.MemberCount != 1 {
		t.Fatalf("publish membership = %+v, %v", added, err)
	}
	exactMembership := Tuple{User: "user:alice", Relation: RelationMember, Object: "group:engineering"}
	tuples := backend.tupleSnapshot()
	if len(tuples) != 1 || tuples[0] != exactMembership {
		t.Fatalf("published tuples = %+v", tuples)
	}
	assertPublishedGroupDecision(t, tuples, true)

	if _, change, err := store.UpsertMembership(ctx, scope, identity.MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-engineering",
		UserExternalID: "user-alice", Active: false,
	}); err != nil || !change.Changed {
		t.Fatalf("remove membership = %+v, %v", change, err)
	}
	removed, err := publisher.PublishLatest(ctx)
	if err != nil || removed.MemberCount != 0 || removed.IdentityWatermark == added.IdentityWatermark {
		t.Fatalf("publish removal = %+v, %v", removed, err)
	}
	tuples = backend.tupleSnapshot()
	if len(tuples) != 0 {
		t.Fatalf("removal tuples = %+v", tuples)
	}
	assertPublishedGroupDecision(t, tuples, false)
}

func TestIdentityMembershipPublisherDelegatesExactTarget(t *testing.T) {
	want := identity.MembershipPublicationTarget{
		TenantID: "tenant-bound", StoreID: identityPublicationStoreID, AuthorizationModelID: localTestModelID,
	}
	backend := newMemoryIdentityBackend()
	store := identityMembershipStoreFunc(func(
		ctx context.Context,
		target identity.MembershipPublicationTarget,
		publicationBackend identity.MembershipPublicationBackend,
	) (identity.MembershipPublicationReceipt, error) {
		if target != want || publicationBackend != backend {
			return identity.MembershipPublicationReceipt{}, identity.ErrPublicationTargetMismatch
		}
		return identity.MembershipPublicationReceipt{TenantID: target.TenantID}, nil
	})
	publisher, err := NewIdentityMembershipPublisher(
		store, backend, want.TenantID, want.StoreID, want.AuthorizationModelID,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := publisher.PublishLatest(context.Background())
	if err != nil || receipt.TenantID != want.TenantID {
		t.Fatalf("delegated publication = %+v, %v", receipt, err)
	}
}

type identityMembershipStoreFunc func(
	context.Context,
	identity.MembershipPublicationTarget,
	identity.MembershipPublicationBackend,
) (identity.MembershipPublicationReceipt, error)

func (f identityMembershipStoreFunc) PublishMembershipProjection(
	ctx context.Context,
	target identity.MembershipPublicationTarget,
	backend identity.MembershipPublicationBackend,
) (identity.MembershipPublicationReceipt, error) {
	return f(ctx, target, backend)
}

func assertPublishedGroupDecision(t *testing.T, membershipTuples []Tuple, want bool) {
	t.Helper()
	tuples := append(slices.Clone(membershipTuples),
		Tuple{User: "group:engineering#member", Relation: RelationMember, Object: "organization:acme"},
		Tuple{User: "organization:acme", Relation: RelationOrganization, Object: "knowledge_base:handbook"},
		Tuple{User: "group:engineering#member", Relation: RelationViewer, Object: "knowledge_base:handbook"},
	)
	authorizer, err := NewLocalAuthorizer(localTestModelID, tuples)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User: "user:alice", Relation: RelationCanView, Object: "knowledge_base:handbook",
		AuthorizationModelID: localTestModelID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed != want {
		t.Fatalf("group authorization allowed=%t, want %t", decision.Allowed, want)
	}
}
