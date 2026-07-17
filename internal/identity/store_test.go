package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestLocalStoreSCIMIsIdempotentAndTenantScoped(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 1, 0, 0, 0, time.UTC))
	store := openTestStore(t, t.TempDir(), clock)
	tenantA := testScope("tenant-a")
	tenantB := testScope("tenant-b")

	registered, err := store.RegisterTenant(ctx, tenantA)
	if err != nil || !registered.Changed || registered.Revision.Number != 1 {
		t.Fatalf("register tenant A = %+v, %v", registered, err)
	}
	repeated, err := store.RegisterTenant(ctx, tenantA)
	if err != nil || repeated.Changed || repeated.Revision != registered.Revision {
		t.Fatalf("repeat tenant registration = %+v, %v", repeated, err)
	}
	conflictingScope := tenantA
	conflictingScope.Region = "us-west"
	if _, err := store.RegisterTenant(ctx, conflictingScope); !errors.Is(err, ErrConflict) {
		t.Fatalf("tenant region conflict = %v", err)
	}
	if _, err := store.RegisterTenant(ctx, tenantB); err != nil {
		t.Fatal(err)
	}

	providerRequest := testProvider()
	providerRequest.Audiences = []string{"knote-web", "knote-cli", "knote-cli"}
	providerA, providerChange, err := store.UpsertProvider(ctx, tenantA, providerRequest)
	if err != nil || !providerChange.Changed || !slices.Equal(providerA.Audiences, []string{"knote-cli", "knote-web"}) {
		t.Fatalf("provider upsert = %+v, %+v, %v", providerA, providerChange, err)
	}
	if _, change, err := store.UpsertProvider(ctx, tenantA, providerRequest); err != nil || change.Changed {
		t.Fatalf("provider replay changed state: %+v, %v", change, err)
	}
	if _, _, err := store.UpsertProvider(ctx, tenantB, providerRequest); err != nil {
		t.Fatal(err)
	}

	userRequest := UserUpsert{
		ProviderID: "provider-main", ExternalID: "scim-user-1",
		ExternalSubjectID: "subject-shared", PrincipalID: "alice", Active: true,
	}
	userA, userChangeA, err := store.UpsertUser(ctx, tenantA, userRequest)
	if err != nil || !userChangeA.Changed {
		t.Fatalf("tenant A user = %+v, %+v, %v", userA, userChangeA, err)
	}
	userB, _, err := store.UpsertUser(ctx, tenantB, userRequest)
	if err != nil {
		t.Fatal(err)
	}
	if userA.ID == userB.ID || userA.TenantID == userB.TenantID {
		t.Fatalf("same external identity collided across tenants: A=%+v B=%+v", userA, userB)
	}
	if _, _, err := store.UpsertUser(ctx, tenantB, UserUpsert{
		ProviderID: "provider-main", ExternalID: "only-in-b",
		ExternalSubjectID: "subject-only-in-b", PrincipalID: "principal-only-in-b", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, change, err := store.UpsertUser(ctx, tenantA, userRequest); err != nil || change.Changed ||
		change.Revision != userChangeA.Revision {
		t.Fatalf("user replay changed state: %+v, %v", change, err)
	}

	groupRequest := GroupUpsert{
		ProviderID: "provider-main", ExternalID: "scim-group-1",
		GroupID: "engineering", DisplayName: "Engineering", Active: true,
	}
	if _, _, err := store.UpsertGroup(ctx, tenantA, groupRequest); err != nil {
		t.Fatal(err)
	}
	membership := MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "scim-group-1",
		UserExternalID: "scim-user-1", Active: true,
	}
	group, membershipChange, err := store.UpsertMembership(ctx, tenantA, membership)
	if err != nil || !membershipChange.Changed || !slices.Equal(group.MemberUserIDs, []string{userA.ID}) {
		t.Fatalf("membership upsert = %+v, %+v, %v", group, membershipChange, err)
	}
	if _, change, err := store.UpsertMembership(ctx, tenantA, membership); err != nil || change.Changed {
		t.Fatalf("membership replay changed state: %+v, %v", change, err)
	}
	if _, change, err := store.ReplaceGroupMembers(ctx, tenantA, MembershipReplace{
		ProviderID: "provider-main", GroupExternalID: "scim-group-1",
		UserExternalIDs: []string{"scim-user-1", "scim-user-1"},
	}); err != nil || change.Changed {
		t.Fatalf("canonical membership replacement changed state: %+v, %v", change, err)
	}

	resolvedA, err := store.ResolveActiveIdentity(ctx, tenantA, "provider-main", "subject-shared")
	if err != nil || !slices.Equal(resolvedA.GroupIDs, []string{"engineering"}) {
		t.Fatalf("resolved tenant A identity = %+v, %v", resolvedA, err)
	}
	resolvedB, err := store.ResolveActiveIdentity(ctx, tenantB, "provider-main", "subject-shared")
	if err != nil || resolvedB.TenantID != tenantB.TenantID || resolvedB.Watermark == resolvedA.Watermark {
		t.Fatalf("resolved tenant B identity = %+v, %v", resolvedB, err)
	}
	_, missingErr := store.ResolveActiveIdentity(ctx, tenantA, "provider-main", "subject-only-in-b")
	if _, err := store.ResolveActiveIdentity(ctx, tenantB, "provider-main", "subject-only-in-b"); err != nil {
		t.Fatalf("tenant-local identity lookup failed: %v", err)
	}
	_, crossTenantErr := store.Provider(ctx, protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: tenantB.TenantID, Region: tenantA.Region,
	}, "missing-provider")
	if !errors.Is(missingErr, ErrIdentityUnavailable) || !errors.Is(crossTenantErr, ErrIdentityUnavailable) ||
		missingErr.Error() != crossTenantErr.Error() {
		t.Fatalf("non-disclosing failures differ: missing=%v cross-tenant=%v", missingErr, crossTenantErr)
	}

	beforeDeprovision := membershipChange.Revision
	deprovisioned, deprovisionChange, err := store.DeprovisionUser(ctx, tenantA, "provider-main", "scim-user-1")
	if err != nil || !deprovisionChange.Changed || deprovisioned.State != protocol.IdentityDeprovisioned ||
		deprovisionChange.Revision.Number <= beforeDeprovision.Number ||
		deprovisionChange.Revision.Watermark <= beforeDeprovision.Watermark {
		t.Fatalf("deprovision = %+v, %+v, %v", deprovisioned, deprovisionChange, err)
	}
	if _, err := store.ResolveActiveIdentity(ctx, tenantA, "provider-main", "subject-shared"); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("deprovisioned identity resolved: %v", err)
	}
	projection, err := store.MembershipProjection(ctx, tenantA)
	if err != nil || len(projection.Members) != 0 || projection.Watermark != deprovisionChange.Revision.Watermark {
		t.Fatalf("post-deprovision projection = %+v, %v", projection, err)
	}
	if _, change, err := store.DeprovisionUser(ctx, tenantA, "provider-main", "scim-user-1"); err != nil || change.Changed || change.Revision != deprovisionChange.Revision {
		t.Fatalf("deprovision replay changed state: %+v, %v", change, err)
	}
	if _, _, err := store.UpsertUser(ctx, tenantA, userRequest); !errors.Is(err, ErrDeprovisioned) {
		t.Fatalf("tombstoned user was reactivated: %v", err)
	}
	snapshot, err := store.Snapshot(ctx, tenantA)
	if err != nil || len(snapshot.Tombstones) != 1 || snapshot.Tombstones[0].Kind != TombstoneUser {
		t.Fatalf("tenant snapshot tombstones = %+v, %v", snapshot.Tombstones, err)
	}
	if _, err := store.ResolveActiveIdentity(ctx, tenantB, "provider-main", "subject-shared"); err != nil {
		t.Fatalf("tenant B identity was affected by tenant A deprovision: %v", err)
	}
}

func TestLocalStoreRestartIsDeterministic(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	clock := newTestClock(time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC))
	scope := testScope("tenant-restart")
	store := openTestStore(t, root, clock)
	registerTestTenant(t, store, scope)
	userRequest := UserUpsert{
		ProviderID: "provider-main", ExternalID: "user-restart",
		ExternalSubjectID: "subject-restart", PrincipalID: "restart-user", Active: true,
	}
	if _, _, err := store.UpsertUser(ctx, scope, userRequest); err != nil {
		t.Fatal(err)
	}
	groupRequest := GroupUpsert{
		ProviderID: "provider-main", ExternalID: "group-restart",
		GroupID: "restart-group", DisplayName: "Restart Group", Active: true,
	}
	if _, _, err := store.UpsertGroup(ctx, scope, groupRequest); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReplaceGroupMembers(ctx, scope, MembershipReplace{
		ProviderID: "provider-main", GroupExternalID: "group-restart",
		UserExternalIDs: []string{"user-restart"},
	}); err != nil {
		t.Fatal(err)
	}

	registryPath := filepath.Join(root, registryFileName)
	tenantPath := filepath.Join(root, tenantDirectory, tenantFileKey(scope.TenantID)+".json")
	registryBefore, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	tenantBefore, err := os.ReadFile(tenantPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, tenantDirectory), 0o755); err != nil {
		t.Fatal(err)
	}
	restarted := openTestStore(t, root, clock)
	if _, change, err := restarted.UpsertUser(ctx, scope, userRequest); err != nil || change.Changed {
		t.Fatalf("restart user replay = %+v, %v", change, err)
	}
	if _, change, err := restarted.UpsertGroup(ctx, scope, groupRequest); err != nil || change.Changed {
		t.Fatalf("restart group replay = %+v, %v", change, err)
	}
	registryAfter, _ := os.ReadFile(registryPath)
	tenantAfter, _ := os.ReadFile(tenantPath)
	if !slices.Equal(registryBefore, registryAfter) || !slices.Equal(tenantBefore, tenantAfter) {
		t.Fatal("idempotent restart changed deterministic durable bytes")
	}
	snapshot, err := restarted.Snapshot(ctx, scope)
	if err != nil || len(snapshot.Users) != 1 || len(snapshot.Groups) != 1 || snapshot.Revision.Number != 5 {
		t.Fatalf("restarted snapshot = %+v, %v", snapshot, err)
	}
	for _, path := range []string{
		root, filepath.Join(root, tenantDirectory), filepath.Join(root, processLockFileName), registryPath, tenantPath,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("identity state %s has permissive mode %o", filepath.Base(path), info.Mode().Perm())
		}
	}
}

func TestLocalStoreConcurrentInstancesDoNotLoseUpdates(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	clock := newTestClock(time.Date(2026, 7, 17, 3, 0, 0, 0, time.UTC))
	scope := testScope("tenant-concurrent")
	first := openTestStore(t, root, clock)
	registerTestTenant(t, first, scope)
	second := openTestStore(t, root, clock)

	const users = 48
	var wg sync.WaitGroup
	errorsSeen := make(chan error, users)
	for index := 0; index < users; index++ {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			identifier := "user-" + formatTestSequence(index+1)
			_, change, err := store.UpsertUser(ctx, scope, UserUpsert{
				ProviderID: "provider-main", ExternalID: identifier,
				ExternalSubjectID: "subject-" + formatTestSequence(index+1),
				PrincipalID:       "principal-" + formatTestSequence(index+1), Active: true,
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			if !change.Changed {
				errorsSeen <- errors.New("unique concurrent upsert was treated as a replay")
			}
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}

	var winners atomic.Int32
	secondErrors := make(chan error, 24)
	wg = sync.WaitGroup{}
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, change, err := second.UpsertUser(ctx, scope, UserUpsert{
				ProviderID: "provider-main", ExternalID: "one-winner",
				ExternalSubjectID: "one-winner-subject", PrincipalID: "one-winner", Active: true,
			})
			if err != nil {
				secondErrors <- err
				return
			}
			if change.Changed {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	close(secondErrors)
	for err := range secondErrors {
		t.Fatal(err)
	}
	if winners.Load() != 1 {
		t.Fatalf("concurrent idempotent upsert winners = %d, want 1", winners.Load())
	}

	restarted := openTestStore(t, root, clock)
	snapshot, err := restarted.Snapshot(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Users) != users+1 || snapshot.Revision.Number != 2+users+1 {
		t.Fatalf("concurrent snapshot users=%d revision=%d", len(snapshot.Users), snapshot.Revision.Number)
	}
	if !slices.IsSortedFunc(snapshot.Users, func(left, right User) int {
		return strings.Compare(left.ExternalID, right.ExternalID)
	}) {
		t.Fatal("concurrent users were not persisted canonically")
	}
}

func TestLocalStoreGroupDeprovisionIsTerminalAndIdempotent(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 3, 30, 0, 0, time.UTC))
	scope := testScope("tenant-group-tombstone")
	store := openTestStore(t, t.TempDir(), clock)
	registerTestTenant(t, store, scope)

	request := GroupUpsert{
		ProviderID: "provider-main", ExternalID: "external-group",
		GroupID: "group-terminal", DisplayName: "Terminal Group", Active: true,
	}
	if _, _, err := store.UpsertGroup(ctx, scope, request); err != nil {
		t.Fatal(err)
	}
	group, change, err := store.DeprovisionGroup(ctx, scope, request.ProviderID, request.ExternalID)
	if err != nil || !change.Changed || group.State != protocol.IdentityDeprovisioned || len(group.MemberUserIDs) != 0 {
		t.Fatalf("group deprovision = %+v, %+v, %v", group, change, err)
	}
	if _, repeated, err := store.DeprovisionGroup(ctx, scope, request.ProviderID, request.ExternalID); err != nil || repeated.Changed || repeated.Revision != change.Revision {
		t.Fatalf("group deprovision replay = %+v, %v", repeated, err)
	}
	if _, _, err := store.UpsertGroup(ctx, scope, request); !errors.Is(err, ErrDeprovisioned) {
		t.Fatalf("tombstoned group was reactivated: %v", err)
	}
	snapshot, err := store.Snapshot(ctx, scope)
	if err != nil || len(snapshot.Tombstones) != 1 || snapshot.Tombstones[0].Kind != TombstoneGroup ||
		snapshot.Tombstones[0].IdentityRevision != change.Revision.Number {
		t.Fatalf("group tombstone snapshot = %+v, %v", snapshot.Tombstones, err)
	}
}

func TestSCIMGrantBearingIdentifiersAreImmutableAndReserved(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir(), newTestClock(time.Date(2026, 7, 17, 3, 45, 0, 0, time.UTC)))
	scope := testScope("tenant-immutable-grants")
	registerTestTenant(t, store, scope)

	user := UserUpsert{
		ProviderID: "provider-main", ExternalID: "external-admin",
		ExternalSubjectID: "subject-admin", PrincipalID: "admin", Active: true,
	}
	if _, _, err := store.UpsertUser(ctx, scope, user); err != nil {
		t.Fatal(err)
	}
	changedUser := user
	changedUser.ExternalSubjectID = "subject-bob"
	changedUser.PrincipalID = "bob"
	if _, _, err := store.UpsertUser(ctx, scope, changedUser); !errors.Is(err, ErrConflict) {
		t.Fatalf("grant-bearing user identifiers changed: %v", err)
	}
	if _, _, err := store.UpsertUser(ctx, scope, UserUpsert{
		ProviderID: "provider-main", ExternalID: "external-attacker",
		ExternalSubjectID: "subject-attacker", PrincipalID: "admin", Active: true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("active principal was reassigned: %v", err)
	}
	if _, _, err := store.UpsertUser(ctx, scope, UserUpsert{
		ProviderID: "provider-main", ExternalID: "external-subject-attacker",
		ExternalSubjectID: "subject-admin", PrincipalID: "other", Active: true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("active external subject was reassigned: %v", err)
	}
	if _, _, err := store.DeprovisionUser(ctx, scope, user.ProviderID, user.ExternalID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertUser(ctx, scope, UserUpsert{
		ProviderID: "provider-main", ExternalID: "external-after-delete",
		ExternalSubjectID: "subject-after-delete", PrincipalID: "admin", Active: true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("deprovisioned principal was reassigned: %v", err)
	}
	if _, _, err := store.UpsertUser(ctx, scope, UserUpsert{
		ProviderID: "provider-main", ExternalID: "external-subject-after-delete",
		ExternalSubjectID: "subject-admin", PrincipalID: "after-delete", Active: true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("deprovisioned subject was reassigned: %v", err)
	}

	group := GroupUpsert{
		ProviderID: "provider-main", ExternalID: "external-admins",
		GroupID: "admins", DisplayName: "Admins", Active: true,
	}
	if _, _, err := store.UpsertGroup(ctx, scope, group); err != nil {
		t.Fatal(err)
	}
	renamed := group
	renamed.DisplayName = "Administrators"
	updated, change, err := store.UpsertGroup(ctx, scope, renamed)
	if err != nil || !change.Changed || updated.GroupID != group.GroupID || updated.DisplayName != renamed.DisplayName {
		t.Fatalf("display-only group rename = %+v, %+v, %v", updated, change, err)
	}
	changedGroup := renamed
	changedGroup.GroupID = "readers"
	if _, _, err := store.UpsertGroup(ctx, scope, changedGroup); !errors.Is(err, ErrConflict) {
		t.Fatalf("grant-bearing group ID changed: %v", err)
	}
	if _, _, err := store.DeprovisionGroup(ctx, scope, group.ProviderID, group.ExternalID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertGroup(ctx, scope, GroupUpsert{
		ProviderID: "provider-main", ExternalID: "external-group-attacker",
		GroupID: "admins", DisplayName: "Attacker", Active: true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("deprovisioned group ID was reassigned: %v", err)
	}
}

func TestNonceReplayStateIsAtomicDurableAndHashed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	clock := newTestClock(time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC))
	scope := testScope("tenant-replay")
	store := openTestStore(t, root, clock)
	registerTestTenant(t, store, scope)
	before, err := store.CurrentRevision(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	rawNonce := "nonce-that-must-never-be-persisted"
	digest := replayDigest(AssertionClaims{
		ProviderID: "provider-main", Issuer: testProvider().Issuer, Audience: "knote-cli",
		Subject: "subject-replay", TenantID: scope.TenantID,
		IssuedAt: clock.Now().Add(-time.Minute), ExpiresAt: clock.Now().Add(time.Hour), Nonce: rawNonce,
	})
	use := NonceUse{TenantID: scope.TenantID, Digest: digest, ExpiresAt: clock.Now().Add(time.Hour)}

	const attempts = 32
	var successes atomic.Int32
	var replays atomic.Int32
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.Consume(ctx, use)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrReplayDetected):
				replays.Add(1)
			default:
				t.Errorf("consume replay key: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || replays.Load() != attempts-1 {
		t.Fatalf("nonce outcomes success=%d replay=%d", successes.Load(), replays.Load())
	}
	restarted := openTestStore(t, root, clock)
	if err := restarted.Consume(ctx, use); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("restart accepted replay: %v", err)
	}
	after, err := restarted.CurrentRevision(ctx, scope)
	if err != nil || after != before {
		t.Fatalf("nonce consumption advanced identity revision: before=%+v after=%+v err=%v", before, after, err)
	}
	persisted, err := os.ReadFile(filepath.Join(root, tenantDirectory, tenantFileKey(scope.TenantID)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), rawNonce) || !strings.Contains(string(persisted), string(digest)) {
		t.Fatal("replay state persisted a raw nonce or omitted its digest")
	}
}
