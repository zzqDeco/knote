package identity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	testPublicationStoreID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testPublicationModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
)

type recordingMembershipWriter struct {
	mu             sync.Mutex
	claimed        bool
	tenantIDs      []string
	members        map[Membership]struct{}
	requests       []MembershipWriteRequest
	inspectCalls   int
	failAfterApply bool
	started        chan struct{}
	release        chan struct{}
}

func (w *recordingMembershipWriter) InspectMembershipState(
	_ context.Context,
	target MembershipPublicationTarget,
) (MembershipRemoteState, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inspectCalls++
	members := make([]Membership, 0, len(w.members))
	for member := range w.members {
		members = append(members, member)
	}
	slices.SortFunc(members, func(left, right Membership) int {
		switch {
		case membershipLess(left, right):
			return -1
		case membershipLess(right, left):
			return 1
		default:
			return 0
		}
	})
	return MembershipRemoteState{
		Claimed: w.claimed, TenantIDs: slices.Clone(w.tenantIDs), Members: members,
	}, nil
}

func (w *recordingMembershipWriter) ClaimMembershipStore(
	_ context.Context,
	target MembershipPublicationTarget,
) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.claimed {
		return errors.New("remote claim already exists")
	}
	w.claimed = true
	w.tenantIDs = []string{target.TenantID}
	return nil
}

func newRecordingMembershipWriter() *recordingMembershipWriter {
	return &recordingMembershipWriter{members: make(map[Membership]struct{})}
}

func (w *recordingMembershipWriter) ApplyMembershipChanges(
	ctx context.Context,
	request MembershipWriteRequest,
) error {
	w.mu.Lock()
	request.Writes = slices.Clone(request.Writes)
	request.Deletes = slices.Clone(request.Deletes)
	w.requests = append(w.requests, request)
	for _, member := range request.Deletes {
		delete(w.members, member)
	}
	for _, member := range request.Writes {
		w.members[member] = struct{}{}
	}
	fail := w.failAfterApply
	w.failAfterApply = false
	started := w.started
	release := w.release
	w.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("injected external write failure")
	}
	return nil
}

func (w *recordingMembershipWriter) snapshot() ([]Membership, []MembershipWriteRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()
	members := make([]Membership, 0, len(w.members))
	for member := range w.members {
		members = append(members, member)
	}
	slices.SortFunc(members, func(left, right Membership) int {
		switch {
		case membershipLess(left, right):
			return -1
		case membershipLess(right, left):
			return 1
		default:
			return 0
		}
	})
	requests := slices.Clone(w.requests)
	return members, requests
}

func TestMembershipPublicationRemovalAndDeprovisionDeleteBeforeReceipt(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC))
	store := openTestStore(t, t.TempDir(), clock)
	scope := testScope("tenant-publication-lifecycle")
	setupPublicationIdentity(t, store, scope, true)
	target := publicationTarget(scope.TenantID)
	writer := newRecordingMembershipWriter()

	added, err := store.PublishMembershipProjection(ctx, target, writer)
	if err != nil || added.MemberCount != 1 {
		t.Fatalf("publish membership add = %+v, %v", added, err)
	}
	beforePublish, err := store.CurrentRevision(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	_, removalChange, err := store.UpsertMembership(ctx, scope, MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-publication",
		UserExternalID: "user-publication", Active: false,
	})
	if err != nil || !removalChange.Changed {
		t.Fatalf("remove membership = %+v, %v", removalChange, err)
	}
	removed, err := store.PublishMembershipProjection(ctx, target, writer)
	if err != nil || removed.MemberCount != 0 || removed.IdentityWatermark != removalChange.Revision.Watermark {
		t.Fatalf("publish membership removal = %+v, %v", removed, err)
	}
	members, requests := writer.snapshot()
	if len(members) != 0 || len(requests) < 2 || len(requests[len(requests)-1].Deletes) != 1 {
		t.Fatalf("removal did not delete the published membership: members=%+v requests=%+v", members, requests)
	}
	afterPublish, err := store.CurrentRevision(ctx, scope)
	if err != nil || afterPublish != removalChange.Revision || beforePublish.Number+1 != afterPublish.Number {
		t.Fatalf("publication advanced identity revision: before=%+v after=%+v err=%v", beforePublish, afterPublish, err)
	}

	if _, change, err := store.UpsertMembership(ctx, scope, MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-publication",
		UserExternalID: "user-publication", Active: true,
	}); err != nil || !change.Changed {
		t.Fatalf("restore membership = %+v, %v", change, err)
	}
	if _, err := store.PublishMembershipProjection(ctx, target, writer); err != nil {
		t.Fatal(err)
	}
	_, deprovisionChange, err := store.DeprovisionUser(ctx, scope, "provider-main", "user-publication")
	if err != nil || !deprovisionChange.Changed {
		t.Fatalf("deprovision user = %+v, %v", deprovisionChange, err)
	}
	deprovisioned, err := store.PublishMembershipProjection(ctx, target, writer)
	if err != nil || deprovisioned.MemberCount != 0 || deprovisioned.IdentityWatermark != deprovisionChange.Revision.Watermark {
		t.Fatalf("publish deprovision = %+v, %v", deprovisioned, err)
	}
	members, requests = writer.snapshot()
	if len(members) != 0 || len(requests[len(requests)-1].Deletes) != 1 {
		t.Fatalf("deprovision did not delete the published membership: members=%+v", members)
	}
}

func TestMembershipPublicationRestartRetriesUncertainWriteIdempotently(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	clock := newTestClock(time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC))
	scope := testScope("tenant-publication-restart")
	store := openTestStore(t, root, clock)
	setupPublicationIdentity(t, store, scope, true)
	target := publicationTarget(scope.TenantID)
	writer := newRecordingMembershipWriter()
	initial, err := store.PublishMembershipProjection(ctx, target, writer)
	if err != nil {
		t.Fatal(err)
	}
	if _, change, err := store.UpsertMembership(ctx, scope, MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-publication",
		UserExternalID: "user-publication", Active: false,
	}); err != nil || !change.Changed {
		t.Fatalf("remove membership = %+v, %v", change, err)
	}
	writer.failAfterApply = true
	if _, err := store.PublishMembershipProjection(ctx, target, writer); !errors.Is(err, ErrPublicationUnavailable) {
		t.Fatalf("uncertain write error = %v", err)
	}
	state, err := store.loadPublicationState(target)
	if err != nil || state.Pending == nil || state.Published == nil || state.Published.IdentityWatermark != initial.IdentityWatermark {
		t.Fatalf("failed write advanced receipt or lost intent: state=%+v err=%v", state, err)
	}

	restarted := openTestStore(t, root, clock)
	receipt, err := restarted.PublishMembershipProjection(ctx, target, writer)
	if err != nil || receipt.MemberCount != 0 || receipt.IdentityWatermark == initial.IdentityWatermark {
		t.Fatalf("restart publication = %+v, %v", receipt, err)
	}
	_, requests := writer.snapshot()
	callCount := len(requests)
	repeated, err := restarted.PublishMembershipProjection(ctx, target, writer)
	if err != nil || repeated != receipt {
		t.Fatalf("idempotent publication = %+v, %v; want %+v", repeated, err, receipt)
	}
	_, requests = writer.snapshot()
	if len(requests) != callCount {
		t.Fatalf("idempotent receipt invoked writer again: before=%d after=%d", callCount, len(requests))
	}
}

func TestMembershipPublicationRacingSCIMChangeCannotResurrectGrant(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC))
	root := t.TempDir()
	scope := testScope("tenant-publication-race")
	first := openTestStore(t, root, clock)
	setupPublicationIdentity(t, first, scope, false)
	second := openTestStore(t, root, clock)
	target := publicationTarget(scope.TenantID)
	writer := newRecordingMembershipWriter()
	if _, err := first.PublishMembershipProjection(ctx, target, writer); err != nil {
		t.Fatal(err)
	}
	if _, change, err := first.UpsertMembership(ctx, scope, MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-publication",
		UserExternalID: "user-publication", Active: true,
	}); err != nil || !change.Changed {
		t.Fatalf("add membership = %+v, %v", change, err)
	}
	writer.started = make(chan struct{}, 1)
	writer.release = make(chan struct{})

	type result struct {
		receipt MembershipPublicationReceipt
		err     error
	}
	firstResult := make(chan result, 1)
	go func() {
		receipt, err := first.PublishMembershipProjection(ctx, target, writer)
		firstResult <- result{receipt: receipt, err: err}
	}()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not reach external writer")
	}
	if _, change, err := second.UpsertMembership(ctx, scope, MembershipUpsert{
		ProviderID: "provider-main", GroupExternalID: "group-publication",
		UserExternalID: "user-publication", Active: false,
	}); err != nil || !change.Changed {
		t.Fatalf("racing removal = %+v, %v", change, err)
	}
	secondResult := make(chan result, 1)
	go func() {
		receipt, err := second.PublishMembershipProjection(ctx, target, writer)
		secondResult <- result{receipt: receipt, err: err}
	}()
	close(writer.release)
	firstPublished := <-firstResult
	secondPublished := <-secondResult
	if firstPublished.err != nil || secondPublished.err != nil ||
		firstPublished.receipt.MemberCount != 0 || secondPublished.receipt != firstPublished.receipt {
		t.Fatalf("concurrent publication results: first=%+v second=%+v", firstPublished, secondPublished)
	}
	members, requests := writer.snapshot()
	if len(members) != 0 || len(requests) < 3 || len(requests[len(requests)-1].Deletes) != 1 {
		t.Fatalf("stale publisher resurrected membership: members=%+v requests=%+v", members, requests)
	}
}

func TestMembershipPublicationBindsStoreToOneTenant(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir(), newTestClock(time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)))
	first := testScope("tenant-publication-first")
	second := testScope("tenant-publication-second")
	setupPublicationIdentity(t, store, first, false)
	setupPublicationIdentity(t, store, second, false)
	writer := newRecordingMembershipWriter()
	if _, err := store.PublishMembershipProjection(ctx, publicationTarget(first.TenantID), writer); err != nil {
		t.Fatal(err)
	}
	_, before := writer.snapshot()
	if _, err := store.PublishMembershipProjection(ctx, publicationTarget(second.TenantID), writer); !errors.Is(err, ErrPublicationTargetMismatch) {
		t.Fatalf("cross-tenant target error = %v", err)
	}
	_, after := writer.snapshot()
	if len(after) != len(before) {
		t.Fatal("cross-tenant target reached external writer")
	}
}

func TestMembershipPublicationUsesRemoteBindingAcrossIndependentRootsAndRepairsJournalLoss(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 11, 15, 0, 0, time.UTC))
	firstScope := testScope("tenant-remote-first")
	secondScope := testScope("tenant-remote-second")
	first := openTestStore(t, t.TempDir(), clock)
	second := openTestStore(t, t.TempDir(), clock)
	setupPublicationIdentity(t, first, firstScope, true)
	setupPublicationIdentity(t, second, secondScope, true)
	backend := newRecordingMembershipWriter()
	firstTarget := publicationTarget(firstScope.TenantID)

	if _, err := first.PublishMembershipProjection(ctx, firstTarget, backend); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(first.publicationStatePath(firstTarget.StoreID)); err != nil {
		t.Fatal(err)
	}
	unknown := Membership{
		TenantID: firstScope.TenantID, PrincipalID: "unknown-stale", GroupID: "unknown-stale",
	}
	backend.mu.Lock()
	backend.members[unknown] = struct{}{}
	backend.mu.Unlock()

	repaired, err := first.PublishMembershipProjection(ctx, firstTarget, backend)
	if err != nil || repaired.MemberCount != 1 {
		t.Fatalf("journal-loss repair = %+v, %v", repaired, err)
	}
	members, requests := backend.snapshot()
	if slices.Contains(members, unknown) || len(requests) < 2 ||
		!slices.Contains(requests[len(requests)-1].Deletes, unknown) {
		t.Fatalf("unknown remote tuple survived reconciliation: members=%+v requests=%+v", members, requests)
	}

	if _, err := second.PublishMembershipProjection(
		ctx, publicationTarget(secondScope.TenantID), backend,
	); !errors.Is(err, ErrPublicationTargetMismatch) {
		t.Fatalf("independent identity root reused bound store: %v", err)
	}
}

func TestMembershipPublicationConcurrentCrossTenantClaimHasOneWinner(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 11, 20, 0, 0, time.UTC))
	firstScope := testScope("tenant-claim-first")
	secondScope := testScope("tenant-claim-second")
	first := openTestStore(t, t.TempDir(), clock)
	second := openTestStore(t, t.TempDir(), clock)
	setupPublicationIdentity(t, first, firstScope, false)
	setupPublicationIdentity(t, second, secondScope, false)
	backend := newRacingClaimBackend()

	type result struct {
		tenantID string
		err      error
	}
	results := make(chan result, 2)
	for _, candidate := range []struct {
		store *LocalStore
		scope protocol.TenantScope
	}{{first, firstScope}, {second, secondScope}} {
		candidate := candidate
		go func() {
			_, err := candidate.store.PublishMembershipProjection(
				ctx, publicationTarget(candidate.scope.TenantID), backend,
			)
			results <- result{tenantID: candidate.scope.TenantID, err: err}
		}()
	}
	var succeeded, mismatched int
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			succeeded++
		case errors.Is(result.err, ErrPublicationTargetMismatch):
			mismatched++
		default:
			t.Fatalf("claim result for %s = %v", result.tenantID, result.err)
		}
	}
	state, err := backend.InspectMembershipState(ctx, publicationTarget(firstScope.TenantID))
	if err != nil || succeeded != 1 || mismatched != 1 || !state.Claimed || len(state.TenantIDs) != 1 {
		t.Fatalf("concurrent claim outcome: success=%d mismatch=%d state=%+v err=%v", succeeded, mismatched, state, err)
	}
}

func TestMembershipPublicationRejectsMalformedOrUnboundNonemptyRemoteState(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 7, 17, 11, 25, 0, 0, time.UTC))
	scope := testScope("tenant-remote-invalid")
	store := openTestStore(t, t.TempDir(), clock)
	setupPublicationIdentity(t, store, scope, false)
	target := publicationTarget(scope.TenantID)

	unbound := newRecordingMembershipWriter()
	unbound.members[Membership{TenantID: scope.TenantID, PrincipalID: "stale", GroupID: "stale"}] = struct{}{}
	if _, err := store.PublishMembershipProjection(ctx, target, unbound); !errors.Is(err, ErrPublicationUnavailable) {
		t.Fatalf("unbound nonempty store error = %v", err)
	}
	if unbound.claimed {
		t.Fatal("unbound nonempty store was claimed")
	}

	malformed := newRecordingMembershipWriter()
	malformed.claimed = true
	malformed.tenantIDs = []string{scope.TenantID, "tenant-other"}
	if _, err := store.PublishMembershipProjection(ctx, target, malformed); !errors.Is(err, ErrPublicationUnavailable) {
		t.Fatalf("multiple tenant binding error = %v", err)
	}
}

type racingClaimBackend struct {
	*recordingMembershipWriter
	barrierMu sync.Mutex
	arrived   int
	release   chan struct{}
}

func newRacingClaimBackend() *racingClaimBackend {
	return &racingClaimBackend{
		recordingMembershipWriter: newRecordingMembershipWriter(), release: make(chan struct{}),
	}
}

func (b *racingClaimBackend) InspectMembershipState(
	ctx context.Context,
	target MembershipPublicationTarget,
) (MembershipRemoteState, error) {
	state, err := b.recordingMembershipWriter.InspectMembershipState(ctx, target)
	if err != nil {
		return MembershipRemoteState{}, err
	}
	b.barrierMu.Lock()
	wait := b.arrived < 2
	if wait {
		b.arrived++
		if b.arrived == 2 {
			close(b.release)
		}
	}
	b.barrierMu.Unlock()
	if wait {
		select {
		case <-b.release:
		case <-ctx.Done():
			return MembershipRemoteState{}, ctx.Err()
		}
	}
	return state, nil
}

func TestMembershipPublicationUsesCrossProcessLock(t *testing.T) {
	root := t.TempDir()
	store, err := OpenLocalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope("tenant-publication-process")
	setupPublicationIdentity(t, store, scope, true)
	markerFirst := filepath.Join(t.TempDir(), "first")
	markerSecond := filepath.Join(t.TempDir(), "second")
	secondReady := filepath.Join(t.TempDir(), "second-ready")
	release := filepath.Join(t.TempDir(), "release")

	first := publicationHelperCommand(root, scope.TenantID, markerFirst, release, "")
	var firstOutput bytes.Buffer
	first.Stdout = &firstOutput
	first.Stderr = &firstOutput
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	waitForPath(t, markerFirst)
	second := publicationHelperCommand(root, scope.TenantID, markerSecond, "", secondReady)
	secondOutput := make(chan error, 1)
	go func() { secondOutput <- second.Run() }()
	waitForPath(t, secondReady)
	select {
	case err := <-secondOutput:
		_ = os.WriteFile(release, []byte("release"), 0o600)
		_ = first.Wait()
		t.Fatalf("second process bypassed publication lock: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := os.Stat(markerSecond); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second process entered writer before first released lock: %v", err)
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatalf("first publication helper: %v: %s", err, firstOutput.String())
	}
	select {
	case err := <-secondOutput:
		if err != nil {
			t.Fatalf("second publication helper: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second publication helper did not exit")
	}
	if _, err := os.Stat(markerSecond); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second process repeated a completed publication: %v", err)
	}
}

func TestMembershipPublicationProcessHelper(t *testing.T) {
	if os.Getenv("KNOTE_IDENTITY_PUBLICATION_HELPER") != "1" {
		return
	}
	root := os.Getenv("KNOTE_IDENTITY_PUBLICATION_ROOT")
	tenantID := os.Getenv("KNOTE_IDENTITY_PUBLICATION_TENANT")
	marker := os.Getenv("KNOTE_IDENTITY_PUBLICATION_MARKER")
	release := os.Getenv("KNOTE_IDENTITY_PUBLICATION_RELEASE")
	ready := os.Getenv("KNOTE_IDENTITY_PUBLICATION_READY")
	store, err := OpenLocalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if ready != "" {
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writer := &staticMembershipBackend{
		tenantID: tenantID,
		members:  []Membership{{TenantID: tenantID, PrincipalID: "alice", GroupID: "engineering"}},
		apply: func(ctx context.Context, _ MembershipWriteRequest) error {
			if err := os.WriteFile(marker, []byte("writer"), 0o600); err != nil {
				return err
			}
			if release == "" {
				return nil
			}
			for {
				if _, err := os.Stat(release); err == nil {
					return nil
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Millisecond):
				}
			}
		},
	}
	if _, err := store.PublishMembershipProjection(context.Background(), publicationTarget(tenantID), writer); err != nil {
		t.Fatal(err)
	}
}

type staticMembershipBackend struct {
	tenantID string
	members  []Membership
	apply    func(context.Context, MembershipWriteRequest) error
}

func (b *staticMembershipBackend) InspectMembershipState(
	context.Context,
	MembershipPublicationTarget,
) (MembershipRemoteState, error) {
	return MembershipRemoteState{
		Claimed: true, TenantIDs: []string{b.tenantID}, Members: slices.Clone(b.members),
	}, nil
}

func (*staticMembershipBackend) ClaimMembershipStore(context.Context, MembershipPublicationTarget) error {
	return errors.New("unexpected claim")
}

func (b *staticMembershipBackend) ApplyMembershipChanges(ctx context.Context, request MembershipWriteRequest) error {
	if b.apply == nil {
		return nil
	}
	return b.apply(ctx, request)
}

func setupPublicationIdentity(t *testing.T, store *LocalStore, scope protocol.TenantScope, member bool) {
	t.Helper()
	ctx := context.Background()
	registerTestTenant(t, store, scope)
	if _, _, err := store.UpsertUser(ctx, scope, UserUpsert{
		ProviderID: "provider-main", ExternalID: "user-publication",
		ExternalSubjectID: "subject-publication", PrincipalID: "alice", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertGroup(ctx, scope, GroupUpsert{
		ProviderID: "provider-main", ExternalID: "group-publication",
		GroupID: "engineering", DisplayName: "Engineering", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if member {
		if _, _, err := store.UpsertMembership(ctx, scope, MembershipUpsert{
			ProviderID: "provider-main", GroupExternalID: "group-publication",
			UserExternalID: "user-publication", Active: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func publicationTarget(tenantID string) MembershipPublicationTarget {
	return MembershipPublicationTarget{
		TenantID: tenantID, StoreID: testPublicationStoreID,
		AuthorizationModelID: testPublicationModelID,
	}
}

func publicationHelperCommand(root, tenantID, marker, release, ready string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestMembershipPublicationProcessHelper$")
	command.Env = append(os.Environ(),
		"KNOTE_IDENTITY_PUBLICATION_HELPER=1",
		"KNOTE_IDENTITY_PUBLICATION_ROOT="+root,
		"KNOTE_IDENTITY_PUBLICATION_TENANT="+tenantID,
		"KNOTE_IDENTITY_PUBLICATION_MARKER="+marker,
		"KNOTE_IDENTITY_PUBLICATION_RELEASE="+release,
		"KNOTE_IDENTITY_PUBLICATION_READY="+ready,
	)
	return command
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", filepath.Base(path))
}
