package authz

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestEpochRevocationLifecycleBlocksBeforeInvalidationCompletes(t *testing.T) {
	resourceID := testClaimResourceID(t, "concurrent")
	entered := make(chan struct{})
	release := make(chan struct{})
	lifecycle, err := NewEpochRevocationLifecycle(ResourceInvalidatorFunc(func(ctx context.Context, request InvalidationRequest) error {
		if err := request.Validate(); err != nil {
			return err
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)
	transition := RevocationTransition{
		BaseRevision: base, TargetRevision: target,
		GrantedResourceIDs: []protocol.ResourceID{resourceID},
	}
	result := make(chan error, 1)
	go func() {
		result <- lifecycle.Prepare(context.Background(), transition)
	}()
	<-entered
	allowed, err := lifecycle.Allows(base, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("resource was readable while stale evidence invalidation was in flight")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Commit(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	allowed, err = lifecycle.Allows(base, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("base revision became readable after target grant commit")
	}
	allowed, err = lifecycle.Allows(target, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("target revision did not activate committed grant")
	}
}

func TestEpochRevocationLifecycleRegrantRequiresNewerEpoch(t *testing.T) {
	resourceID := testClaimResourceID(t, "regrant")
	lifecycle, err := NewEpochRevocationLifecycle(ResourceInvalidatorFunc(func(_ context.Context, request InvalidationRequest) error {
		return request.Validate()
	}))
	if err != nil {
		t.Fatal(err)
	}
	base := testAuthorizationRevision(1)
	revoked := testAuthorizationRevision(2)
	revocation := RevocationTransition{
		BaseRevision: base, TargetRevision: revoked,
		RetiredResourceIDs: []protocol.ResourceID{resourceID},
	}
	if err := lifecycle.Prepare(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Commit(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	allowed, err := lifecycle.Allows(revoked, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("revoked resource remained readable")
	}

	staleRegrant := RevocationTransition{
		BaseRevision: base, TargetRevision: revoked,
		GrantedResourceIDs: []protocol.ResourceID{resourceID},
	}
	if err := lifecycle.Prepare(context.Background(), staleRegrant); !errors.Is(err, ErrRegrantRevision) {
		t.Fatalf("same-epoch regrant error = %v", err)
	}

	regranted := testAuthorizationRevision(3)
	regrant := RevocationTransition{
		BaseRevision: revoked, TargetRevision: regranted,
		GrantedResourceIDs: []protocol.ResourceID{resourceID},
	}
	if err := lifecycle.Prepare(context.Background(), regrant); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Commit(context.Background(), regrant); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		revision AuthorizationRevision
		want     bool
	}{
		{revision: revoked, want: false},
		{revision: regranted, want: true},
	} {
		allowed, err := lifecycle.Allows(test.revision, resourceID)
		if err != nil {
			t.Fatal(err)
		}
		if allowed != test.want {
			t.Fatalf("Allows(epoch=%d) = %t, want %t", test.revision.Epoch, allowed, test.want)
		}
	}
}

func TestEpochRevocationLifecycleConcurrentReads(t *testing.T) {
	resourceID := testClaimResourceID(t, "race")
	lifecycle, err := NewEpochRevocationLifecycle(ResourceInvalidatorFunc(func(_ context.Context, request InvalidationRequest) error {
		return request.Validate()
	}))
	if err != nil {
		t.Fatal(err)
	}
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)
	transition := RevocationTransition{
		BaseRevision: base, TargetRevision: target,
		RetiredResourceIDs: []protocol.ResourceID{resourceID},
		GrantedResourceIDs: []protocol.ResourceID{resourceID},
	}

	start := make(chan struct{})
	var readers sync.WaitGroup
	for index := 0; index < 16; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for attempt := 0; attempt < 500; attempt++ {
				if _, err := lifecycle.Allows(base, resourceID); err != nil {
					t.Errorf("base read: %v", err)
					return
				}
				if _, err := lifecycle.Allows(target, resourceID); err != nil {
					t.Errorf("target read: %v", err)
					return
				}
			}
		}()
	}
	close(start)
	if err := lifecycle.Prepare(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Commit(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	allowed, err := lifecycle.Allows(target, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("target revision was not readable after concurrent transition")
	}
}
