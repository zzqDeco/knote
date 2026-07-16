package authz

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestAtomicRevisionPublisherReservationIsInvisibleAndExclusive(t *testing.T) {
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)
	publisher, err := NewAtomicRevisionPublisher(base)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := publisher.Reserve(context.Background(), base, target)
	if err != nil {
		t.Fatal(err)
	}
	current, err := publisher.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current != base {
		t.Fatalf("reservation published target early: %#v", current)
	}
	if _, err := publisher.Reserve(context.Background(), base, target); !errors.Is(err, ErrRevisionPending) {
		t.Fatalf("concurrent reservation error = %v", err)
	}
	publisher.Abort(reservation)

	reservation, err = publisher.Reserve(context.Background(), base, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	current, err = publisher.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current != target {
		t.Fatalf("published revision = %#v, want %#v", current, target)
	}
}

func TestAtomicRevisionPublisherConcurrentReads(t *testing.T) {
	base := testAuthorizationRevision(1)
	target := testAuthorizationRevision(2)
	publisher, err := NewAtomicRevisionPublisher(base)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := publisher.Reserve(context.Background(), base, target)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var readers sync.WaitGroup
	for index := 0; index < 16; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for attempt := 0; attempt < 500; attempt++ {
				if _, err := publisher.Current(context.Background()); err != nil {
					t.Errorf("current revision: %v", err)
					return
				}
			}
		}()
	}
	close(start)
	if err := publisher.Publish(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
}
