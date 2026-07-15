package protocol

import (
	"context"
	"testing"
)

func TestAuthorizationExecutionContextRoundTrip(t *testing.T) {
	authorization := testAuthorizationContext()
	ctx, err := WithAuthorizationContext(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := AuthorizationContextFrom(ctx)
	if !ok || got != authorization {
		t.Fatalf("authorization context = %+v, %t; want %+v", got, ok, authorization)
	}

	got.PrincipalID = "mutated"
	again, ok := AuthorizationContextFrom(ctx)
	if !ok || again != authorization {
		t.Fatalf("stored authorization was mutable: %+v", again)
	}
}

func TestAuthorizationExecutionContextRejectsInvalidInputs(t *testing.T) {
	if _, err := WithAuthorizationContext(nil, testAuthorizationContext()); err == nil {
		t.Fatal("nil context should fail")
	}
	if _, err := WithAuthorizationContext(context.Background(), AuthorizationContext{}); err == nil {
		t.Fatal("invalid authorization should fail")
	}
	if _, ok := AuthorizationContextFrom(context.Background()); ok {
		t.Fatal("unbound context should not contain authorization")
	}
	if _, ok := AuthorizationContextFrom(nil); ok {
		t.Fatal("nil context should not contain authorization")
	}
}
