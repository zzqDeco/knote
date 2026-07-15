package protocol

import (
	"context"
	"fmt"
)

type authorizationContextKey struct{}

// WithAuthorizationContext binds trusted runtime authorization to an execution
// context. Tool arguments must never be used as an alternate source.
func WithAuthorizationContext(ctx context.Context, authorization AuthorizationContext) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("authorization execution context is nil")
	}
	if err := authorization.Validate(); err != nil {
		return nil, fmt.Errorf("authorization execution context: %w", err)
	}
	return context.WithValue(ctx, authorizationContextKey{}, authorization), nil
}

// AuthorizationContextFrom returns the trusted authorization bound by the
// runtime. Callers receive a value copy so the binding remains immutable.
func AuthorizationContextFrom(ctx context.Context) (AuthorizationContext, bool) {
	if ctx == nil {
		return AuthorizationContext{}, false
	}
	authorization, ok := ctx.Value(authorizationContextKey{}).(AuthorizationContext)
	return authorization, ok
}
