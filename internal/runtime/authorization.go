package runtime

import (
	"context"
	"fmt"

	"github.com/zzqDeco/knote/internal/protocol"
)

func (provider AuthorizationContextProvider) authorizationContext(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
	if provider == nil {
		return protocol.AuthorizationContext{}, fmt.Errorf("authorization context provider is not configured")
	}
	authorization, err := provider(ctx, sessionID)
	if err != nil {
		return protocol.AuthorizationContext{}, fmt.Errorf("authorization context provider: %w", err)
	}
	if authorization.SessionID != sessionID {
		return protocol.AuthorizationContext{}, fmt.Errorf("authorization context session %q does not match runtime session %q", authorization.SessionID, sessionID)
	}
	return authorization, nil
}
