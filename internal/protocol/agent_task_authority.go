package protocol

import (
	"context"
	"fmt"
	"time"
)

// AgentTaskScopeAuthority resolves current delegation and task state from an
// independent trusted source. Implementations must not treat the presented
// authorization context as proof that the scope is still active.
type AgentTaskScopeAuthority interface {
	CurrentAgentTaskScope(context.Context, AuthorizationContext) (AgentTaskScope, string, error)
}

// ResolveCurrentAgentTaskScope verifies a delegated authorization context
// against current authority state. Direct-user contexts need no authority.
func ResolveCurrentAgentTaskScope(
	ctx context.Context,
	authority AgentTaskScopeAuthority,
	auth AuthorizationContext,
	at time.Time,
) (AgentTaskScope, error) {
	if ctx == nil {
		return AgentTaskScope{}, fmt.Errorf("agent task scope resolution requires a context")
	}
	if err := auth.Validate(); err != nil {
		return AgentTaskScope{}, err
	}
	if auth.AgentID == "" {
		return AgentTaskScope{}, nil
	}
	if authority == nil {
		return AgentTaskScope{}, fmt.Errorf("delegated authorization requires a current agent task scope authority")
	}
	if err := ctx.Err(); err != nil {
		return AgentTaskScope{}, err
	}
	scope, currentDelegationWatermark, err := authority.CurrentAgentTaskScope(ctx, auth)
	if err != nil {
		return AgentTaskScope{}, fmt.Errorf("current agent task scope is unavailable: %w", err)
	}
	if err := auth.ValidateAgentTaskScope(scope, currentDelegationWatermark, at); err != nil {
		return AgentTaskScope{}, err
	}
	return scope, nil
}
