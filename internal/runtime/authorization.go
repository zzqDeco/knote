package runtime

import (
	"context"
	"fmt"

	"github.com/zzqDeco/knote/internal/protocol"
)

const permissionedResumeErrorMessage = "resume is disabled when an authorization context provider is configured: persisted sessions do not contain a durable authorization envelope"

type authorizationBinding struct {
	tenantID             string
	knowledgeBaseID      string
	principalID          string
	authorizationModelID string
	identityWatermark    string
	aclWatermark         string
	agentID              string
	taskID               string
	consistency          protocol.ConsistencyPreference
}

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

func (m *Manager) bindAuthorizationContext(sessionID string, authorization protocol.AuthorizationContext) error {
	binding := authorizationBinding{
		tenantID:             authorization.TenantID,
		knowledgeBaseID:      authorization.KnowledgeBaseID,
		principalID:          authorization.PrincipalID,
		authorizationModelID: authorization.AuthorizationModelID,
		identityWatermark:    authorization.IdentityWatermark,
		aclWatermark:         authorization.ACLWatermark,
		agentID:              authorization.AgentID,
		taskID:               authorization.TaskID,
		consistency:          authorization.Consistency,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.einoSession.ID != sessionID {
		return fmt.Errorf("runtime session changed before authorization context could be bound")
	}
	if m.authorizationBinding == nil {
		m.authorizationBinding = &binding
		return nil
	}
	if *m.authorizationBinding != binding {
		return fmt.Errorf("authorization context changed for live session %q", sessionID)
	}
	return nil
}

func permissionedResumeError() error {
	return fmt.Errorf("%s", permissionedResumeErrorMessage)
}
