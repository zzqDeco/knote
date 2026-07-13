package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

const (
	permissionedResumeErrorMessage   = "resume authorization failed"
	sessionAuthorizationErrorMessage = "session authorization failed"
)

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
	binding := newAuthorizationBinding(authorization)

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

func newAuthorizationBinding(authorization protocol.AuthorizationContext) authorizationBinding {
	return authorizationBinding{
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
}

func (m *Manager) bindSessionAuthorization(ctx context.Context, sessionID string, authorization protocol.AuthorizationContext) error {
	if err := m.bindAuthorizationContext(sessionID, authorization); err != nil {
		return err
	}
	sessions, ok := m.deps.Sessions.(repository.PermissionedSessions)
	if !ok {
		return sessionAuthorizationError()
	}
	envelope, err := protocol.NewSessionAuthorizationEnvelope(authorization, time.Now().UTC())
	if err != nil {
		return sessionAuthorizationError()
	}
	if err := sessions.BindAuthorization(ctx, envelope); err != nil {
		return sessionAuthorizationError()
	}
	return nil
}

func (m *Manager) authorizeSessionResume(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
	authorization, err := m.deps.AuthorizationContextProvider.authorizationContext(ctx, sessionID)
	if err != nil {
		return protocol.AuthorizationContext{}, permissionedResumeError()
	}
	sessions, ok := m.deps.Sessions.(repository.PermissionedSessions)
	if !ok {
		return protocol.AuthorizationContext{}, permissionedResumeError()
	}
	envelope, err := sessions.LoadAuthorization(ctx, sessionID)
	if err != nil {
		return protocol.AuthorizationContext{}, permissionedResumeError()
	}
	if err := envelope.ValidateFor(authorization); err != nil {
		return protocol.AuthorizationContext{}, permissionedResumeError()
	}
	return authorization, nil
}

func permissionedResumeError() error {
	return fmt.Errorf("%s", permissionedResumeErrorMessage)
}

func sessionAuthorizationError() error {
	return fmt.Errorf("%s", sessionAuthorizationErrorMessage)
}
