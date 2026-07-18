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
	tenantID                  string
	knowledgeBaseID           string
	principalID               string
	authorizationModelID      string
	identityWatermark         string
	aclWatermark              string
	agentID                   string
	taskID                    string
	delegationWatermark       string
	agentTaskScopeFingerprint protocol.AgentTaskScopeFingerprint
	consistency               protocol.ConsistencyPreference
}

type expectedSessionAuthorizationEnvelopeKey struct{}

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
		tenantID:                  authorization.TenantID,
		knowledgeBaseID:           authorization.KnowledgeBaseID,
		principalID:               authorization.PrincipalID,
		authorizationModelID:      authorization.AuthorizationModelID,
		identityWatermark:         authorization.IdentityWatermark,
		aclWatermark:              authorization.ACLWatermark,
		agentID:                   authorization.AgentID,
		taskID:                    authorization.TaskID,
		delegationWatermark:       authorization.DelegationWatermark,
		agentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
		consistency:               authorization.Consistency,
	}
}

func authorizationBindingFromEnvelope(envelope protocol.SessionAuthorizationEnvelope) authorizationBinding {
	return authorizationBinding{
		tenantID:                  envelope.TenantID,
		knowledgeBaseID:           envelope.KnowledgeBaseID,
		principalID:               envelope.PrincipalID,
		authorizationModelID:      envelope.AuthorizationModelID,
		identityWatermark:         envelope.IdentityWatermark,
		aclWatermark:              envelope.ACLWatermark,
		agentID:                   envelope.AgentID,
		taskID:                    envelope.TaskID,
		delegationWatermark:       envelope.DelegationWatermark,
		agentTaskScopeFingerprint: envelope.AgentTaskScopeFingerprint,
		consistency:               envelope.Consistency,
	}
}

func allowsArtifactScopeTransition(current, next authorizationBinding) bool {
	return current.principalID == next.principalID &&
		current.authorizationModelID == next.authorizationModelID &&
		current.identityWatermark == next.identityWatermark &&
		current.agentID == next.agentID &&
		current.taskID == next.taskID &&
		current.delegationWatermark == next.delegationWatermark &&
		current.agentTaskScopeFingerprint == next.agentTaskScopeFingerprint &&
		current.consistency == next.consistency
}

func withExpectedSessionAuthorizationEnvelope(
	ctx context.Context,
	envelope protocol.SessionAuthorizationEnvelope,
) context.Context {
	return context.WithValue(ctx, expectedSessionAuthorizationEnvelopeKey{}, envelope)
}

func expectedSessionAuthorizationEnvelopeFrom(ctx context.Context) (protocol.SessionAuthorizationEnvelope, bool) {
	envelope, ok := ctx.Value(expectedSessionAuthorizationEnvelopeKey{}).(protocol.SessionAuthorizationEnvelope)
	return envelope, ok
}

func (m *Manager) withSessionAuthorizationExpectation(
	ctx context.Context,
	sessionID string,
	authorization protocol.AuthorizationContext,
) (context.Context, error) {
	sessions, ok := m.deps.Sessions.(repository.PermissionedSessions)
	if !ok {
		return nil, sessionAuthorizationError()
	}
	envelope, err := sessions.LoadAuthorization(ctx, sessionID)
	if err != nil || envelope.ValidateFor(authorization) != nil {
		return nil, sessionAuthorizationError()
	}
	return withExpectedSessionAuthorizationEnvelope(ctx, envelope), nil
}

// RebindSessionAuthorization transitions a live permissioned session only
// after a trusted, confirmed artifact scope change. Query-time provider drift
// continues to use bindSessionAuthorization and remains immutable.
func (m *Manager) RebindSessionAuthorization(ctx context.Context, sessionID string) error {
	if !m.deps.Capabilities.IsPermissioned() {
		return sessionAuthorizationError()
	}
	expectedAuthorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok || expectedAuthorization.SessionID != sessionID {
		return sessionAuthorizationError()
	}
	expectedBinding := newAuthorizationBinding(expectedAuthorization)
	expectedEnvelope, ok := expectedSessionAuthorizationEnvelopeFrom(ctx)
	if !ok || expectedEnvelope.SessionID != sessionID || authorizationBindingFromEnvelope(expectedEnvelope) != expectedBinding {
		return sessionAuthorizationError()
	}
	sessions, ok := m.deps.Sessions.(repository.RebindablePermissionedSessions)
	if !ok {
		return sessionAuthorizationError()
	}
	authorization, err := m.deps.AuthorizationContextProvider.authorizationContext(ctx, sessionID)
	if err != nil {
		return sessionAuthorizationError()
	}
	replacement, err := protocol.NewSessionAuthorizationEnvelope(authorization, time.Now().UTC())
	if err != nil {
		return sessionAuthorizationError()
	}
	nextBinding := newAuthorizationBinding(authorization)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.einoSession.ID != sessionID || m.authorizationBinding == nil {
		return sessionAuthorizationError()
	}
	currentBinding := *m.authorizationBinding
	if currentBinding != expectedBinding {
		return sessionAuthorizationError()
	}
	if !allowsArtifactScopeTransition(currentBinding, nextBinding) {
		return sessionAuthorizationError()
	}
	existing, err := sessions.LoadAuthorization(ctx, sessionID)
	if currentBinding == nextBinding {
		if err != nil || existing != expectedEnvelope {
			return sessionAuthorizationError()
		}
		return nil
	}
	if err != nil {
		return sessionAuthorizationError()
	}
	if err := sessions.RebindAuthorization(ctx, expectedEnvelope, replacement); err != nil {
		return sessionAuthorizationError()
	}
	m.authorizationBinding = &nextBinding
	return nil
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
