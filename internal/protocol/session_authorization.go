package protocol

import (
	"fmt"
	"time"
)

const SessionAuthorizationEnvelopeVersion = "v1"

// SessionAuthorizationEnvelope durably binds a session to the authorization
// state that created it. RequestID is intentionally excluded because it is
// scoped to a single request rather than the session.
type SessionAuthorizationEnvelope struct {
	Version              string                `json:"version"`
	TenantID             string                `json:"tenant_id"`
	KnowledgeBaseID      string                `json:"knowledge_base_id"`
	PrincipalID          string                `json:"principal_id"`
	SessionID            string                `json:"session_id"`
	AuthorizationModelID string                `json:"authorization_model_id"`
	IdentityWatermark    string                `json:"identity_watermark"`
	ACLWatermark         string                `json:"acl_watermark"`
	AgentID              string                `json:"agent_id,omitempty"`
	TaskID               string                `json:"task_id,omitempty"`
	Consistency          ConsistencyPreference `json:"consistency"`
	BoundAt              time.Time             `json:"bound_at"`
}

func NewSessionAuthorizationEnvelope(auth AuthorizationContext, boundAt time.Time) (SessionAuthorizationEnvelope, error) {
	if err := auth.Validate(); err != nil {
		return SessionAuthorizationEnvelope{}, err
	}
	envelope := SessionAuthorizationEnvelope{
		Version:              SessionAuthorizationEnvelopeVersion,
		TenantID:             auth.TenantID,
		KnowledgeBaseID:      auth.KnowledgeBaseID,
		PrincipalID:          auth.PrincipalID,
		SessionID:            auth.SessionID,
		AuthorizationModelID: auth.AuthorizationModelID,
		IdentityWatermark:    auth.IdentityWatermark,
		ACLWatermark:         auth.ACLWatermark,
		AgentID:              auth.AgentID,
		TaskID:               auth.TaskID,
		Consistency:          auth.Consistency,
		BoundAt:              boundAt.UTC(),
	}
	if err := envelope.Validate(); err != nil {
		return SessionAuthorizationEnvelope{}, err
	}
	return envelope, nil
}

func (e SessionAuthorizationEnvelope) Validate() error {
	required := []struct {
		name  string
		value string
	}{
		{"version", e.Version},
		{"tenant_id", e.TenantID},
		{"knowledge_base_id", e.KnowledgeBaseID},
		{"principal_id", e.PrincipalID},
		{"session_id", e.SessionID},
		{"authorization_model_id", e.AuthorizationModelID},
		{"identity_watermark", e.IdentityWatermark},
		{"acl_watermark", e.ACLWatermark},
	}
	for _, field := range required {
		if err := validateToken(field.name, field.value); err != nil {
			return err
		}
	}
	if e.Version != SessionAuthorizationEnvelopeVersion {
		return fmt.Errorf("unsupported session authorization envelope version %q", e.Version)
	}
	if e.AgentID != "" {
		if err := validateToken("agent_id", e.AgentID); err != nil {
			return err
		}
	}
	if e.TaskID != "" {
		if err := validateToken("task_id", e.TaskID); err != nil {
			return err
		}
	}
	switch e.Consistency {
	case ConsistencyMinimizeLatency, ConsistencyHigherConsistency:
	default:
		return fmt.Errorf("unsupported session authorization consistency preference %q", e.Consistency)
	}
	if e.BoundAt.IsZero() {
		return fmt.Errorf("session authorization bound_at is required")
	}
	if e.BoundAt.Location() != time.UTC {
		return fmt.Errorf("session authorization bound_at must be UTC")
	}
	return nil
}

func (e SessionAuthorizationEnvelope) ValidateFor(auth AuthorizationContext) error {
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := e.Validate(); err != nil {
		return err
	}
	bindings := []struct {
		name string
		got  string
		want string
	}{
		{"tenant_id", e.TenantID, auth.TenantID},
		{"knowledge_base_id", e.KnowledgeBaseID, auth.KnowledgeBaseID},
		{"principal_id", e.PrincipalID, auth.PrincipalID},
		{"session_id", e.SessionID, auth.SessionID},
		{"authorization_model_id", e.AuthorizationModelID, auth.AuthorizationModelID},
		{"identity_watermark", e.IdentityWatermark, auth.IdentityWatermark},
		{"acl_watermark", e.ACLWatermark, auth.ACLWatermark},
		{"agent_id", e.AgentID, auth.AgentID},
		{"task_id", e.TaskID, auth.TaskID},
		{"consistency", string(e.Consistency), string(auth.Consistency)},
	}
	for _, binding := range bindings {
		if binding.got != binding.want {
			return fmt.Errorf("session authorization envelope %s does not match authorization context", binding.name)
		}
	}
	return nil
}
