package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const EnterpriseContractVersion = "v1"

// TenantScope is the minimum trusted partition key for Phase 3 control-plane
// metadata. Protected content remains in the tenant's data-plane boundary.
type TenantScope struct {
	Version  string `json:"version"`
	TenantID string `json:"tenant_id"`
	Region   string `json:"region"`
}

func (s TenantScope) Validate() error {
	if s.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported tenant scope version %q", s.Version)
	}
	if err := validateEnterpriseID("tenant_id", s.TenantID); err != nil {
		return err
	}
	return validateRegion("region", s.Region)
}

func (s TenantScope) ValidateAuthorization(auth AuthorizationContext) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if auth.TenantID != s.TenantID {
		return fmt.Errorf("authorization context crosses the tenant scope")
	}
	return nil
}

type IdentityState string

const (
	IdentityActive        IdentityState = "active"
	IdentityDeprovisioned IdentityState = "deprovisioned"
)

// IdentitySnapshot is a content-free, provider-normalized identity view. Raw
// bearer assertions and credentials are deliberately absent.
type IdentitySnapshot struct {
	Version           string        `json:"version"`
	TenantID          string        `json:"tenant_id"`
	ProviderID        string        `json:"provider_id"`
	ExternalSubjectID string        `json:"external_subject_id"`
	PrincipalID       string        `json:"principal_id"`
	GroupIDs          []string      `json:"group_ids"`
	State             IdentityState `json:"state"`
	Watermark         string        `json:"identity_watermark"`
	IssuedAt          time.Time     `json:"issued_at"`
	ExpiresAt         time.Time     `json:"expires_at"`
}

func (s IdentitySnapshot) Validate() error {
	if s.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported identity snapshot version %q", s.Version)
	}
	if err := validateEnterpriseFields(
		"tenant_id", s.TenantID,
		"provider_id", s.ProviderID,
		"external_subject_id", s.ExternalSubjectID,
		"principal_id", s.PrincipalID,
		"identity_watermark", s.Watermark,
	); err != nil {
		return err
	}
	if err := validateSortedEnterpriseIDs("group_ids", s.GroupIDs, false); err != nil {
		return err
	}
	switch s.State {
	case IdentityActive, IdentityDeprovisioned:
	default:
		return fmt.Errorf("unsupported identity state %q", s.State)
	}
	if err := validateUTC("issued_at", s.IssuedAt); err != nil {
		return err
	}
	if err := validateUTC("expires_at", s.ExpiresAt); err != nil {
		return err
	}
	if !s.ExpiresAt.After(s.IssuedAt) {
		return fmt.Errorf("identity snapshot expires_at must be after issued_at")
	}
	return nil
}

func (s IdentitySnapshot) ValidateFor(scope TenantScope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if s.TenantID != scope.TenantID {
		return fmt.Errorf("identity snapshot crosses the tenant scope")
	}
	return nil
}

func (s IdentitySnapshot) UsableAt(currentIdentityWatermark string, at time.Time) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseID("current_identity_watermark", currentIdentityWatermark); err != nil {
		return err
	}
	if err := validateUTC("evaluation_time", at); err != nil {
		return err
	}
	if s.State != IdentityActive {
		return fmt.Errorf("identity snapshot is not active")
	}
	if s.Watermark != currentIdentityWatermark {
		return fmt.Errorf("identity snapshot watermark is stale")
	}
	if at.Before(s.IssuedAt) || !at.Before(s.ExpiresAt) {
		return fmt.Errorf("identity snapshot is not valid at the evaluation time")
	}
	return nil
}

type ConnectorEventKind string

const (
	ConnectorContentUpsert     ConnectorEventKind = "content_upsert"
	ConnectorACLReplace        ConnectorEventKind = "acl_replace"
	ConnectorResourceTombstone ConnectorEventKind = "resource_tombstone"
	ConnectorSnapshotComplete  ConnectorEventKind = "snapshot_complete"
)

// ConnectorEventEnvelope contains only routing, integrity, and version data.
// Connector payload bodies remain in the tenant data plane.
type ConnectorEventEnvelope struct {
	Version         string             `json:"version"`
	TenantID        string             `json:"tenant_id"`
	ConnectorID     string             `json:"connector_id"`
	EventID         string             `json:"event_id"`
	IdempotencyKey  string             `json:"idempotency_key"`
	Kind            ConnectorEventKind `json:"kind"`
	Sequence        uint64             `json:"sequence"`
	ResourceID      ResourceID         `json:"resource_id,omitempty"`
	SourceWatermark string             `json:"source_watermark"`
	ACLWatermark    string             `json:"acl_watermark"`
	PayloadDigest   ContentDigest      `json:"payload_digest"`
	OccurredAt      time.Time          `json:"occurred_at"`
}

func (e ConnectorEventEnvelope) Validate() error {
	if e.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported connector event version %q", e.Version)
	}
	if err := validateEnterpriseFields(
		"tenant_id", e.TenantID,
		"connector_id", e.ConnectorID,
		"event_id", e.EventID,
		"idempotency_key", e.IdempotencyKey,
		"source_watermark", e.SourceWatermark,
		"acl_watermark", e.ACLWatermark,
	); err != nil {
		return err
	}
	if e.Sequence == 0 {
		return fmt.Errorf("connector event sequence must be greater than zero")
	}
	switch e.Kind {
	case ConnectorContentUpsert, ConnectorACLReplace, ConnectorResourceTombstone:
		if err := e.ResourceID.Validate(); err != nil {
			return err
		}
	case ConnectorSnapshotComplete:
		if e.ResourceID != "" {
			return fmt.Errorf("snapshot_complete event must not identify one resource")
		}
	default:
		return fmt.Errorf("unsupported connector event kind %q", e.Kind)
	}
	if err := e.PayloadDigest.Validate(); err != nil {
		return err
	}
	return validateUTC("occurred_at", e.OccurredAt)
}

func (e ConnectorEventEnvelope) ValidateFor(scope TenantScope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := e.Validate(); err != nil {
		return err
	}
	if e.TenantID != scope.TenantID {
		return fmt.Errorf("connector event crosses the tenant scope")
	}
	return nil
}

type ConnectorEventFingerprint string

func NewConnectorEventFingerprint(event ConnectorEventEnvelope) (ConnectorEventFingerprint, error) {
	if err := event.Validate(); err != nil {
		return "", err
	}
	parts := []string{
		event.Version, event.TenantID, event.ConnectorID, event.EventID, event.IdempotencyKey,
		string(event.Kind), fmt.Sprintf("%d", event.Sequence), string(event.ResourceID),
		event.SourceWatermark, event.ACLWatermark, string(event.PayloadDigest),
		event.OccurredAt.Format(time.RFC3339Nano),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return ConnectorEventFingerprint("cevt_" + hex.EncodeToString(sum[:16])), nil
}

func (f ConnectorEventFingerprint) Validate() error {
	value := string(f)
	if !strings.HasPrefix(value, "cevt_") || len(value) != len("cevt_")+32 {
		return fmt.Errorf("connector event fingerprint must be an opaque cevt_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "cevt_")); err != nil {
		return fmt.Errorf("connector event fingerprint must be hexadecimal: %w", err)
	}
	return nil
}

type ConnectorCheckpoint struct {
	Version                   string                    `json:"version"`
	TenantID                  string                    `json:"tenant_id"`
	ConnectorID               string                    `json:"connector_id"`
	LastSequence              uint64                    `json:"last_sequence"`
	CommittedEventID          string                    `json:"committed_event_id"`
	CommittedEventFingerprint ConnectorEventFingerprint `json:"committed_event_fingerprint"`
	IdempotencyKey            string                    `json:"idempotency_key"`
	SourceWatermark           string                    `json:"source_watermark"`
	ACLWatermark              string                    `json:"acl_watermark"`
	CommittedAt               time.Time                 `json:"committed_at"`
}

func (c ConnectorCheckpoint) Validate() error {
	if c.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported connector checkpoint version %q", c.Version)
	}
	if err := validateEnterpriseFields(
		"tenant_id", c.TenantID,
		"connector_id", c.ConnectorID,
		"committed_event_id", c.CommittedEventID,
		"idempotency_key", c.IdempotencyKey,
		"source_watermark", c.SourceWatermark,
		"acl_watermark", c.ACLWatermark,
	); err != nil {
		return err
	}
	if err := c.CommittedEventFingerprint.Validate(); err != nil {
		return err
	}
	if c.LastSequence == 0 {
		return fmt.Errorf("connector checkpoint last_sequence must be greater than zero")
	}
	return validateUTC("committed_at", c.CommittedAt)
}

// ValidateEvent accepts a new event or an exact replay of the committed event.
// A conflicting event at or behind the checkpoint fails closed.
func (c ConnectorCheckpoint) ValidateEvent(event ConnectorEventEnvelope) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.TenantID != c.TenantID || event.ConnectorID != c.ConnectorID {
		return fmt.Errorf("connector event crosses the checkpoint scope")
	}
	if event.Sequence < c.LastSequence {
		return fmt.Errorf("connector event is older than the committed checkpoint")
	}
	if event.Sequence > c.LastSequence && event.Sequence != c.LastSequence+1 {
		return fmt.Errorf("connector event leaves a sequence gap after the committed checkpoint")
	}
	if event.Sequence == c.LastSequence+1 &&
		(event.EventID == c.CommittedEventID || event.IdempotencyKey == c.IdempotencyKey) {
		return fmt.Errorf("connector event reuses a committed identifier at a new sequence")
	}
	if event.Sequence == c.LastSequence {
		fingerprint, err := NewConnectorEventFingerprint(event)
		if err != nil {
			return err
		}
		if event.EventID != c.CommittedEventID || event.IdempotencyKey != c.IdempotencyKey ||
			event.SourceWatermark != c.SourceWatermark || event.ACLWatermark != c.ACLWatermark ||
			fingerprint != c.CommittedEventFingerprint {
			return fmt.Errorf("connector event conflicts with the committed checkpoint")
		}
	}
	return nil
}

type ConnectorDeliveryState string

const (
	ConnectorDeliveryApplied      ConnectorDeliveryState = "applied"
	ConnectorDeliveryDeadLettered ConnectorDeliveryState = "dead_lettered"
)

type ConnectorDeliveryReceipt struct {
	Version          string                    `json:"version"`
	TenantID         string                    `json:"tenant_id"`
	ConnectorID      string                    `json:"connector_id"`
	EventID          string                    `json:"event_id"`
	EventFingerprint ConnectorEventFingerprint `json:"event_fingerprint"`
	IdempotencyKey   string                    `json:"idempotency_key"`
	Sequence         uint64                    `json:"sequence"`
	State            ConnectorDeliveryState    `json:"state"`
	Attempts         uint32                    `json:"attempts"`
	ErrorCode        string                    `json:"error_code,omitempty"`
	HandledAt        time.Time                 `json:"handled_at"`
}

func (r ConnectorDeliveryReceipt) ValidateFor(event ConnectorEventEnvelope) error {
	if r.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported connector delivery receipt version %q", r.Version)
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseFields(
		"tenant_id", r.TenantID,
		"connector_id", r.ConnectorID,
		"event_id", r.EventID,
		"idempotency_key", r.IdempotencyKey,
	); err != nil {
		return err
	}
	if err := r.EventFingerprint.Validate(); err != nil {
		return err
	}
	fingerprint, err := NewConnectorEventFingerprint(event)
	if err != nil {
		return err
	}
	if r.TenantID != event.TenantID || r.ConnectorID != event.ConnectorID ||
		r.EventID != event.EventID || r.EventFingerprint != fingerprint ||
		r.IdempotencyKey != event.IdempotencyKey || r.Sequence != event.Sequence {
		return fmt.Errorf("connector delivery receipt does not match the event")
	}
	if r.Attempts == 0 {
		return fmt.Errorf("connector delivery receipt attempts must be greater than zero")
	}
	switch r.State {
	case ConnectorDeliveryApplied:
		if r.ErrorCode != "" {
			return fmt.Errorf("applied connector delivery must not contain an error code")
		}
	case ConnectorDeliveryDeadLettered:
		if err := validateEnterpriseID("error_code", r.ErrorCode); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported connector delivery state %q", r.State)
	}
	return validateUTC("handled_at", r.HandledAt)
}

type ConnectorTombstone struct {
	Version          string                    `json:"version"`
	TenantID         string                    `json:"tenant_id"`
	ConnectorID      string                    `json:"connector_id"`
	EventID          string                    `json:"event_id"`
	EventFingerprint ConnectorEventFingerprint `json:"event_fingerprint"`
	IdempotencyKey   string                    `json:"idempotency_key"`
	Sequence         uint64                    `json:"sequence"`
	ResourceID       ResourceID                `json:"resource_id"`
	SourceWatermark  string                    `json:"source_watermark"`
	ACLWatermark     string                    `json:"acl_watermark"`
	ReasonCode       string                    `json:"reason_code"`
	DeletedAt        time.Time                 `json:"deleted_at"`
}

func (t ConnectorTombstone) ValidateFor(event ConnectorEventEnvelope) error {
	if t.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported connector tombstone version %q", t.Version)
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.Kind != ConnectorResourceTombstone {
		return fmt.Errorf("connector tombstone requires a resource_tombstone event")
	}
	if err := validateEnterpriseFields(
		"tenant_id", t.TenantID,
		"connector_id", t.ConnectorID,
		"event_id", t.EventID,
		"idempotency_key", t.IdempotencyKey,
		"source_watermark", t.SourceWatermark,
		"acl_watermark", t.ACLWatermark,
		"reason_code", t.ReasonCode,
	); err != nil {
		return err
	}
	if err := t.EventFingerprint.Validate(); err != nil {
		return err
	}
	if err := t.ResourceID.Validate(); err != nil {
		return err
	}
	fingerprint, err := NewConnectorEventFingerprint(event)
	if err != nil {
		return err
	}
	if t.TenantID != event.TenantID || t.ConnectorID != event.ConnectorID ||
		t.EventID != event.EventID || t.EventFingerprint != fingerprint || t.IdempotencyKey != event.IdempotencyKey ||
		t.Sequence != event.Sequence || t.ResourceID != event.ResourceID ||
		t.SourceWatermark != event.SourceWatermark || t.ACLWatermark != event.ACLWatermark {
		return fmt.Errorf("connector tombstone does not match the event")
	}
	return validateUTC("deleted_at", t.DeletedAt)
}

type AgentTaskScope struct {
	Version              string    `json:"version"`
	TenantID             string    `json:"tenant_id"`
	KnowledgeBaseID      string    `json:"knowledge_base_id"`
	PrincipalID          string    `json:"principal_id"`
	AgentID              string    `json:"agent_id"`
	TaskID               string    `json:"task_id"`
	AuthorizationModelID string    `json:"authorization_model_id"`
	IdentityWatermark    string    `json:"identity_watermark"`
	ACLWatermark         string    `json:"acl_watermark"`
	DelegationWatermark  string    `json:"delegation_watermark"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func (s AgentTaskScope) Validate() error {
	if s.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported agent task scope version %q", s.Version)
	}
	if err := validateEnterpriseFields(
		"tenant_id", s.TenantID,
		"knowledge_base_id", s.KnowledgeBaseID,
		"principal_id", s.PrincipalID,
		"agent_id", s.AgentID,
		"task_id", s.TaskID,
		"authorization_model_id", s.AuthorizationModelID,
		"identity_watermark", s.IdentityWatermark,
		"acl_watermark", s.ACLWatermark,
		"delegation_watermark", s.DelegationWatermark,
	); err != nil {
		return err
	}
	if err := validateUTC("issued_at", s.IssuedAt); err != nil {
		return err
	}
	if err := validateUTC("expires_at", s.ExpiresAt); err != nil {
		return err
	}
	if !s.ExpiresAt.After(s.IssuedAt) {
		return fmt.Errorf("agent task scope expires_at must be after issued_at")
	}
	return nil
}

func (s AgentTaskScope) ValidateFor(auth AuthorizationContext, currentDelegationWatermark string, at time.Time) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseID("current_delegation_watermark", currentDelegationWatermark); err != nil {
		return err
	}
	if err := validateUTC("evaluation_time", at); err != nil {
		return err
	}
	if at.Before(s.IssuedAt) || !at.Before(s.ExpiresAt) {
		return fmt.Errorf("agent task scope is not valid at the evaluation time")
	}
	bindings := []struct {
		name string
		got  string
		want string
	}{
		{"tenant_id", s.TenantID, auth.TenantID},
		{"knowledge_base_id", s.KnowledgeBaseID, auth.KnowledgeBaseID},
		{"principal_id", s.PrincipalID, auth.PrincipalID},
		{"agent_id", s.AgentID, auth.AgentID},
		{"task_id", s.TaskID, auth.TaskID},
		{"authorization_model_id", s.AuthorizationModelID, auth.AuthorizationModelID},
		{"identity_watermark", s.IdentityWatermark, auth.IdentityWatermark},
		{"acl_watermark", s.ACLWatermark, auth.ACLWatermark},
		{"delegation_watermark", s.DelegationWatermark, currentDelegationWatermark},
	}
	for _, binding := range bindings {
		if binding.got != binding.want {
			return fmt.Errorf("agent task scope %s does not match the authorization context", binding.name)
		}
	}
	return nil
}

type AgentTaskScopeFingerprint string

func NewAgentTaskScopeFingerprint(scope AgentTaskScope) (AgentTaskScopeFingerprint, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	parts := []string{
		scope.Version, scope.TenantID, scope.KnowledgeBaseID, scope.PrincipalID,
		scope.AgentID, scope.TaskID, scope.AuthorizationModelID,
		scope.IdentityWatermark, scope.ACLWatermark, scope.DelegationWatermark,
		scope.IssuedAt.Format(time.RFC3339Nano), scope.ExpiresAt.Format(time.RFC3339Nano),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return AgentTaskScopeFingerprint("scope_" + hex.EncodeToString(sum[:16])), nil
}

func (f AgentTaskScopeFingerprint) Validate() error {
	value := string(f)
	if !strings.HasPrefix(value, "scope_") || len(value) != len("scope_")+32 {
		return fmt.Errorf("agent task scope fingerprint must be an opaque scope_ identifier")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, "scope_")); err != nil {
		return fmt.Errorf("agent task scope fingerprint must be hexadecimal: %w", err)
	}
	return nil
}

type ToolInvocationAuthorization struct {
	Version              string                `json:"version"`
	CorrelationID        string                `json:"correlation_id"`
	TenantID             string                `json:"tenant_id"`
	KnowledgeBaseID      string                `json:"knowledge_base_id"`
	PrincipalID          string                `json:"principal_id"`
	AgentID              string                `json:"agent_id,omitempty"`
	TaskID               string                `json:"task_id,omitempty"`
	SessionID            string                `json:"session_id"`
	RequestID            string                `json:"request_id"`
	ToolName             string                `json:"tool_name"`
	Action               string                `json:"action"`
	Relation             string                `json:"relation"`
	AuthorizationModelID string                `json:"authorization_model_id"`
	IdentityWatermark    string                `json:"identity_watermark"`
	ACLWatermark         string                `json:"acl_watermark"`
	SideEffect           bool                  `json:"side_effect"`
	Outcome              DecisionOutcome       `json:"outcome"`
	Consistency          ConsistencyPreference `json:"consistency"`
	CheckedAt            time.Time             `json:"checked_at"`
}

func (a ToolInvocationAuthorization) ValidateFor(auth AuthorizationContext) error {
	if a.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported tool invocation authorization version %q", a.Version)
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseAuthorizationContext(auth); err != nil {
		return err
	}
	if err := validateEnterpriseFields(
		"correlation_id", a.CorrelationID,
		"tool_name", a.ToolName,
		"action", a.Action,
		"relation", a.Relation,
	); err != nil {
		return err
	}
	if a.Outcome != DecisionAllow {
		return fmt.Errorf("tool invocation authorization requires an allow decision")
	}
	if err := validateUTC("checked_at", a.CheckedAt); err != nil {
		return err
	}
	bindings := []struct {
		name string
		got  string
		want string
	}{
		{"tenant_id", a.TenantID, auth.TenantID},
		{"knowledge_base_id", a.KnowledgeBaseID, auth.KnowledgeBaseID},
		{"principal_id", a.PrincipalID, auth.PrincipalID},
		{"agent_id", a.AgentID, auth.AgentID},
		{"task_id", a.TaskID, auth.TaskID},
		{"session_id", a.SessionID, auth.SessionID},
		{"request_id", a.RequestID, auth.RequestID},
		{"authorization_model_id", a.AuthorizationModelID, auth.AuthorizationModelID},
		{"identity_watermark", a.IdentityWatermark, auth.IdentityWatermark},
		{"acl_watermark", a.ACLWatermark, auth.ACLWatermark},
		{"consistency", string(a.Consistency), string(auth.Consistency)},
	}
	for _, binding := range bindings {
		if binding.got != binding.want {
			return fmt.Errorf("tool invocation authorization %s does not match the authorization context", binding.name)
		}
	}
	return nil
}

// ToolResultAuthorization contains handles and content-free allow decisions.
// Protected bodies must remain in EvidencePackage or another exact,
// authorization-bound content container.
type ToolResultAuthorization struct {
	Version              string                  `json:"version"`
	TenantID             string                  `json:"tenant_id"`
	KnowledgeBaseID      string                  `json:"knowledge_base_id"`
	PrincipalID          string                  `json:"principal_id"`
	AgentID              string                  `json:"agent_id,omitempty"`
	TaskID               string                  `json:"task_id,omitempty"`
	SessionID            string                  `json:"session_id"`
	RequestID            string                  `json:"request_id"`
	ToolName             string                  `json:"tool_name"`
	Relation             string                  `json:"relation"`
	AuthorizationModelID string                  `json:"authorization_model_id"`
	IdentityWatermark    string                  `json:"identity_watermark"`
	ACLWatermark         string                  `json:"acl_watermark"`
	Resources            []ResourceHandle        `json:"resources"`
	Decisions            []AuthorizationDecision `json:"decisions"`
}

func (r ToolResultAuthorization) ValidateFor(auth AuthorizationContext) error {
	if r.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported tool result authorization version %q", r.Version)
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseAuthorizationContext(auth); err != nil {
		return err
	}
	if err := validateEnterpriseID("tool_name", r.ToolName); err != nil {
		return err
	}
	if err := validateEnterpriseID("relation", r.Relation); err != nil {
		return err
	}
	bindings := []struct {
		name string
		got  string
		want string
	}{
		{"tenant_id", r.TenantID, auth.TenantID},
		{"knowledge_base_id", r.KnowledgeBaseID, auth.KnowledgeBaseID},
		{"principal_id", r.PrincipalID, auth.PrincipalID},
		{"agent_id", r.AgentID, auth.AgentID},
		{"task_id", r.TaskID, auth.TaskID},
		{"session_id", r.SessionID, auth.SessionID},
		{"request_id", r.RequestID, auth.RequestID},
		{"authorization_model_id", r.AuthorizationModelID, auth.AuthorizationModelID},
		{"identity_watermark", r.IdentityWatermark, auth.IdentityWatermark},
		{"acl_watermark", r.ACLWatermark, auth.ACLWatermark},
	}
	for _, binding := range bindings {
		if binding.got != binding.want {
			return fmt.Errorf("tool result authorization %s does not match the authorization context", binding.name)
		}
	}
	if len(r.Resources) == 0 {
		return fmt.Errorf("tool result authorization requires at least one resource")
	}
	if len(r.Decisions) != len(r.Resources) {
		return fmt.Errorf("tool result authorization requires one decision per resource")
	}
	var previous string
	for index, resource := range r.Resources {
		if err := resource.ValidateFor(auth); err != nil {
			return fmt.Errorf("tool result resource %d: %w", index, err)
		}
		current := string(resource.ResourceID)
		if index > 0 && current <= previous {
			return fmt.Errorf("tool result resources must be sorted by unique resource_id")
		}
		decision := r.Decisions[index]
		if err := decision.ValidateFor(auth); err != nil {
			return fmt.Errorf("tool result decision %d: %w", index, err)
		}
		if err := validateUTC("tool_result_decision_checked_at", decision.CheckedAt); err != nil {
			return fmt.Errorf("tool result decision %d: %w", index, err)
		}
		if !decision.Authorized() {
			return fmt.Errorf("tool result decision %d is not allow", index)
		}
		if decision.Relation != r.Relation {
			return fmt.Errorf("tool result decision %d relation does not match the result", index)
		}
		if decision.Resource != resource {
			return fmt.Errorf("tool result decision %d resource does not match the returned handle", index)
		}
		previous = current
	}
	return nil
}

type PolicySimulationMode string

const PolicySimulationReadOnly PolicySimulationMode = "read_only"

type PolicySimulationRequest struct {
	Version                      string               `json:"version"`
	TenantID                     string               `json:"tenant_id"`
	SimulationID                 string               `json:"simulation_id"`
	RequestID                    string               `json:"request_id"`
	ActorID                      string               `json:"actor_id"`
	Mode                         PolicySimulationMode `json:"mode"`
	BaseAuthorizationModelID     string               `json:"base_authorization_model_id"`
	ProposedAuthorizationModelID string               `json:"proposed_authorization_model_id"`
	BaseIdentityWatermark        string               `json:"base_identity_watermark"`
	ProposedIdentityWatermark    string               `json:"proposed_identity_watermark"`
	BaseACLWatermark             string               `json:"base_acl_watermark"`
	ProposedACLWatermark         string               `json:"proposed_acl_watermark"`
	RequestedAt                  time.Time            `json:"requested_at"`
}

func (r PolicySimulationRequest) ValidateFor(scope TenantScope) error {
	if r.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported policy simulation request version %q", r.Version)
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseFields(
		"tenant_id", r.TenantID,
		"simulation_id", r.SimulationID,
		"request_id", r.RequestID,
		"actor_id", r.ActorID,
		"base_authorization_model_id", r.BaseAuthorizationModelID,
		"proposed_authorization_model_id", r.ProposedAuthorizationModelID,
		"base_identity_watermark", r.BaseIdentityWatermark,
		"proposed_identity_watermark", r.ProposedIdentityWatermark,
		"base_acl_watermark", r.BaseACLWatermark,
		"proposed_acl_watermark", r.ProposedACLWatermark,
	); err != nil {
		return err
	}
	if r.TenantID != scope.TenantID {
		return fmt.Errorf("policy simulation request crosses the tenant scope")
	}
	if r.Mode != PolicySimulationReadOnly {
		return fmt.Errorf("policy simulation mode must be read_only")
	}
	return validateUTC("requested_at", r.RequestedAt)
}

type PolicyImpactKind string

const (
	PolicyImpactGrant         PolicyImpactKind = "grant"
	PolicyImpactRevoke        PolicyImpactKind = "revoke"
	PolicyImpactUnchanged     PolicyImpactKind = "unchanged"
	PolicyImpactIndeterminate PolicyImpactKind = "indeterminate"
)

type PolicyImpactEntry struct {
	CorrelationID string           `json:"correlation_id"`
	SubjectID     string           `json:"subject_id"`
	Relation      string           `json:"relation"`
	Object        string           `json:"object"`
	Kind          PolicyImpactKind `json:"kind"`
	Before        DecisionOutcome  `json:"before"`
	After         DecisionOutcome  `json:"after"`
}

func (e PolicyImpactEntry) Validate() error {
	if err := validateEnterpriseFields(
		"correlation_id", e.CorrelationID,
	); err != nil {
		return err
	}
	if err := validateAuthorizationReference("subject_id", e.SubjectID, true, true); err != nil {
		return err
	}
	if err := validateAuthorizationName("relation", e.Relation); err != nil {
		return err
	}
	if err := validateAuthorizationReference("object", e.Object, false, false); err != nil {
		return err
	}
	if err := validateDecisionOutcome("before", e.Before); err != nil {
		return err
	}
	if err := validateDecisionOutcome("after", e.After); err != nil {
		return err
	}
	switch e.Kind {
	case PolicyImpactGrant:
		if e.Before != DecisionDeny || e.After != DecisionAllow {
			return fmt.Errorf("grant impact must transition from deny to allow")
		}
	case PolicyImpactRevoke:
		if e.Before != DecisionAllow || e.After != DecisionDeny {
			return fmt.Errorf("revoke impact must transition from allow to deny")
		}
	case PolicyImpactUnchanged:
		if e.Before != e.After || e.Before == DecisionIndeterminate {
			return fmt.Errorf("unchanged impact must preserve a determinate outcome")
		}
	case PolicyImpactIndeterminate:
		if e.Before != DecisionIndeterminate && e.After != DecisionIndeterminate {
			return fmt.Errorf("indeterminate impact requires an indeterminate outcome")
		}
	default:
		return fmt.Errorf("unsupported policy impact kind %q", e.Kind)
	}
	return nil
}

type PolicyImpactReport struct {
	Version      string              `json:"version"`
	TenantID     string              `json:"tenant_id"`
	SimulationID string              `json:"simulation_id"`
	GeneratedAt  time.Time           `json:"generated_at"`
	Entries      []PolicyImpactEntry `json:"entries"`
}

func (r PolicyImpactReport) ValidateFor(request PolicySimulationRequest, scope TenantScope) error {
	if r.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported policy impact report version %q", r.Version)
	}
	if err := request.ValidateFor(scope); err != nil {
		return err
	}
	if r.TenantID != request.TenantID || r.SimulationID != request.SimulationID {
		return fmt.Errorf("policy impact report does not match the simulation request")
	}
	if err := validateUTC("generated_at", r.GeneratedAt); err != nil {
		return err
	}
	if len(r.Entries) == 0 {
		return fmt.Errorf("policy impact report requires at least one entry")
	}
	var previous string
	for index, entry := range r.Entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("policy impact entry %d: %w", index, err)
		}
		if index > 0 && entry.CorrelationID <= previous {
			return fmt.Errorf("policy impact entries must be sorted by unique correlation_id")
		}
		for prior := 0; prior < index; prior++ {
			candidate := r.Entries[prior]
			if entry.SubjectID == candidate.SubjectID && entry.Relation == candidate.Relation && entry.Object == candidate.Object {
				return fmt.Errorf("policy impact entries must use unique subject, relation, and object tuples")
			}
		}
		previous = entry.CorrelationID
	}
	return nil
}

// AuditRecordReference deliberately excludes prompts, resource bodies, titles,
// paths, credentials, assertions, and graph structure.
type AuditRecordReference struct {
	Version        string          `json:"version"`
	TenantID       string          `json:"tenant_id"`
	RecordID       string          `json:"record_id"`
	CorrelationID  string          `json:"correlation_id"`
	ActorID        string          `json:"actor_id"`
	Action         string          `json:"action"`
	Outcome        DecisionOutcome `json:"outcome"`
	PreviousDigest ContentDigest   `json:"previous_digest"`
	RecordDigest   ContentDigest   `json:"record_digest"`
	RecordedAt     time.Time       `json:"recorded_at"`
}

func (r AuditRecordReference) ValidateFor(scope TenantScope) error {
	if r.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported audit record reference version %q", r.Version)
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseFields(
		"tenant_id", r.TenantID,
		"record_id", r.RecordID,
		"correlation_id", r.CorrelationID,
		"actor_id", r.ActorID,
		"action", r.Action,
	); err != nil {
		return err
	}
	if r.TenantID != scope.TenantID {
		return fmt.Errorf("audit record reference crosses the tenant scope")
	}
	if err := validateDecisionOutcome("audit outcome", r.Outcome); err != nil {
		return err
	}
	if err := r.PreviousDigest.Validate(); err != nil {
		return fmt.Errorf("previous audit digest: %w", err)
	}
	if err := r.RecordDigest.Validate(); err != nil {
		return fmt.Errorf("audit record digest: %w", err)
	}
	return validateUTC("recorded_at", r.RecordedAt)
}

type ResidencyOperationKind string

const (
	ResidencyStore   ResidencyOperationKind = "store"
	ResidencyProcess ResidencyOperationKind = "process"
	ResidencyEgress  ResidencyOperationKind = "egress"
)

type ResidencyDataClass string

const (
	ResidencyProtectedContent ResidencyDataClass = "protected_content"
	ResidencyIdentity         ResidencyDataClass = "identity"
	ResidencyACL              ResidencyDataClass = "acl"
	ResidencyAudit            ResidencyDataClass = "audit"
	ResidencyTelemetry        ResidencyDataClass = "telemetry"
	ResidencyBackup           ResidencyDataClass = "backup"
)

type ResidencyPolicy struct {
	Version           string   `json:"version"`
	TenantID          string   `json:"tenant_id"`
	HomeRegion        string   `json:"home_region"`
	StorageRegions    []string `json:"storage_regions"`
	ProcessingRegions []string `json:"processing_regions"`
	EgressRegions     []string `json:"egress_regions"`
	PolicyWatermark   string   `json:"policy_watermark"`
}

func (p ResidencyPolicy) ValidateFor(scope TenantScope) error {
	if p.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported residency policy version %q", p.Version)
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEnterpriseID("tenant_id", p.TenantID); err != nil {
		return err
	}
	if p.TenantID != scope.TenantID {
		return fmt.Errorf("residency policy crosses the tenant scope")
	}
	if err := validateRegion("home_region", p.HomeRegion); err != nil {
		return err
	}
	if p.HomeRegion != scope.Region {
		return fmt.Errorf("residency policy home_region does not match the tenant scope")
	}
	if err := validateRegionList("storage_regions", p.StorageRegions, true); err != nil {
		return err
	}
	if err := validateRegionList("processing_regions", p.ProcessingRegions, true); err != nil {
		return err
	}
	if err := validateRegionList("egress_regions", p.EgressRegions, false); err != nil {
		return err
	}
	if !containsString(p.StorageRegions, p.HomeRegion) || !containsString(p.ProcessingRegions, p.HomeRegion) {
		return fmt.Errorf("residency policy home_region must allow storage and processing")
	}
	return validateEnterpriseID("policy_watermark", p.PolicyWatermark)
}

type ResidencyCheckRequest struct {
	Version           string                 `json:"version"`
	TenantID          string                 `json:"tenant_id"`
	RequestID         string                 `json:"request_id"`
	Operation         ResidencyOperationKind `json:"operation"`
	DataClass         ResidencyDataClass     `json:"data_class"`
	DestinationRegion string                 `json:"destination_region"`
	PolicyWatermark   string                 `json:"policy_watermark"`
}

func (r ResidencyCheckRequest) ValidateFor(policy ResidencyPolicy, scope TenantScope) error {
	if r.Version != EnterpriseContractVersion {
		return fmt.Errorf("unsupported residency check request version %q", r.Version)
	}
	if err := policy.ValidateFor(scope); err != nil {
		return err
	}
	if err := validateEnterpriseFields(
		"tenant_id", r.TenantID,
		"request_id", r.RequestID,
		"policy_watermark", r.PolicyWatermark,
	); err != nil {
		return err
	}
	if r.TenantID != policy.TenantID || r.PolicyWatermark != policy.PolicyWatermark {
		return fmt.Errorf("residency check request does not match the active policy")
	}
	if err := validateRegion("destination_region", r.DestinationRegion); err != nil {
		return err
	}
	switch r.DataClass {
	case ResidencyProtectedContent, ResidencyIdentity, ResidencyACL, ResidencyAudit, ResidencyTelemetry, ResidencyBackup:
	default:
		return fmt.Errorf("unsupported residency data class %q", r.DataClass)
	}
	var allowed []string
	switch r.Operation {
	case ResidencyStore:
		allowed = policy.StorageRegions
	case ResidencyProcess:
		allowed = policy.ProcessingRegions
	case ResidencyEgress:
		allowed = policy.EgressRegions
	default:
		return fmt.Errorf("unsupported residency operation %q", r.Operation)
	}
	if !containsString(allowed, r.DestinationRegion) {
		return fmt.Errorf("residency policy denies the destination region")
	}
	return nil
}

func validateEnterpriseID(name, value string) error {
	if err := validateToken(name, value); err != nil {
		return err
	}
	if len(value) > 128 {
		return fmt.Errorf("%s is too long", name)
	}
	for index, character := range []byte(value) {
		allowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' || character == ':' || character == '@'
		if !allowed || index == 0 && !isASCIIAlphaNumeric(character) {
			return fmt.Errorf("%s must be a canonical opaque identifier", name)
		}
	}
	return nil
}

func validateEnterpriseFields(fields ...string) error {
	if len(fields)%2 != 0 {
		return fmt.Errorf("enterprise field validation requires name and value pairs")
	}
	for index := 0; index < len(fields); index += 2 {
		if err := validateEnterpriseID(fields[index], fields[index+1]); err != nil {
			return err
		}
	}
	return nil
}

func validateEnterpriseAuthorizationContext(auth AuthorizationContext) error {
	if err := validateEnterpriseFields(
		"tenant_id", auth.TenantID,
		"knowledge_base_id", auth.KnowledgeBaseID,
		"principal_id", auth.PrincipalID,
		"session_id", auth.SessionID,
		"request_id", auth.RequestID,
		"authorization_model_id", auth.AuthorizationModelID,
		"identity_watermark", auth.IdentityWatermark,
		"acl_watermark", auth.ACLWatermark,
	); err != nil {
		return err
	}
	if auth.AgentID != "" {
		if err := validateEnterpriseID("agent_id", auth.AgentID); err != nil {
			return err
		}
	}
	if auth.TaskID != "" {
		if err := validateEnterpriseID("task_id", auth.TaskID); err != nil {
			return err
		}
	}
	return nil
}

func validateAuthorizationReference(name, value string, allowUserset, allowWildcard bool) error {
	if value == "" || len(value) > 256 {
		return fmt.Errorf("%s is empty or too long", name)
	}
	base, usersetRelation, hasUserset := strings.Cut(value, "#")
	if hasUserset {
		if !allowUserset || strings.Contains(usersetRelation, "#") {
			return fmt.Errorf("%s has an invalid userset", name)
		}
		if err := validateAuthorizationName(name+" userset relation", usersetRelation); err != nil {
			return err
		}
	}
	typeName, id, ok := strings.Cut(base, ":")
	if !ok || id == "" || strings.Contains(id, ":") {
		return fmt.Errorf("%s must be type:opaque-id", name)
	}
	if err := validateAuthorizationName(name+" type", typeName); err != nil {
		return err
	}
	if id == "*" && !allowWildcard {
		return fmt.Errorf("%s cannot be a wildcard", name)
	}
	for _, character := range id {
		if unicode.IsSpace(character) || unicode.IsControl(character) || character == '#' {
			return fmt.Errorf("%s contains invalid characters", name)
		}
	}
	return nil
}

func validateAuthorizationName(name, value string) error {
	if value == "" || len(value) > 64 {
		return fmt.Errorf("%s is empty or too long", name)
	}
	for index, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z' || index > 0 && (character >= '0' && character <= '9' || character == '_')) {
			return fmt.Errorf("%s must be a canonical authorization name", name)
		}
	}
	return nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func validateRegion(name, value string) error {
	if err := validateToken(name, value); err != nil {
		return err
	}
	if len(value) > 32 {
		return fmt.Errorf("%s is too long", name)
	}
	for index, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && character == '-') {
			return fmt.Errorf("%s must be a canonical lowercase region", name)
		}
	}
	return nil
}

func validateUTC(name string, value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("%s is required", name)
	}
	_, offset := value.Zone()
	if offset != 0 {
		return fmt.Errorf("%s must be UTC", name)
	}
	return nil
}

func validateSortedEnterpriseIDs(name string, values []string, requireOne bool) error {
	if !requireOne && values == nil {
		return fmt.Errorf("%s must use an explicit empty list", name)
	}
	if requireOne && len(values) == 0 {
		return fmt.Errorf("%s requires at least one value", name)
	}
	var previous string
	for index, value := range values {
		if err := validateEnterpriseID(name, value); err != nil {
			return err
		}
		if index > 0 && value <= previous {
			return fmt.Errorf("%s must be sorted and unique", name)
		}
		previous = value
	}
	return nil
}

func validateRegionList(name string, values []string, requireOne bool) error {
	if !requireOne && values == nil {
		return fmt.Errorf("%s must use an explicit empty list", name)
	}
	if requireOne && len(values) == 0 {
		return fmt.Errorf("%s requires at least one region", name)
	}
	var previous string
	for index, value := range values {
		if err := validateRegion(name, value); err != nil {
			return err
		}
		if index > 0 && value <= previous {
			return fmt.Errorf("%s must be sorted and unique", name)
		}
		previous = value
	}
	return nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validateDecisionOutcome(name string, outcome DecisionOutcome) error {
	switch outcome {
	case DecisionAllow, DecisionDeny, DecisionIndeterminate:
		return nil
	default:
		return fmt.Errorf("unsupported %s %q", name, outcome)
	}
}
