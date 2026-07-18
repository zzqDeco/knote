package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSessionAuthorizationEnvelopeValidationAndMatch(t *testing.T) {
	auth := testAuthorizationContext()
	boundAt := time.Date(2026, time.July, 13, 8, 9, 10, 11, time.FixedZone("offset", 8*60*60))
	envelope, err := NewSessionAuthorizationEnvelope(auth, boundAt)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.BoundAt.Location() != time.UTC || !envelope.BoundAt.Equal(boundAt) {
		t.Fatalf("bound_at was not normalized to UTC: %s", envelope.BoundAt)
	}
	if err := envelope.ValidateFor(auth); err != nil {
		t.Fatalf("valid envelope did not match authorization context: %v", err)
	}
	if envelope.DelegationWatermark != auth.DelegationWatermark ||
		envelope.AgentTaskScopeFingerprint != auth.AgentTaskScopeFingerprint {
		t.Fatal("durable envelope did not preserve the exact agent task binding")
	}

	otherRequest := auth
	otherRequest.RequestID = "request-2"
	if err := envelope.ValidateFor(otherRequest); err != nil {
		t.Fatalf("request_id must not be part of the durable binding: %v", err)
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"request_id", "body", "title"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("envelope JSON contains forbidden field %q: %s", forbidden, data)
		}
	}
	for _, required := range []string{"delegation_watermark", "agent_task_scope_fingerprint"} {
		if !strings.Contains(string(data), `"`+required+`"`) {
			t.Fatalf("delegated envelope JSON is missing %q: %s", required, data)
		}
	}
}

func TestSessionAuthorizationEnvelopeRejectsInvalidValues(t *testing.T) {
	valid, err := NewSessionAuthorizationEnvelope(testAuthorizationContext(), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*SessionAuthorizationEnvelope){
		"version":                 func(value *SessionAuthorizationEnvelope) { value.Version = "" },
		"unsupported version":     func(value *SessionAuthorizationEnvelope) { value.Version = "v2" },
		"tenant":                  func(value *SessionAuthorizationEnvelope) { value.TenantID = "" },
		"knowledge base":          func(value *SessionAuthorizationEnvelope) { value.KnowledgeBaseID = "" },
		"principal":               func(value *SessionAuthorizationEnvelope) { value.PrincipalID = "" },
		"session":                 func(value *SessionAuthorizationEnvelope) { value.SessionID = "" },
		"authorization model":     func(value *SessionAuthorizationEnvelope) { value.AuthorizationModelID = "" },
		"identity watermark":      func(value *SessionAuthorizationEnvelope) { value.IdentityWatermark = "" },
		"authorization watermark": func(value *SessionAuthorizationEnvelope) { value.ACLWatermark = "" },
		"agent":                   func(value *SessionAuthorizationEnvelope) { value.AgentID = " bad" },
		"task":                    func(value *SessionAuthorizationEnvelope) { value.TaskID = "bad\n" },
		"delegation watermark":    func(value *SessionAuthorizationEnvelope) { value.DelegationWatermark = "bad\n" },
		"scope fingerprint": func(value *SessionAuthorizationEnvelope) {
			value.AgentTaskScopeFingerprint = "scope_invalid"
		},
		"consistency": func(value *SessionAuthorizationEnvelope) { value.Consistency = "eventual" },
		"bound at":    func(value *SessionAuthorizationEnvelope) { value.BoundAt = time.Time{} },
		"non-UTC bound at": func(value *SessionAuthorizationEnvelope) {
			value.BoundAt = value.BoundAt.In(time.FixedZone("offset", 60*60))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid envelope was accepted")
			}
		})
	}

	invalidAuth := testAuthorizationContext()
	invalidAuth.RequestID = ""
	if _, err := NewSessionAuthorizationEnvelope(invalidAuth, time.Now()); err == nil {
		t.Fatal("invalid authorization context was accepted")
	}
	if _, err := NewSessionAuthorizationEnvelope(testAuthorizationContext(), time.Time{}); err == nil {
		t.Fatal("zero bound_at was accepted")
	}
}

func TestSessionAuthorizationEnvelopeAgentTaskBindingIsAllOrNone(t *testing.T) {
	delegated, err := NewSessionAuthorizationEnvelope(testAuthorizationContext(), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	missing := map[string]func(*SessionAuthorizationEnvelope){
		"agent":                func(value *SessionAuthorizationEnvelope) { value.AgentID = "" },
		"task":                 func(value *SessionAuthorizationEnvelope) { value.TaskID = "" },
		"delegation watermark": func(value *SessionAuthorizationEnvelope) { value.DelegationWatermark = "" },
		"scope fingerprint": func(value *SessionAuthorizationEnvelope) {
			value.AgentTaskScopeFingerprint = ""
		},
	}
	for name, mutate := range missing {
		t.Run("missing "+name, func(t *testing.T) {
			candidate := delegated
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("partial delegated session envelope was accepted")
			}
		})
	}

	directAuth := testDirectAuthorizationContext()
	direct, err := NewSessionAuthorizationEnvelope(directAuth, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("direct-user envelope: %v", err)
	}
	if err := direct.ValidateFor(directAuth); err != nil {
		t.Fatalf("direct-user envelope binding: %v", err)
	}
	data, err := json.Marshal(direct)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"agent_id", "task_id", "delegation_watermark", "agent_task_scope_fingerprint"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Fatalf("direct-user envelope JSON contains delegated field %q: %s", field, data)
		}
	}

	legacyPartial := direct
	legacyPartial.AgentID = delegated.AgentID
	legacyPartial.TaskID = delegated.TaskID
	if err := legacyPartial.Validate(); err == nil {
		t.Fatal("legacy session envelope with only agent and task IDs was accepted")
	}
}

func TestSessionAuthorizationEnvelopeRejectsAuthorizationMismatch(t *testing.T) {
	auth := testAuthorizationContext()
	envelope, err := NewSessionAuthorizationEnvelope(auth, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*AuthorizationContext){
		"tenant":              func(value *AuthorizationContext) { value.TenantID = "other" },
		"knowledge base":      func(value *AuthorizationContext) { value.KnowledgeBaseID = "other" },
		"principal":           func(value *AuthorizationContext) { value.PrincipalID = "other" },
		"session":             func(value *AuthorizationContext) { value.SessionID = "other" },
		"authorization model": func(value *AuthorizationContext) { value.AuthorizationModelID = "other" },
		"identity watermark":  func(value *AuthorizationContext) { value.IdentityWatermark = "other" },
		"acl watermark":       func(value *AuthorizationContext) { value.ACLWatermark = "other" },
		"agent":               func(value *AuthorizationContext) { value.AgentID = "other" },
		"task":                func(value *AuthorizationContext) { value.TaskID = "other" },
		"delegation watermark": func(value *AuthorizationContext) {
			value.DelegationWatermark = "other"
		},
		"scope fingerprint": func(value *AuthorizationContext) {
			value.AgentTaskScopeFingerprint = "scope_ffffffffffffffffffffffffffffffff"
		},
		"consistency": func(value *AuthorizationContext) {
			value.Consistency = ConsistencyMinimizeLatency
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := auth
			mutate(&candidate)
			if err := envelope.ValidateFor(candidate); err == nil {
				t.Fatal("authorization mismatch was accepted")
			}
		})
	}

	tamperedDelegation := envelope
	tamperedDelegation.DelegationWatermark = "delegation-v2"
	if err := tamperedDelegation.ValidateFor(auth); err == nil {
		t.Fatal("well-formed delegation watermark tampering was accepted")
	}
	tamperedFingerprint := envelope
	tamperedFingerprint.AgentTaskScopeFingerprint = "scope_ffffffffffffffffffffffffffffffff"
	if err := tamperedFingerprint.ValidateFor(auth); err == nil {
		t.Fatal("well-formed scope fingerprint tampering was accepted")
	}
}
