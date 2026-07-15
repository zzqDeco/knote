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
		"consistency":             func(value *SessionAuthorizationEnvelope) { value.Consistency = "eventual" },
		"bound at":                func(value *SessionAuthorizationEnvelope) { value.BoundAt = time.Time{} },
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
}
