package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/governance"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

type governanceProviderFunc func(context.Context, protocol.AuthorizationContext) (governance.Snapshot, error)

func (f governanceProviderFunc) View(ctx context.Context, auth protocol.AuthorizationContext) (governance.Snapshot, error) {
	return f(ctx, auth)
}

func TestGovernanceSlashUsesTrustedAuthorizationAndContentFreeOverlay(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	calls := 0
	rt := New(Dependencies{
		Workspace: workspace, Capabilities: PermissionedSessionCapabilityProfile(), Sessions: store,
		EinoRunner: &fakeEinoRunner{events: []protocol.Event{
			protocol.NewEvent(protocol.EventAssistantDone, "", "unused", nil),
		}}, AuthorizationContextProvider: testAuthorizationContextProvider,
		Governance: governanceProviderFunc(func(_ context.Context, auth protocol.AuthorizationContext) (governance.Snapshot, error) {
			calls++
			if auth.SessionID == "" || auth.TenantID != "local" {
				t.Fatalf("governance received untrusted authorization: %+v", auth)
			}
			return governance.Snapshot{
				Version: governance.SnapshotVersion, TenantID: auth.TenantID,
				GeneratedAt: time.Date(2026, time.July, 19, 6, 0, 0, 0, time.UTC),
				Tenant: &governance.TenantStatus{
					Scope:                protocol.TenantScope{Version: protocol.EnterpriseContractVersion, TenantID: auth.TenantID, Region: "local"},
					AuthorizationModelID: auth.AuthorizationModelID, IdentityWatermark: auth.IdentityWatermark,
					ACLWatermark: auth.ACLWatermark, DelegationWatermark: auth.DelegationWatermark,
					ConnectorWatermark: "connector-v1", ResidencyPolicyWatermark: "residency-v1",
				},
			}, nil
		}),
		NewSessionID: func() string { return "session-governance" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events, _ := rt.SendMessage(context.Background(), "/governance")
	if calls != 1 {
		t.Fatalf("governance provider calls = %d, want 1", calls)
	}
	var found bool
	for _, event := range events {
		if event.Type != protocol.EventAssistantDone {
			continue
		}
		found = true
		if !strings.Contains(event.Message, "governance") || eventOverlayForTest(event.Payload) != "governance" {
			t.Fatalf("governance event = %+v", event)
		}
	}
	if !found {
		t.Fatalf("governance event missing: %+v", events)
	}
}

func TestGovernanceSlashSuppressesProviderFailuresAndPersistsNoCanary(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	const canary = "PROTECTED GOVERNANCE FAILURE CANARY"
	rt := New(Dependencies{
		Workspace: workspace, Capabilities: PermissionedSessionCapabilityProfile(), Sessions: store,
		EinoRunner: &fakeEinoRunner{events: []protocol.Event{
			protocol.NewEvent(protocol.EventAssistantDone, "", "unused", nil),
		}}, AuthorizationContextProvider: testAuthorizationContextProvider,
		Governance: governanceProviderFunc(func(context.Context, protocol.AuthorizationContext) (governance.Snapshot, error) {
			return governance.Snapshot{}, errors.New(canary)
		}),
		NewSessionID: func() string { return "session-governance-denied" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}
	events, _ := rt.SendMessage(context.Background(), "/governance")
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) || !strings.Contains(string(encoded), governanceUnavailableMessage) {
		t.Fatalf("governance failure surface = %s", encoded)
	}
	persisted, err := store.Load(context.Background(), rt.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Fatalf("persisted governance events leaked provider failure: %s", encoded)
	}
}

func eventOverlayForTest(payload any) string {
	data, _ := json.Marshal(payload)
	var value map[string]any
	_ = json.Unmarshal(data, &value)
	overlay, _ := value["overlay"].(string)
	return overlay
}
