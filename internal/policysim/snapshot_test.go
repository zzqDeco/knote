package policysim

import (
	"errors"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestSnapshotCopiesAndValidatesCompletePins(t *testing.T) {
	pins := testBasePins()
	snapshot, err := NewSnapshot(pins)
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}

	pins.AuthorizationModelID = "changed-after-construction"
	if got := snapshot.Pins().AuthorizationModelID; got != "model-v1" {
		t.Fatalf("snapshot changed with constructor input: %q", got)
	}
	copyOfPins := snapshot.Pins()
	copyOfPins.IdentityWatermark = "changed-copy"
	if got := snapshot.Pins().IdentityWatermark; got != "identity-v1" {
		t.Fatalf("snapshot changed through Pins result: %q", got)
	}

	tests := []struct {
		name   string
		mutate func(*SnapshotPins)
	}{
		{name: "tenant", mutate: func(p *SnapshotPins) { p.TenantID = "" }},
		{name: "agent", mutate: func(p *SnapshotPins) { p.AgentID = "" }},
		{name: "task", mutate: func(p *SnapshotPins) { p.TaskID = "" }},
		{name: "authorization model", mutate: func(p *SnapshotPins) { p.AuthorizationModelID = "" }},
		{name: "identity", mutate: func(p *SnapshotPins) { p.IdentityWatermark = "" }},
		{name: "acl", mutate: func(p *SnapshotPins) { p.ACLWatermark = "" }},
		{name: "delegation", mutate: func(p *SnapshotPins) { p.DelegationWatermark = "" }},
		{name: "agent task fingerprint", mutate: func(p *SnapshotPins) {
			p.AgentTaskScopeFingerprint = protocol.AgentTaskScopeFingerprint("scope_invalid")
		}},
		{name: "connector", mutate: func(p *SnapshotPins) { p.ConnectorWatermark = "" }},
		{name: "residency", mutate: func(p *SnapshotPins) { p.ResidencyWatermark = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := testBasePins()
			test.mutate(&invalid)
			if _, err := NewSnapshot(invalid); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}
