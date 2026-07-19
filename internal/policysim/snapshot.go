package policysim

import (
	"errors"
	"fmt"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var ErrInvalidSnapshot = errors.New("invalid policy simulation snapshot")

// SnapshotPins identifies one complete, immutable governance policy snapshot.
// It deliberately contains only control-plane references, never policy bodies
// or serving state.
type SnapshotPins struct {
	TenantID                  string
	AgentID                   string
	TaskID                    string
	AuthorizationModelID      string
	IdentityWatermark         string
	ACLWatermark              string
	DelegationWatermark       string
	AgentTaskScopeFingerprint protocol.AgentTaskScopeFingerprint
	ConnectorWatermark        string
	ResidencyWatermark        string
}

// Snapshot is an immutable copy of a complete set of governance pins. The
// zero value is invalid and is rejected by Engine.Simulate.
type Snapshot struct {
	pins SnapshotPins
}

// NewSnapshot validates and copies pins into an immutable snapshot.
func NewSnapshot(pins SnapshotPins) (Snapshot, error) {
	if err := validateSnapshotPins(pins); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	return Snapshot{pins: pins}, nil
}

// Pins returns a value copy of the snapshot pins.
func (s Snapshot) Pins() SnapshotPins {
	return s.pins
}

func validateSnapshotPins(pins SnapshotPins) error {
	// Reuse the shared v2 contract validator so snapshot pin syntax cannot drift
	// from policy simulation request syntax.
	scope := protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: pins.TenantID,
		Region:   "snapshot-validation",
	}
	request := protocol.PolicySimulationRequest{
		Version:                      protocol.GovernanceContractVersion,
		TenantID:                     pins.TenantID,
		SimulationID:                 "snapshot-validation",
		RequestID:                    "snapshot-validation",
		ActorID:                      "snapshot-validation",
		Mode:                         protocol.PolicySimulationReadOnly,
		AgentID:                      pins.AgentID,
		TaskID:                       pins.TaskID,
		BaseAuthorizationModelID:     pins.AuthorizationModelID,
		ProposedAuthorizationModelID: pins.AuthorizationModelID,
		BaseIdentityWatermark:        pins.IdentityWatermark,
		ProposedIdentityWatermark:    pins.IdentityWatermark,
		BaseACLWatermark:             pins.ACLWatermark,
		ProposedACLWatermark:         pins.ACLWatermark,
		BaseDelegationWatermark:      pins.DelegationWatermark,
		ProposedDelegationWatermark:  pins.DelegationWatermark,
		BaseAgentTaskScope:           pins.AgentTaskScopeFingerprint,
		ProposedAgentTaskScope:       pins.AgentTaskScopeFingerprint,
		BaseConnectorWatermark:       pins.ConnectorWatermark,
		ProposedConnectorWatermark:   pins.ConnectorWatermark,
		BaseResidencyWatermark:       pins.ResidencyWatermark,
		ProposedResidencyWatermark:   pins.ResidencyWatermark,
		RequestedAt:                  time.Unix(0, 0).UTC(),
	}
	return request.ValidateFor(scope)
}
