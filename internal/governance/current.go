package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type CurrentSourceOptions struct {
	Region                   string
	ConnectorWatermark       string
	ResidencyPolicyWatermark string
	Now                      func() time.Time
}

type CurrentSource struct {
	options CurrentSourceOptions
}

func NewCurrentSource(options CurrentSourceOptions) (*CurrentSource, error) {
	if err := validateRegion(options.Region); err != nil {
		return nil, err
	}
	if err := validateID("connector_watermark", options.ConnectorWatermark); err != nil {
		return nil, err
	}
	if err := validateID("residency_policy_watermark", options.ResidencyPolicyWatermark); err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	return &CurrentSource{options: options}, nil
}

func (s *CurrentSource) Load(ctx context.Context, auth protocol.AuthorizationContext) (RawSnapshot, error) {
	if s == nil || ctx == nil {
		return RawSnapshot{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return RawSnapshot{}, err
	}
	now := s.options.Now()
	if err := validateUTC("generated_at", now); err != nil {
		return RawSnapshot{}, fmt.Errorf("%w: clock", ErrUnavailable)
	}
	return RawSnapshot{
		Version: SnapshotVersion, GeneratedAt: now,
		Tenant: TenantStatus{
			Scope:                protocol.TenantScope{Version: protocol.EnterpriseContractVersion, TenantID: auth.TenantID, Region: s.options.Region},
			AuthorizationModelID: auth.AuthorizationModelID, IdentityWatermark: auth.IdentityWatermark,
			ACLWatermark: auth.ACLWatermark, DelegationWatermark: auth.DelegationWatermark,
			ConnectorWatermark:       s.options.ConnectorWatermark,
			ResidencyPolicyWatermark: s.options.ResidencyPolicyWatermark,
		},
		Connectors: []ConnectorHealth{}, Simulations: []SimulationSummary{},
		AuditReferences: []protocol.AuditRecordReference{}, ResidencyViolations: []ResidencyViolation{},
	}, nil
}

var _ Source = (*CurrentSource)(nil)
