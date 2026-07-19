package governance

import (
	"context"
	"errors"
	"fmt"

	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	ErrDenied      = errors.New("governance access denied")
	ErrUnavailable = errors.New("governance unavailable")
)

type Visibility struct {
	TenantStatus        bool
	ConnectorSummary    bool
	ConnectorDetails    bool
	SimulationSummary   bool
	SimulationDetails   bool
	AuditReferences     bool
	ResidencyViolations bool
}

func (v Visibility) any() bool {
	return v.TenantStatus || v.ConnectorSummary || v.ConnectorDetails || v.SimulationSummary ||
		v.SimulationDetails || v.AuditReferences || v.ResidencyViolations
}

func (v Visibility) validate() error {
	if v.ConnectorDetails && !v.ConnectorSummary {
		return fmt.Errorf("connector details require connector summary visibility")
	}
	if v.SimulationDetails && !v.SimulationSummary {
		return fmt.Errorf("simulation details require simulation summary visibility")
	}
	return nil
}

type Authorizer interface {
	Authorize(context.Context, protocol.AuthorizationContext) (Visibility, error)
}

type AuthorizerFunc func(context.Context, protocol.AuthorizationContext) (Visibility, error)

func (f AuthorizerFunc) Authorize(ctx context.Context, auth protocol.AuthorizationContext) (Visibility, error) {
	return f(ctx, auth)
}

type Source interface {
	Load(context.Context, protocol.AuthorizationContext) (RawSnapshot, error)
}

type SourceFunc func(context.Context, protocol.AuthorizationContext) (RawSnapshot, error)

func (f SourceFunc) Load(ctx context.Context, auth protocol.AuthorizationContext) (RawSnapshot, error) {
	return f(ctx, auth)
}

type Service struct {
	authorizer Authorizer
	source     Source
}

func New(authorizer Authorizer, source Source) (*Service, error) {
	if authorizer == nil || source == nil {
		return nil, fmt.Errorf("%w: authorizer and source are required", ErrUnavailable)
	}
	return &Service{authorizer: authorizer, source: source}, nil
}

func (s *Service) View(ctx context.Context, auth protocol.AuthorizationContext) (Snapshot, error) {
	if s == nil || s.authorizer == nil || s.source == nil || ctx == nil {
		return Snapshot{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := auth.Validate(); err != nil {
		return Snapshot{}, ErrDenied
	}
	visibility, err := s.authorizer.Authorize(ctx, auth)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: authorization failed", ErrUnavailable)
	}
	if err := visibility.validate(); err != nil {
		return Snapshot{}, fmt.Errorf("%w: invalid visibility", ErrUnavailable)
	}
	if !visibility.any() {
		return Snapshot{}, ErrDenied
	}
	raw, err := s.source.Load(ctx, auth)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: source failed", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := raw.validateFor(auth); err != nil {
		return Snapshot{}, fmt.Errorf("%w: source integrity", ErrUnavailable)
	}
	raw = canonicalize(raw)
	view := Snapshot{Version: SnapshotVersion, TenantID: auth.TenantID, GeneratedAt: raw.GeneratedAt}
	if visibility.TenantStatus {
		tenant := raw.Tenant
		view.Tenant = &tenant
	}
	if visibility.ConnectorSummary {
		section := ConnectorSection{Total: uint64(len(raw.Connectors))}
		for _, connector := range raw.Connectors {
			if connector.State == ConnectorBlocked {
				section.Blocked++
			}
		}
		if visibility.ConnectorDetails {
			section.Items = raw.Connectors
		}
		view.Connectors = &section
	}
	if visibility.SimulationSummary {
		section := SimulationSection{Total: uint64(len(raw.Simulations))}
		if visibility.SimulationDetails {
			section.Items = raw.Simulations
		}
		view.Simulations = &section
	}
	if visibility.AuditReferences {
		view.Audit = &AuditSection{Total: uint64(len(raw.AuditReferences)), References: raw.AuditReferences}
	}
	if visibility.ResidencyViolations {
		view.Residency = &ResidencySection{Total: uint64(len(raw.ResidencyViolations)), Violations: raw.ResidencyViolations}
	}
	return view, nil
}

var _ interface {
	View(context.Context, protocol.AuthorizationContext) (Snapshot, error)
} = (*Service)(nil)
