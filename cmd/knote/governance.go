package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/zzqDeco/knote/internal/governance"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

const (
	governanceRegionEnv             = "KNOTE_GOVERNANCE_REGION"
	governanceConnectorWatermarkEnv = "KNOTE_GOVERNANCE_CONNECTOR_WATERMARK"
	governanceResidencyWatermarkEnv = "KNOTE_GOVERNANCE_RESIDENCY_WATERMARK"
)

func newGovernanceProvider(application *permissionedApplication) (runtime.GovernanceProvider, error) {
	if application == nil || application.GovernanceAuthorizer() == nil || application.residency == nil {
		return nil, fmt.Errorf("initialize governance: permissioned authorizer is required")
	}
	authorizer, err := governance.NewKnowledgeBaseEditorAuthorizer(application.GovernanceAuthorizer())
	if err != nil {
		return nil, fmt.Errorf("initialize governance authorizer: %w", err)
	}
	current, err := governance.NewCurrentSource(governance.CurrentSourceOptions{
		Region:                   application.residency.Region(),
		ConnectorWatermark:       governanceSetting(governanceConnectorWatermarkEnv, "connector-unconfigured-v1"),
		ResidencyPolicyWatermark: application.residency.PolicyWatermark(),
	})
	if err != nil {
		return nil, fmt.Errorf("initialize governance source: %w", err)
	}
	var source governance.Source = current
	if application.audit != nil {
		source = governance.SourceFunc(func(ctx context.Context, authorization protocol.AuthorizationContext) (governance.RawSnapshot, error) {
			raw, err := current.Load(ctx, authorization)
			if err != nil {
				return governance.RawSnapshot{}, err
			}
			scope := protocol.TenantScope{
				Version: protocol.EnterpriseContractVersion, TenantID: authorization.TenantID,
				Region: application.residency.Region(),
			}
			references, err := application.audit.store.ListReferences(
				ctx,
				scope,
				func(_ context.Context, requested protocol.TenantScope) error {
					if requested != scope {
						return fmt.Errorf("audit reference scope mismatch")
					}
					return scope.ValidateAuthorization(authorization)
				},
			)
			if err != nil {
				return governance.RawSnapshot{}, err
			}
			raw.AuditReferences = references
			raw.ResidencyViolations = application.residency.Violations(authorization.TenantID)
			return raw, nil
		})
	} else {
		source = governance.SourceFunc(func(ctx context.Context, authorization protocol.AuthorizationContext) (governance.RawSnapshot, error) {
			raw, err := current.Load(ctx, authorization)
			if err != nil {
				return governance.RawSnapshot{}, err
			}
			raw.ResidencyViolations = application.residency.Violations(authorization.TenantID)
			return raw, nil
		})
	}
	service, err := governance.New(authorizer, source)
	if err != nil {
		return nil, fmt.Errorf("initialize governance service: %w", err)
	}
	return &auditedGovernanceProvider{provider: service, audit: application.audit}, nil
}

type auditedGovernanceProvider struct {
	provider runtime.GovernanceProvider
	audit    *permissionedAuditRecorder
}

func (p *auditedGovernanceProvider) View(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) (governance.Snapshot, error) {
	if p == nil || p.provider == nil {
		return governance.Snapshot{}, governance.ErrUnavailable
	}
	snapshot, err := p.provider.View(ctx, authorization)
	if err != nil {
		return governance.Snapshot{}, err
	}
	if p.audit != nil {
		if _, err := p.audit.Record(ctx, "governance.view", protocol.DecisionAllow); err != nil {
			return governance.Snapshot{}, governance.ErrUnavailable
		}
	}
	return snapshot, nil
}

func governanceSetting(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
