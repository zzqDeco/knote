package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zzqDeco/knote/internal/governance"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/residency"
)

const (
	residencyStorageRegionsEnv        = "KNOTE_RESIDENCY_STORAGE_REGIONS"
	residencyProcessingRegionsEnv     = "KNOTE_RESIDENCY_PROCESSING_REGIONS"
	residencyEgressRegionsEnv         = "KNOTE_RESIDENCY_EGRESS_REGIONS"
	residencyKAGRegionEnv             = "KNOTE_RESIDENCY_KAG_REGION"
	residencyTelemetryRegionEnv       = "KNOTE_RESIDENCY_TELEMETRY_REGION"
	residencyAuditRegionEnv           = "KNOTE_RESIDENCY_AUDIT_REGION"
	residencyConnectorEgressRegionEnv = "KNOTE_RESIDENCY_CONNECTOR_EGRESS_REGION"
	residencyBackupRegionEnv          = "KNOTE_RESIDENCY_BACKUP_REGION"
)

type permissionedResidencyBoundary struct {
	homeRegion            string
	policyWatermark       string
	policy                protocol.ResidencyPolicy
	kagRegion             string
	telemetryRegion       string
	auditRegion           string
	connectorEgressRegion string
	backupRegion          string
	sequence              atomic.Uint64
	violationsMu          sync.RWMutex
	violations            map[string][]governance.ResidencyViolation
	now                   func() time.Time
}

func newPermissionedResidencyBoundary() (*permissionedResidencyBoundary, error) {
	home := governanceSetting(governanceRegionEnv, "local")
	storage, err := residencyRegions(residencyStorageRegionsEnv, home, false)
	if err != nil {
		return nil, err
	}
	processing, err := residencyRegions(residencyProcessingRegionsEnv, home, false)
	if err != nil {
		return nil, err
	}
	egress, err := residencyRegions(residencyEgressRegionsEnv, home, true)
	if err != nil {
		return nil, err
	}
	boundary := &permissionedResidencyBoundary{
		homeRegion:            home,
		policyWatermark:       governanceSetting(governanceResidencyWatermarkEnv, "residency-local-v1"),
		kagRegion:             governanceSetting(residencyKAGRegionEnv, home),
		telemetryRegion:       governanceSetting(residencyTelemetryRegionEnv, home),
		auditRegion:           governanceSetting(residencyAuditRegionEnv, home),
		connectorEgressRegion: governanceSetting(residencyConnectorEgressRegionEnv, home),
		backupRegion:          governanceSetting(residencyBackupRegionEnv, home),
		violations:            make(map[string][]governance.ResidencyViolation),
		now:                   func() time.Time { return time.Now().UTC() },
	}
	boundary.policy = protocol.ResidencyPolicy{
		Version: protocol.EnterpriseContractVersion, TenantID: "tenant-validation", HomeRegion: home,
		StorageRegions: storage, ProcessingRegions: processing, EgressRegions: egress,
		PolicyWatermark: boundary.policyWatermark,
	}
	validationScope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: boundary.policy.TenantID, Region: home,
	}
	if err := boundary.policy.ValidateFor(validationScope); err != nil {
		return nil, fmt.Errorf("initialize residency policy: %w", err)
	}
	type configuredDestination struct {
		operation protocol.ResidencyOperationKind
		region    string
	}
	destinations := map[string]configuredDestination{
		"KAG":       {operation: protocol.ResidencyProcess, region: boundary.kagRegion},
		"telemetry": {operation: protocol.ResidencyStore, region: boundary.telemetryRegion},
		"audit":     {operation: protocol.ResidencyStore, region: boundary.auditRegion},
		"backup":    {operation: protocol.ResidencyStore, region: boundary.backupRegion},
	}
	if len(egress) > 0 {
		destinations["connector egress"] = configuredDestination{
			operation: protocol.ResidencyEgress,
			region:    boundary.connectorEgressRegion,
		}
	}
	for name, destination := range destinations {
		if !boundary.regionAllowed(destination.operation, destination.region) {
			return nil, fmt.Errorf("initialize residency policy: %s destination region %q is not allowed", name, destination.region)
		}
	}
	return boundary, nil
}

func (b *permissionedResidencyBoundary) Region() string {
	if b == nil {
		return ""
	}
	return b.homeRegion
}

func (b *permissionedResidencyBoundary) PolicyWatermark() string {
	if b == nil {
		return ""
	}
	return b.policyWatermark
}

func (b *permissionedResidencyBoundary) Violations(tenantID string) []governance.ResidencyViolation {
	if b == nil {
		return []governance.ResidencyViolation{}
	}
	b.violationsMu.RLock()
	defer b.violationsMu.RUnlock()
	return append([]governance.ResidencyViolation(nil), b.violations[tenantID]...)
}

func (b *permissionedResidencyBoundary) AuthorizeKAGProcessing(ctx context.Context, _ string) error {
	return b.authorizeCurrent(ctx, protocol.ResidencyProcess, protocol.ResidencyProtectedContent, b.kagRegion)
}

func (b *permissionedResidencyBoundary) AuthorizeTelemetryStore(ctx context.Context) error {
	return b.authorizeCurrent(ctx, protocol.ResidencyStore, protocol.ResidencyTelemetry, b.telemetryRegion)
}

func (b *permissionedResidencyBoundary) AuthorizeAuditStore(
	ctx context.Context,
	scope protocol.TenantScope,
) error {
	if authorization, ok := protocol.AuthorizationContextFrom(ctx); ok && authorization.TenantID != scope.TenantID {
		return residency.ErrDenied
	}
	return b.authorizeScope(ctx, scope, protocol.ResidencyStore, protocol.ResidencyAudit, b.auditRegion)
}

func (b *permissionedResidencyBoundary) AuthorizeConnectorEgress(ctx context.Context, _ string) error {
	return b.authorizeCurrent(
		ctx,
		protocol.ResidencyEgress,
		protocol.ResidencyProtectedContent,
		b.connectorEgressRegion,
	)
}

func (b *permissionedResidencyBoundary) AuthorizeBackupStore(ctx context.Context) error {
	return b.authorizeCurrent(ctx, protocol.ResidencyStore, protocol.ResidencyBackup, b.backupRegion)
}

func (b *permissionedResidencyBoundary) WithConnectorEgress(
	ctx context.Context,
	connectorID string,
	write func() error,
) error {
	if write == nil {
		return residency.ErrDenied
	}
	if err := b.AuthorizeConnectorEgress(ctx, connectorID); err != nil {
		return err
	}
	return write()
}

func (b *permissionedResidencyBoundary) WithBackupStore(
	ctx context.Context,
	write func() error,
) error {
	if write == nil {
		return residency.ErrDenied
	}
	if err := b.AuthorizeBackupStore(ctx); err != nil {
		return err
	}
	return write()
}

func (b *permissionedResidencyBoundary) authorizeCurrent(
	ctx context.Context,
	operation protocol.ResidencyOperationKind,
	dataClass protocol.ResidencyDataClass,
	destination string,
) error {
	if b == nil || ctx == nil {
		return residency.ErrDenied
	}
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok || authorization.Validate() != nil {
		return residency.ErrDenied
	}
	return b.authorizeScope(ctx, protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: authorization.TenantID, Region: b.homeRegion,
	}, operation, dataClass, destination)
}

func (b *permissionedResidencyBoundary) authorizeScope(
	ctx context.Context,
	scope protocol.TenantScope,
	operation protocol.ResidencyOperationKind,
	dataClass protocol.ResidencyDataClass,
	destination string,
) error {
	if b == nil || ctx == nil || ctx.Err() != nil || scope.Region != b.homeRegion {
		return residency.ErrDenied
	}
	provider := residency.PolicyProviderFunc(func(ctx context.Context, requested protocol.TenantScope) (protocol.ResidencyPolicy, error) {
		if ctx == nil || ctx.Err() != nil || requested != scope {
			return protocol.ResidencyPolicy{}, residency.ErrDenied
		}
		policy := b.policy
		policy.TenantID = scope.TenantID
		policy.StorageRegions = append([]string(nil), b.policy.StorageRegions...)
		policy.ProcessingRegions = append([]string(nil), b.policy.ProcessingRegions...)
		policy.EgressRegions = append([]string(nil), b.policy.EgressRegions...)
		return policy, nil
	})
	gate, err := residency.NewGate(scope, provider, residency.DestinationConfig{{
		Operation: operation, DataClass: dataClass, Region: destination,
	}})
	if err != nil {
		b.recordViolation(scope.TenantID, protocol.ResidencyCheckRequest{
			RequestID: fmt.Sprintf("residency_%016x", b.sequence.Add(1)), Operation: operation,
			DataClass: dataClass, DestinationRegion: destination,
		})
		return residency.ErrDenied
	}
	request := protocol.ResidencyCheckRequest{
		Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
		RequestID: fmt.Sprintf("residency_%016x", b.sequence.Add(1)),
		Operation: operation, DataClass: dataClass, DestinationRegion: destination,
		PolicyWatermark: b.policyWatermark,
	}
	if err := gate.Authorize(ctx, request); err != nil {
		b.recordViolation(scope.TenantID, request)
		return err
	}
	return nil
}

func (b *permissionedResidencyBoundary) recordViolation(
	tenantID string,
	request protocol.ResidencyCheckRequest,
) {
	if b == nil || tenantID == "" || b.now == nil {
		return
	}
	violation := governance.ResidencyViolation{
		RequestID: request.RequestID, Operation: request.Operation, DataClass: request.DataClass,
		DestinationRegion: request.DestinationRegion, ReasonCode: "policy-denied", RecordedAt: b.now().UTC(),
	}
	b.violationsMu.Lock()
	defer b.violationsMu.Unlock()
	values := append(b.violations[tenantID], violation)
	if len(values) > 128 {
		values = append([]governance.ResidencyViolation(nil), values[len(values)-128:]...)
	}
	b.violations[tenantID] = values
}

func (b *permissionedResidencyBoundary) regionAllowed(operation protocol.ResidencyOperationKind, region string) bool {
	var regions []string
	switch operation {
	case protocol.ResidencyStore:
		regions = b.policy.StorageRegions
	case protocol.ResidencyProcess:
		regions = b.policy.ProcessingRegions
	case protocol.ResidencyEgress:
		regions = b.policy.EgressRegions
	}
	for _, allowed := range regions {
		if allowed == region {
			return true
		}
	}
	return false
}

func residencyRegions(name, fallback string, allowNone bool) ([]string, error) {
	value, configured := os.LookupEnv(name)
	if !configured || strings.TrimSpace(value) == "" {
		return []string{fallback}, nil
	}
	if allowNone && strings.EqualFold(strings.TrimSpace(value), "none") {
		return []string{}, nil
	}
	parts := strings.Split(value, ",")
	regions := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		region := strings.TrimSpace(part)
		if region == "" {
			return nil, fmt.Errorf("%s must contain canonical comma-separated regions", name)
		}
		if _, duplicate := seen[region]; duplicate {
			return nil, fmt.Errorf("%s must contain unique regions", name)
		}
		seen[region] = struct{}{}
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions, nil
}
