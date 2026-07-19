package governance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const SnapshotVersion = protocol.GovernanceContractVersion

type ConnectorState string

const (
	ConnectorHealthy ConnectorState = "healthy"
	ConnectorLagging ConnectorState = "lagging"
	ConnectorBlocked ConnectorState = "blocked"
)

type SimulationState string

const (
	SimulationComplete SimulationState = "complete"
	SimulationFailed   SimulationState = "failed"
)

type TenantStatus struct {
	Scope                    protocol.TenantScope `json:"scope"`
	AuthorizationModelID     string               `json:"authorization_model_id"`
	IdentityWatermark        string               `json:"identity_watermark"`
	ACLWatermark             string               `json:"acl_watermark"`
	DelegationWatermark      string               `json:"delegation_watermark,omitempty"`
	ConnectorWatermark       string               `json:"connector_watermark"`
	ResidencyPolicyWatermark string               `json:"residency_policy_watermark"`
}

type ConnectorHealth struct {
	ConnectorID     string         `json:"connector_id"`
	State           ConnectorState `json:"state"`
	Checkpoint      uint64         `json:"checkpoint_sequence"`
	SourceWatermark string         `json:"source_watermark"`
	ACLWatermark    string         `json:"acl_watermark"`
	DLQCount        uint64         `json:"dlq_count"`
}

type ImpactCounts struct {
	Grants      uint64 `json:"grants"`
	Revocations uint64 `json:"revocations"`
	Unchanged   uint64 `json:"unchanged"`
	Unknowns    uint64 `json:"unknowns"`
	Failures    uint64 `json:"failures"`
}

type SimulationSummary struct {
	SimulationID string          `json:"simulation_id"`
	State        SimulationState `json:"state"`
	GeneratedAt  time.Time       `json:"generated_at"`
	Impacts      ImpactCounts    `json:"impacts"`
}

type ResidencyViolation struct {
	RequestID         string                          `json:"request_id"`
	Operation         protocol.ResidencyOperationKind `json:"operation"`
	DataClass         protocol.ResidencyDataClass     `json:"data_class"`
	DestinationRegion string                          `json:"destination_region"`
	ReasonCode        string                          `json:"reason_code"`
	RecordedAt        time.Time                       `json:"recorded_at"`
}

// RawSnapshot is a trusted content-free source projection. Service.View still
// applies section authorization before any field reaches a caller.
type RawSnapshot struct {
	Version             string                          `json:"version"`
	GeneratedAt         time.Time                       `json:"generated_at"`
	Tenant              TenantStatus                    `json:"tenant"`
	Connectors          []ConnectorHealth               `json:"connectors"`
	Simulations         []SimulationSummary             `json:"simulations"`
	AuditReferences     []protocol.AuditRecordReference `json:"audit_references"`
	ResidencyViolations []ResidencyViolation            `json:"residency_violations"`
}

type ConnectorSection struct {
	Total   uint64            `json:"total"`
	Blocked uint64            `json:"blocked"`
	Items   []ConnectorHealth `json:"items,omitempty"`
}

type SimulationSection struct {
	Total uint64              `json:"total"`
	Items []SimulationSummary `json:"items,omitempty"`
}

type AuditSection struct {
	Total      uint64                          `json:"total"`
	References []protocol.AuditRecordReference `json:"references,omitempty"`
}

type ResidencySection struct {
	Total      uint64               `json:"total"`
	Violations []ResidencyViolation `json:"violations,omitempty"`
}

// Snapshot uses pointer sections so denied visibility is distinct from an
// authorized empty result.
type Snapshot struct {
	Version     string             `json:"version"`
	TenantID    string             `json:"tenant_id"`
	GeneratedAt time.Time          `json:"generated_at"`
	Tenant      *TenantStatus      `json:"tenant,omitempty"`
	Connectors  *ConnectorSection  `json:"connectors,omitempty"`
	Simulations *SimulationSection `json:"simulations,omitempty"`
	Audit       *AuditSection      `json:"audit,omitempty"`
	Residency   *ResidencySection  `json:"residency,omitempty"`
}

func (r RawSnapshot) validateFor(auth protocol.AuthorizationContext) error {
	if r.Version != SnapshotVersion {
		return fmt.Errorf("unsupported governance snapshot version %q", r.Version)
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if err := r.Tenant.Scope.ValidateAuthorization(auth); err != nil {
		return err
	}
	if err := validateUTC("generated_at", r.GeneratedAt); err != nil {
		return err
	}
	if err := validateTenantStatus(r.Tenant, auth); err != nil {
		return err
	}
	seenConnectors := make(map[string]struct{}, len(r.Connectors))
	for index, connector := range r.Connectors {
		if err := connector.validate(); err != nil {
			return fmt.Errorf("connector %d: %w", index, err)
		}
		if _, exists := seenConnectors[connector.ConnectorID]; exists {
			return fmt.Errorf("connector ids must be unique")
		}
		seenConnectors[connector.ConnectorID] = struct{}{}
	}
	seenSimulations := make(map[string]struct{}, len(r.Simulations))
	for index, simulation := range r.Simulations {
		if err := simulation.validate(); err != nil {
			return fmt.Errorf("simulation %d: %w", index, err)
		}
		if _, exists := seenSimulations[simulation.SimulationID]; exists {
			return fmt.Errorf("simulation ids must be unique")
		}
		seenSimulations[simulation.SimulationID] = struct{}{}
	}
	seenAudit := make(map[string]struct{}, len(r.AuditReferences))
	for index, reference := range r.AuditReferences {
		if err := reference.ValidateFor(r.Tenant.Scope); err != nil {
			return fmt.Errorf("audit reference %d: %w", index, err)
		}
		if _, exists := seenAudit[reference.RecordID]; exists {
			return fmt.Errorf("audit record ids must be unique")
		}
		seenAudit[reference.RecordID] = struct{}{}
	}
	seenViolations := make(map[string]struct{}, len(r.ResidencyViolations))
	for index, violation := range r.ResidencyViolations {
		if err := violation.validate(); err != nil {
			return fmt.Errorf("residency violation %d: %w", index, err)
		}
		if _, exists := seenViolations[violation.RequestID]; exists {
			return fmt.Errorf("residency violation request ids must be unique")
		}
		seenViolations[violation.RequestID] = struct{}{}
	}
	return nil
}

func validateTenantStatus(status TenantStatus, auth protocol.AuthorizationContext) error {
	for name, value := range map[string]string{
		"authorization_model_id":     status.AuthorizationModelID,
		"identity_watermark":         status.IdentityWatermark,
		"acl_watermark":              status.ACLWatermark,
		"connector_watermark":        status.ConnectorWatermark,
		"residency_policy_watermark": status.ResidencyPolicyWatermark,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if status.DelegationWatermark != "" {
		if err := validateID("delegation_watermark", status.DelegationWatermark); err != nil {
			return err
		}
	}
	if status.AuthorizationModelID != auth.AuthorizationModelID || status.IdentityWatermark != auth.IdentityWatermark ||
		status.ACLWatermark != auth.ACLWatermark || status.DelegationWatermark != auth.DelegationWatermark {
		return fmt.Errorf("governance tenant status does not match the authorization context")
	}
	return nil
}

func (c ConnectorHealth) validate() error {
	if err := validateID("connector_id", c.ConnectorID); err != nil {
		return err
	}
	if err := validateID("source_watermark", c.SourceWatermark); err != nil {
		return err
	}
	if err := validateID("acl_watermark", c.ACLWatermark); err != nil {
		return err
	}
	switch c.State {
	case ConnectorHealthy, ConnectorLagging, ConnectorBlocked:
		return nil
	default:
		return fmt.Errorf("unsupported connector state %q", c.State)
	}
}

func (s SimulationSummary) validate() error {
	if err := validateID("simulation_id", s.SimulationID); err != nil {
		return err
	}
	if err := validateUTC("simulation_generated_at", s.GeneratedAt); err != nil {
		return err
	}
	switch s.State {
	case SimulationComplete, SimulationFailed:
		return nil
	default:
		return fmt.Errorf("unsupported simulation state %q", s.State)
	}
}

func (v ResidencyViolation) validate() error {
	for name, value := range map[string]string{"request_id": v.RequestID, "reason_code": v.ReasonCode} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	switch v.Operation {
	case protocol.ResidencyStore, protocol.ResidencyProcess, protocol.ResidencyEgress:
	default:
		return fmt.Errorf("unsupported residency operation %q", v.Operation)
	}
	switch v.DataClass {
	case protocol.ResidencyProtectedContent, protocol.ResidencyIdentity, protocol.ResidencyACL,
		protocol.ResidencyAudit, protocol.ResidencyTelemetry, protocol.ResidencyBackup:
	default:
		return fmt.Errorf("unsupported residency data class %q", v.DataClass)
	}
	if err := validateRegion(v.DestinationRegion); err != nil {
		return err
	}
	return validateUTC("residency_recorded_at", v.RecordedAt)
}

func canonicalize(raw RawSnapshot) RawSnapshot {
	raw.Connectors = append([]ConnectorHealth(nil), raw.Connectors...)
	raw.Simulations = append([]SimulationSummary(nil), raw.Simulations...)
	raw.AuditReferences = append([]protocol.AuditRecordReference(nil), raw.AuditReferences...)
	raw.ResidencyViolations = append([]ResidencyViolation(nil), raw.ResidencyViolations...)
	sort.Slice(raw.Connectors, func(i, j int) bool { return raw.Connectors[i].ConnectorID < raw.Connectors[j].ConnectorID })
	sort.Slice(raw.Simulations, func(i, j int) bool { return raw.Simulations[i].SimulationID < raw.Simulations[j].SimulationID })
	sort.Slice(raw.AuditReferences, func(i, j int) bool { return raw.AuditReferences[i].RecordID < raw.AuditReferences[j].RecordID })
	sort.Slice(raw.ResidencyViolations, func(i, j int) bool {
		return raw.ResidencyViolations[i].RequestID < raw.ResidencyViolations[j].RequestID
	})
	return raw
}

func validateID(name, value string) error {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be a canonical opaque identifier", name)
	}
	for index, character := range []byte(value) {
		allowed := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' ||
			character == ':' || character == '@'
		if !allowed || index == 0 && !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return fmt.Errorf("%s must be a canonical opaque identifier", name)
		}
	}
	return nil
}

func validateRegion(value string) error {
	if value == "" || len(value) > 32 {
		return fmt.Errorf("destination region must be canonical")
	}
	for index, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && character == '-') {
			return fmt.Errorf("destination region must be canonical")
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
