package governance

import (
	"fmt"
	"strings"
)

func Render(snapshot Snapshot) string {
	var b strings.Builder
	b.WriteString("governance\n")
	if snapshot.Tenant != nil {
		fmt.Fprintf(&b, "tenant\n  id: %s\n  region: %s\n  model: %s\n  identity: %s\n  acl: %s\n  connector: %s\n  residency: %s\n",
			snapshot.Tenant.Scope.TenantID, snapshot.Tenant.Scope.Region,
			snapshot.Tenant.AuthorizationModelID, snapshot.Tenant.IdentityWatermark,
			snapshot.Tenant.ACLWatermark, snapshot.Tenant.ConnectorWatermark,
			snapshot.Tenant.ResidencyPolicyWatermark)
	}
	if snapshot.Connectors != nil {
		fmt.Fprintf(&b, "connectors\n  total: %d\n  blocked: %d\n", snapshot.Connectors.Total, snapshot.Connectors.Blocked)
		for _, connector := range snapshot.Connectors.Items {
			fmt.Fprintf(&b, "  %s: %s checkpoint=%d dlq=%d source=%s acl=%s\n",
				connector.ConnectorID, connector.State, connector.Checkpoint, connector.DLQCount,
				connector.SourceWatermark, connector.ACLWatermark)
		}
	}
	if snapshot.Simulations != nil {
		fmt.Fprintf(&b, "simulations\n  total: %d\n", snapshot.Simulations.Total)
		for _, simulation := range snapshot.Simulations.Items {
			fmt.Fprintf(&b, "  %s: %s grants=%d revocations=%d unknowns=%d failures=%d\n",
				simulation.SimulationID, simulation.State, simulation.Impacts.Grants,
				simulation.Impacts.Revocations, simulation.Impacts.Unknowns, simulation.Impacts.Failures)
		}
	}
	if snapshot.Audit != nil {
		fmt.Fprintf(&b, "audit\n  total: %d\n", snapshot.Audit.Total)
		for _, reference := range snapshot.Audit.References {
			fmt.Fprintf(&b, "  %s: %s %s %s\n", reference.RecordID, reference.Action, reference.Outcome, reference.CorrelationID)
		}
	}
	if snapshot.Residency != nil {
		fmt.Fprintf(&b, "residency violations\n  total: %d\n", snapshot.Residency.Total)
		for _, violation := range snapshot.Residency.Violations {
			fmt.Fprintf(&b, "  %s: %s %s %s %s\n", violation.RequestID, violation.Operation,
				violation.DataClass, violation.DestinationRegion, violation.ReasonCode)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
