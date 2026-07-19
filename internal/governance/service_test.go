package governance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/protocol"
	phase3contract "github.com/zzqDeco/knote/tests/phase3/contract"
)

func TestViewDenialDoesNotReadSource(t *testing.T) {
	calls := 0
	service, err := New(
		AuthorizerFunc(func(context.Context, protocol.AuthorizationContext) (Visibility, error) {
			return Visibility{}, nil
		}),
		SourceFunc(func(context.Context, protocol.AuthorizationContext) (RawSnapshot, error) {
			calls++
			return RawSnapshot{}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.View(context.Background(), governanceTestAuthorization()); !errors.Is(err, ErrDenied) {
		t.Fatalf("View error = %v, want ErrDenied", err)
	}
	if calls != 0 {
		t.Fatalf("denied governance view read source %d time(s)", calls)
	}
}

func TestViewProjectsAuthorizedSectionsWithoutZeroSideChannels(t *testing.T) {
	raw := governanceTestRawSnapshot()
	service, err := New(
		AuthorizerFunc(func(context.Context, protocol.AuthorizationContext) (Visibility, error) {
			return Visibility{TenantStatus: true, ConnectorSummary: true}, nil
		}),
		SourceFunc(func(context.Context, protocol.AuthorizationContext) (RawSnapshot, error) { return raw, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.View(context.Background(), governanceTestAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	if view.Tenant == nil || view.Connectors == nil || view.Connectors.Total != 2 || view.Connectors.Blocked != 1 {
		t.Fatalf("authorized governance projection = %+v", view)
	}
	if view.Connectors.Items != nil {
		t.Fatalf("summary-only projection exposed connector identities: %+v", view.Connectors.Items)
	}
	if view.Simulations != nil || view.Audit != nil || view.Residency != nil {
		t.Fatalf("unauthorized section rendered as an empty count: %+v", view)
	}
}

func TestViewAndRenderAreDeterministic(t *testing.T) {
	if phase3contract.GovernanceSampleCount != 2 {
		t.Fatalf("governance test executes two views, contract requires %d", phase3contract.GovernanceSampleCount)
	}
	raw := governanceTestRawSnapshot()
	visibility := Visibility{
		TenantStatus: true, ConnectorSummary: true, ConnectorDetails: true,
		SimulationSummary: true, SimulationDetails: true, AuditReferences: true,
		ResidencyViolations: true,
	}
	service, err := New(
		AuthorizerFunc(func(context.Context, protocol.AuthorizationContext) (Visibility, error) { return visibility, nil }),
		SourceFunc(func(context.Context, protocol.AuthorizationContext) (RawSnapshot, error) { return raw, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	first, err := service.View(context.Background(), governanceTestAuthorization())
	firstElapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	second, err := service.View(context.Background(), governanceTestAuthorization())
	secondElapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	maximumElapsed := firstElapsed
	if secondElapsed > maximumElapsed {
		maximumElapsed = secondElapsed
	}
	if maximumElapsed > phase3contract.GovernanceMaxBudget {
		t.Fatalf("slowest governance view took %s, want at most %s", maximumElapsed, phase3contract.GovernanceMaxBudget)
	}
	if Render(first) != Render(second) {
		t.Fatalf("governance rendering is not deterministic:\n%s\n---\n%s", Render(first), Render(second))
	}
	if first.Connectors.Items[0].ConnectorID != "connector-a" || first.Simulations.Items[0].SimulationID != "simulation-a" {
		t.Fatalf("governance lists were not canonicalized: %+v", first)
	}
	for _, forbidden := range []string{"protected body", "credential", "/secret/path"} {
		if strings.Contains(Render(first), forbidden) {
			t.Fatalf("governance rendering leaked %q", forbidden)
		}
	}
}

func TestViewRejectsCrossTenantAndInvalidVisibility(t *testing.T) {
	raw := governanceTestRawSnapshot()
	for _, test := range []struct {
		name       string
		visibility Visibility
		change     func(*RawSnapshot)
	}{
		{name: "details without summary", visibility: Visibility{ConnectorDetails: true}},
		{name: "cross tenant", visibility: Visibility{TenantStatus: true}, change: func(value *RawSnapshot) {
			value.Tenant.Scope.TenantID = "tenant-b"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := raw
			if test.change != nil {
				test.change(&candidate)
			}
			service, err := New(
				AuthorizerFunc(func(context.Context, protocol.AuthorizationContext) (Visibility, error) { return test.visibility, nil }),
				SourceFunc(func(context.Context, protocol.AuthorizationContext) (RawSnapshot, error) { return candidate, nil }),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.View(context.Background(), governanceTestAuthorization()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("View error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestKnowledgeBaseEditorAuthorizerRequiresDirectEditor(t *testing.T) {
	modelID := "01GAHCE4YVKPQEKZQHT2R89MQV"
	checker, err := authz.NewLocalAuthorizer(modelID, []authz.Tuple{
		{User: "user:alice", Relation: authz.RelationMember, Object: "organization:tenant-a"},
		{User: "user:bob", Relation: authz.RelationMember, Object: "organization:tenant-a"},
		{User: "organization:tenant-a", Relation: authz.RelationOrganization, Object: "knowledge_base:kb-a"},
		{User: "user:alice", Relation: authz.RelationEditor, Object: "knowledge_base:kb-a"},
		{User: "user:bob", Relation: authz.RelationViewer, Object: "knowledge_base:kb-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewKnowledgeBaseEditorAuthorizer(checker)
	if err != nil {
		t.Fatal(err)
	}
	auth := governanceTestAuthorization()
	auth.AuthorizationModelID = modelID
	visible, err := authorizer.Authorize(context.Background(), auth)
	if err != nil || !visible.TenantStatus || !visible.AuditReferences {
		t.Fatalf("editor visibility = %+v, err=%v", visible, err)
	}
	auth.PrincipalID = "bob"
	visible, err = authorizer.Authorize(context.Background(), auth)
	if err != nil || visible.any() {
		t.Fatalf("viewer visibility = %+v, err=%v", visible, err)
	}
	auth.PrincipalID = "alice"
	auth.AgentID, auth.TaskID = "agent-a", "task-a"
	auth.DelegationWatermark = "delegation-v1"
	auth.AgentTaskScopeFingerprint = "scope_0123456789abcdef0123456789abcdef"
	visible, err = authorizer.Authorize(context.Background(), auth)
	if err != nil || visible.any() {
		t.Fatalf("delegated visibility = %+v, err=%v", visible, err)
	}
}

func TestKnowledgeBaseEditorAuthorizerForcesHigherConsistency(t *testing.T) {
	checker := &recordingGovernanceChecker{}
	authorizer, err := NewKnowledgeBaseEditorAuthorizer(checker)
	if err != nil {
		t.Fatal(err)
	}
	authorization := governanceTestAuthorization()
	authorization.Consistency = protocol.ConsistencyMinimizeLatency

	visible, err := authorizer.Authorize(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if !visible.TenantStatus {
		t.Fatal("editor governance visibility was denied")
	}
	if checker.request.Consistency != authz.ConsistencyHigherConsistency {
		t.Fatalf("governance consistency = %q, want %q", checker.request.Consistency, authz.ConsistencyHigherConsistency)
	}
}

type recordingGovernanceChecker struct {
	request authz.CheckRequest
}

func (c *recordingGovernanceChecker) Check(_ context.Context, request authz.CheckRequest) (authz.Decision, error) {
	c.request = request
	return authz.Decision{Allowed: true, AuthorizationModelID: request.AuthorizationModelID}, nil
}

func governanceTestAuthorization() protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version: protocol.SecurityContractVersion, TenantID: "tenant-a", KnowledgeBaseID: "kb-a",
		PrincipalID: "alice", SessionID: "session-a", RequestID: "request-a",
		AuthorizationModelID: "model-v1", IdentityWatermark: "identity-v1", ACLWatermark: "acl-v1",
		Consistency: protocol.ConsistencyHigherConsistency,
	}
}

func governanceTestRawSnapshot() RawSnapshot {
	now := time.Date(2026, time.July, 19, 6, 0, 0, 0, time.UTC)
	scope := protocol.TenantScope{Version: protocol.EnterpriseContractVersion, TenantID: "tenant-a", Region: "local"}
	return RawSnapshot{
		Version: SnapshotVersion, GeneratedAt: now,
		Tenant: TenantStatus{
			Scope: scope, AuthorizationModelID: "model-v1", IdentityWatermark: "identity-v1",
			ACLWatermark: "acl-v1", ConnectorWatermark: "connector-v1", ResidencyPolicyWatermark: "residency-v1",
		},
		Connectors: []ConnectorHealth{
			{ConnectorID: "connector-b", State: ConnectorBlocked, Checkpoint: 3, SourceWatermark: "source-v3", ACLWatermark: "acl-v3", DLQCount: 1},
			{ConnectorID: "connector-a", State: ConnectorHealthy, Checkpoint: 4, SourceWatermark: "source-v4", ACLWatermark: "acl-v4"},
		},
		Simulations: []SimulationSummary{
			{SimulationID: "simulation-b", State: SimulationFailed, GeneratedAt: now, Impacts: ImpactCounts{Failures: 1}},
			{SimulationID: "simulation-a", State: SimulationComplete, GeneratedAt: now, Impacts: ImpactCounts{Grants: 1}},
		},
		AuditReferences: []protocol.AuditRecordReference{{
			Version: protocol.EnterpriseContractVersion, TenantID: "tenant-a", RecordID: "audit-a",
			CorrelationID: "request-a", ActorID: "alice", Action: "governance-view", Outcome: protocol.DecisionAllow,
			PreviousDigest: protocol.NewContentDigest("genesis"), RecordDigest: protocol.NewContentDigest("audit-a"), RecordedAt: now,
		}},
		ResidencyViolations: []ResidencyViolation{{
			RequestID: "residency-request-a", Operation: protocol.ResidencyEgress,
			DataClass: protocol.ResidencyProtectedContent, DestinationRegion: "remote",
			ReasonCode: "region-denied", RecordedAt: now,
		}},
	}
}
