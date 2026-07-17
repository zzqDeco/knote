package protocol

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestEnterpriseTenantIdentityContractsFailClosed(t *testing.T) {
	now := enterpriseTestTime()
	scope := enterpriseTestTenantScope()
	snapshot := IdentitySnapshot{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID,
		ProviderID: "provider-1", ExternalSubjectID: "subject-1", PrincipalID: "principal-1",
		GroupIDs: []string{"group-a", "group-b"}, State: IdentityActive,
		Watermark: "identity-v1", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := snapshot.ValidateFor(scope); err != nil {
		t.Fatalf("ValidateFor: %v", err)
	}
	if err := snapshot.UsableAt(snapshot.Watermark, now.Add(time.Minute)); err != nil {
		t.Fatalf("UsableAt: %v", err)
	}

	crossTenant := snapshot
	crossTenant.TenantID = "tenant-b"
	if err := crossTenant.ValidateFor(scope); err == nil {
		t.Fatal("cross-tenant identity snapshot was accepted")
	}

	unsorted := snapshot
	unsorted.GroupIDs = []string{"group-b", "group-a"}
	if err := unsorted.Validate(); err == nil {
		t.Fatal("unsorted identity groups were accepted")
	}

	deprovisioned := snapshot
	deprovisioned.State = IdentityDeprovisioned
	if err := deprovisioned.UsableAt(deprovisioned.Watermark, now.Add(time.Minute)); err == nil {
		t.Fatal("deprovisioned identity snapshot was usable")
	}
	if err := snapshot.UsableAt(snapshot.Watermark, snapshot.ExpiresAt); err == nil {
		t.Fatal("expired identity snapshot was usable")
	}
	if err := snapshot.UsableAt("identity-v2", now.Add(time.Minute)); err == nil {
		t.Fatal("stale identity snapshot watermark was usable")
	}

	auth := enterpriseTestAuthorization()
	if err := scope.ValidateAuthorization(auth); err != nil {
		t.Fatalf("ValidateAuthorization: %v", err)
	}
	auth.TenantID = "tenant-b"
	if err := scope.ValidateAuthorization(auth); err == nil {
		t.Fatal("cross-tenant authorization context was accepted")
	}
}

func TestConnectorContractsBindReplayDLQAndTombstones(t *testing.T) {
	now := enterpriseTestTime()
	scope := enterpriseTestTenantScope()
	resource := enterpriseTestResource(t, "doc-a")
	event := ConnectorEventEnvelope{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID, ConnectorID: "connector-1",
		EventID: "event-10", IdempotencyKey: "idem-10", Kind: ConnectorResourceTombstone,
		Sequence: 10, ResourceID: resource.ResourceID, SourceWatermark: "source-v10",
		ACLWatermark: "acl-v1", PayloadDigest: NewContentDigest("tombstone-metadata"), OccurredAt: now,
	}
	if err := event.ValidateFor(scope); err != nil {
		t.Fatalf("event ValidateFor: %v", err)
	}
	fingerprint, err := NewConnectorEventFingerprint(event)
	if err != nil {
		t.Fatalf("event fingerprint: %v", err)
	}

	checkpoint := ConnectorCheckpoint{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID, ConnectorID: event.ConnectorID,
		LastSequence: event.Sequence, CommittedEventID: event.EventID, CommittedEventFingerprint: fingerprint,
		IdempotencyKey:  event.IdempotencyKey,
		SourceWatermark: event.SourceWatermark, ACLWatermark: event.ACLWatermark, CommittedAt: now.Add(time.Second),
	}
	if err := checkpoint.ValidateEvent(event); err != nil {
		t.Fatalf("exact checkpoint replay: %v", err)
	}
	conflict := event
	conflict.EventID = "event-conflict"
	if err := checkpoint.ValidateEvent(conflict); err == nil {
		t.Fatal("conflicting event at committed sequence was accepted")
	}
	tampered := event
	tampered.PayloadDigest = NewContentDigest("different-tombstone-metadata")
	if err := checkpoint.ValidateEvent(tampered); err == nil {
		t.Fatal("tampered event with reused identifiers was accepted")
	}
	stale := event
	stale.Sequence--
	if err := checkpoint.ValidateEvent(stale); err == nil {
		t.Fatal("event behind checkpoint was accepted")
	}
	next := event
	next.Sequence++
	next.EventID = "event-11"
	next.IdempotencyKey = "idem-11"
	if err := checkpoint.ValidateEvent(next); err != nil {
		t.Fatalf("new event after checkpoint: %v", err)
	}
	reusedEventID := next
	reusedEventID.EventID = event.EventID
	if err := checkpoint.ValidateEvent(reusedEventID); err == nil {
		t.Fatal("new event with the committed event ID was accepted")
	}
	reusedIdempotencyKey := next
	reusedIdempotencyKey.IdempotencyKey = event.IdempotencyKey
	if err := checkpoint.ValidateEvent(reusedIdempotencyKey); err == nil {
		t.Fatal("new event with the committed idempotency key was accepted")
	}
	gap := next
	gap.Sequence++
	gap.EventID = "event-12"
	gap.IdempotencyKey = "idem-12"
	if err := checkpoint.ValidateEvent(gap); err == nil {
		t.Fatal("event with a sequence gap was accepted")
	}

	receipt := ConnectorDeliveryReceipt{
		Version: EnterpriseContractVersion, TenantID: event.TenantID, ConnectorID: event.ConnectorID,
		EventID: event.EventID, EventFingerprint: fingerprint,
		IdempotencyKey: event.IdempotencyKey, Sequence: event.Sequence,
		State: ConnectorDeliveryDeadLettered, Attempts: 3, ErrorCode: "invalid-acl", HandledAt: now.Add(time.Minute),
	}
	if err := receipt.ValidateFor(event); err != nil {
		t.Fatalf("DLQ receipt ValidateFor: %v", err)
	}
	appliedWithError := receipt
	appliedWithError.State = ConnectorDeliveryApplied
	if err := appliedWithError.ValidateFor(event); err == nil {
		t.Fatal("applied receipt with error code was accepted")
	}

	tombstone := ConnectorTombstone{
		Version: EnterpriseContractVersion, TenantID: event.TenantID, ConnectorID: event.ConnectorID,
		EventID: event.EventID, EventFingerprint: fingerprint,
		IdempotencyKey: event.IdempotencyKey, Sequence: event.Sequence,
		ResourceID: event.ResourceID, SourceWatermark: event.SourceWatermark, ACLWatermark: event.ACLWatermark,
		ReasonCode: "source-delete", DeletedAt: now.Add(2 * time.Minute),
	}
	if err := tombstone.ValidateFor(event); err != nil {
		t.Fatalf("tombstone ValidateFor: %v", err)
	}
	tombstone.ResourceID = enterpriseTestResource(t, "doc-b").ResourceID
	if err := tombstone.ValidateFor(event); err == nil {
		t.Fatal("tombstone for a different resource was accepted")
	}

	snapshotComplete := event
	snapshotComplete.Kind = ConnectorSnapshotComplete
	snapshotComplete.ResourceID = ""
	if err := snapshotComplete.Validate(); err != nil {
		t.Fatalf("snapshot_complete event: %v", err)
	}
	snapshotComplete.ResourceID = resource.ResourceID
	if err := snapshotComplete.Validate(); err == nil {
		t.Fatal("snapshot_complete event with resource was accepted")
	}
}

func TestAgentTaskScopeBindsExactAuthorizationContext(t *testing.T) {
	now := enterpriseTestTime()
	auth := enterpriseTestAuthorization()
	scope := AgentTaskScope{
		Version: EnterpriseContractVersion, TenantID: auth.TenantID, KnowledgeBaseID: auth.KnowledgeBaseID,
		PrincipalID: auth.PrincipalID, AgentID: auth.AgentID, TaskID: auth.TaskID,
		AuthorizationModelID: auth.AuthorizationModelID, IdentityWatermark: auth.IdentityWatermark,
		ACLWatermark: auth.ACLWatermark, DelegationWatermark: "delegation-v1",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := scope.ValidateFor(auth, "delegation-v1", now.Add(time.Minute)); err != nil {
		t.Fatalf("ValidateFor: %v", err)
	}
	first, err := NewAgentTaskScopeFingerprint(scope)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	second, err := NewAgentTaskScopeFingerprint(scope)
	if err != nil || first != second {
		t.Fatalf("fingerprint is not deterministic: %q %q %v", first, second, err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("fingerprint Validate: %v", err)
	}

	wrongAgent := auth
	wrongAgent.AgentID = "agent-2"
	if err := scope.ValidateFor(wrongAgent, "delegation-v1", now.Add(time.Minute)); err == nil {
		t.Fatal("mismatched agent was accepted")
	}
	if err := scope.ValidateFor(auth, "delegation-v1", scope.ExpiresAt); err == nil {
		t.Fatal("expired agent task scope was accepted")
	}
	noTask := auth
	noTask.TaskID = ""
	if err := scope.ValidateFor(noTask, "delegation-v1", now.Add(time.Minute)); err == nil {
		t.Fatal("authorization context without task was accepted")
	}
	if err := scope.ValidateFor(auth, "delegation-v2", now.Add(time.Minute)); err == nil {
		t.Fatal("stale agent task delegation watermark was accepted")
	}
}

func TestToolContractsAuthorizeInvocationAndSortedReturnedHandles(t *testing.T) {
	auth := enterpriseTestAuthorization()
	invocation := ToolInvocationAuthorization{
		Version: EnterpriseContractVersion, CorrelationID: "tool-invocation-1",
		TenantID: auth.TenantID, KnowledgeBaseID: auth.KnowledgeBaseID,
		PrincipalID: auth.PrincipalID, AgentID: auth.AgentID, TaskID: auth.TaskID,
		SessionID: auth.SessionID, RequestID: auth.RequestID, ToolName: "knote-query",
		Action: "invoke", Relation: EvidenceReadRelation, AuthorizationModelID: auth.AuthorizationModelID,
		IdentityWatermark: auth.IdentityWatermark, ACLWatermark: auth.ACLWatermark, SideEffect: false,
		Outcome: DecisionAllow, CheckedAt: enterpriseTestTime(),
	}
	if err := invocation.ValidateFor(auth); err != nil {
		t.Fatalf("invocation ValidateFor: %v", err)
	}
	wrongTask := invocation
	wrongTask.TaskID = "task-2"
	if err := wrongTask.ValidateFor(auth); err == nil {
		t.Fatal("tool invocation with wrong task was accepted")
	}
	deniedInvocation := invocation
	deniedInvocation.Outcome = DecisionDeny
	if err := deniedInvocation.ValidateFor(auth); err == nil {
		t.Fatal("denied tool invocation was accepted")
	}

	resources := []ResourceHandle{enterpriseTestResource(t, "doc-a"), enterpriseTestResource(t, "doc-b")}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	decisions := []AuthorizationDecision{
		enterpriseTestAllowDecision(auth, resources[0], invocation.Relation, "tool-result-1"),
		enterpriseTestAllowDecision(auth, resources[1], invocation.Relation, "tool-result-2"),
	}
	result := ToolResultAuthorization{
		Version: EnterpriseContractVersion, TenantID: auth.TenantID, KnowledgeBaseID: auth.KnowledgeBaseID,
		PrincipalID: auth.PrincipalID, AgentID: auth.AgentID, TaskID: auth.TaskID,
		SessionID: auth.SessionID, RequestID: auth.RequestID, ToolName: invocation.ToolName,
		Relation: EvidenceReadRelation, AuthorizationModelID: auth.AuthorizationModelID,
		IdentityWatermark: auth.IdentityWatermark, ACLWatermark: auth.ACLWatermark,
		Resources: resources, Decisions: decisions,
	}
	if err := result.ValidateFor(auth); err != nil {
		t.Fatalf("result ValidateFor: %v", err)
	}
	unsorted := result
	unsorted.Resources = []ResourceHandle{resources[1], resources[0]}
	if err := unsorted.ValidateFor(auth); err == nil {
		t.Fatal("unsorted tool resources were accepted")
	}
	crossTenant := result
	crossTenant.Resources = append([]ResourceHandle(nil), result.Resources...)
	crossTenant.Resources[0].TenantID = "tenant-b"
	if err := crossTenant.ValidateFor(auth); err == nil {
		t.Fatal("cross-tenant returned resource was accepted")
	}
	staleModel := result
	staleModel.AuthorizationModelID = "model-v0"
	if err := staleModel.ValidateFor(auth); err == nil {
		t.Fatal("tool result with a stale authorization model was accepted")
	}
	staleIdentity := result
	staleIdentity.IdentityWatermark = "identity-v0"
	if err := staleIdentity.ValidateFor(auth); err == nil {
		t.Fatal("tool result with a stale identity watermark was accepted")
	}
	deniedResult := result
	deniedResult.Decisions = append([]AuthorizationDecision(nil), result.Decisions...)
	deniedResult.Decisions[0].Outcome = DecisionDeny
	if err := deniedResult.ValidateFor(auth); err == nil {
		t.Fatal("tool result with a denied resource was accepted")
	}
	partialResult := result
	partialResult.Decisions = append([]AuthorizationDecision(nil), result.Decisions[:1]...)
	if err := partialResult.ValidateFor(auth); err == nil {
		t.Fatal("tool result with a missing resource decision was accepted")
	}
	wrongRelation := result
	wrongRelation.Decisions = append([]AuthorizationDecision(nil), result.Decisions...)
	wrongRelation.Decisions[0].Relation = "can-edit"
	if err := wrongRelation.ValidateFor(auth); err == nil {
		t.Fatal("tool result with a mismatched relation decision was accepted")
	}
}

func TestPolicyAuditAndResidencyContractsArePinnedAndNonMutating(t *testing.T) {
	now := enterpriseTestTime()
	scope := enterpriseTestTenantScope()
	request := PolicySimulationRequest{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID, SimulationID: "simulation-1",
		RequestID: "request-1", ActorID: "operator-1", Mode: PolicySimulationReadOnly,
		BaseAuthorizationModelID: "model-v1", ProposedAuthorizationModelID: "model-v2",
		BaseIdentityWatermark: "identity-v1", ProposedIdentityWatermark: "identity-v2",
		BaseACLWatermark: "acl-v1", ProposedACLWatermark: "acl-v2", RequestedAt: now,
	}
	if err := request.ValidateFor(scope); err != nil {
		t.Fatalf("simulation request: %v", err)
	}
	mutating := request
	mutating.Mode = "apply"
	if err := mutating.ValidateFor(scope); err == nil {
		t.Fatal("mutating simulation mode was accepted")
	}
	report := PolicyImpactReport{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID,
		SimulationID: request.SimulationID, GeneratedAt: now.Add(time.Minute),
		Entries: []PolicyImpactEntry{
			{CorrelationID: "impact-1", SubjectID: "user:alice", Relation: "can-view", Object: "document:doc-a", Kind: PolicyImpactGrant, Before: DecisionDeny, After: DecisionAllow},
			{CorrelationID: "impact-2", SubjectID: "user:bob", Relation: "can-view", Object: "document:doc-b", Kind: PolicyImpactRevoke, Before: DecisionAllow, After: DecisionDeny},
		},
	}
	if err := report.ValidateFor(request, scope); err != nil {
		t.Fatalf("impact report: %v", err)
	}
	unsorted := report
	unsorted.Entries = []PolicyImpactEntry{report.Entries[1], report.Entries[0]}
	if err := unsorted.ValidateFor(request, scope); err == nil {
		t.Fatal("unsorted impact report was accepted")
	}
	duplicateTuple := report
	duplicate := report.Entries[0]
	duplicate.CorrelationID = "impact-3"
	duplicateTuple.Entries = []PolicyImpactEntry{report.Entries[0], duplicate}
	if err := duplicateTuple.ValidateFor(request, scope); err == nil {
		t.Fatal("duplicate policy impact tuple was accepted")
	}

	audit := AuditRecordReference{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID, RecordID: "audit-1",
		CorrelationID: "request-1", ActorID: "operator-1", Action: "policy-simulate",
		Outcome: DecisionAllow, PreviousDigest: NewContentDigest("genesis"),
		RecordDigest: NewContentDigest("record-1"), RecordedAt: now.Add(2 * time.Minute),
	}
	if err := audit.ValidateFor(scope); err != nil {
		t.Fatalf("audit reference: %v", err)
	}
	audit.TenantID = "tenant-b"
	if err := audit.ValidateFor(scope); err == nil {
		t.Fatal("cross-tenant audit reference was accepted")
	}

	policy := ResidencyPolicy{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID, HomeRegion: scope.Region,
		StorageRegions: []string{"cn-east", "cn-north"}, ProcessingRegions: []string{"cn-east"},
		EgressRegions: []string{}, PolicyWatermark: "residency-v1",
	}
	if err := policy.ValidateFor(scope); err != nil {
		t.Fatalf("residency policy: %v", err)
	}
	store := ResidencyCheckRequest{
		Version: EnterpriseContractVersion, TenantID: scope.TenantID, RequestID: "request-2",
		Operation: ResidencyStore, DataClass: ResidencyProtectedContent,
		DestinationRegion: "cn-north", PolicyWatermark: policy.PolicyWatermark,
	}
	if err := store.ValidateFor(policy, scope); err != nil {
		t.Fatalf("allowed residency store: %v", err)
	}
	egress := store
	egress.Operation = ResidencyEgress
	if err := egress.ValidateFor(policy, scope); err == nil {
		t.Fatal("egress into a denied region was accepted")
	}
}

func TestEnterpriseContractsSerializeDeterministicallyWithoutPayloads(t *testing.T) {
	event := ConnectorEventEnvelope{
		Version: EnterpriseContractVersion, TenantID: "tenant-a", ConnectorID: "connector-1",
		EventID: "event-1", IdempotencyKey: "idem-1", Kind: ConnectorSnapshotComplete,
		Sequence: 1, SourceWatermark: "source-v1", ACLWatermark: "acl-v1",
		PayloadDigest: NewContentDigest("metadata-only"), OccurredAt: enterpriseTestTime(),
	}
	first, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	second, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("non-deterministic JSON:\n%s\n%s", first, second)
	}
	for _, forbidden := range []string{"bearer", "credential", "assertion", "payload_body", "secret"} {
		if strings.Contains(string(first), forbidden) {
			t.Fatalf("connector envelope serialized forbidden field %q: %s", forbidden, first)
		}
	}
}

func enterpriseTestTime() time.Time {
	return time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
}

func TestEnterpriseUTCValidationAcceptsRFC3339ZeroOffset(t *testing.T) {
	zeroOffset, err := time.Parse(time.RFC3339, "2026-07-17T12:00:00+00:00")
	if err != nil {
		t.Fatalf("parse zero-offset timestamp: %v", err)
	}
	if err := validateUTC("wire_time", zeroOffset); err != nil {
		t.Fatalf("zero-offset RFC3339 timestamp was rejected: %v", err)
	}
	nonUTC, err := time.Parse(time.RFC3339, "2026-07-17T12:00:00+08:00")
	if err != nil {
		t.Fatalf("parse non-UTC timestamp: %v", err)
	}
	if err := validateUTC("wire_time", nonUTC); err == nil {
		t.Fatal("non-zero-offset timestamp was accepted")
	}
}

func enterpriseTestTenantScope() TenantScope {
	return TenantScope{Version: EnterpriseContractVersion, TenantID: "tenant-a", Region: "cn-east"}
}

func enterpriseTestAuthorization() AuthorizationContext {
	return AuthorizationContext{
		Version: SecurityContractVersion, TenantID: "tenant-a", KnowledgeBaseID: "kb-a",
		PrincipalID: "principal-1", AgentID: "agent-1", TaskID: "task-1",
		SessionID: "session-1", RequestID: "request-1", AuthorizationModelID: "model-v1",
		IdentityWatermark: "identity-v1", ACLWatermark: "acl-v1",
		Consistency: ConsistencyHigherConsistency,
	}
}

func enterpriseTestResource(t *testing.T, sourceKey string) ResourceHandle {
	t.Helper()
	id, err := NewStableResourceID("tenant-a", "kb-a", ResourceDocument, sourceKey)
	if err != nil {
		t.Fatalf("resource id: %v", err)
	}
	return ResourceHandle{
		ResourceID: id, Type: ResourceDocument, TenantID: "tenant-a", KnowledgeBaseID: "kb-a",
		AuthorizationID: "document:" + string(id), AuthorizationResourceID: id,
		ContentDigest: NewContentDigest("content-" + sourceKey),
		Versions: ResourceVersions{
			Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
			Index: "index-v1", Graph: "graph-v1", Projection: "projection-v1",
		},
		ServingState: ServingActive,
	}
}

func enterpriseTestAllowDecision(auth AuthorizationContext, resource ResourceHandle, relation, correlationID string) AuthorizationDecision {
	return AuthorizationDecision{
		CorrelationID: correlationID, RequestID: auth.RequestID, SessionID: auth.SessionID,
		PrincipalID: auth.PrincipalID, AgentID: auth.AgentID, TaskID: auth.TaskID,
		Relation: relation, Resource: resource, AuthorizationResource: resource, Outcome: DecisionAllow,
		AuthorizationModelID: auth.AuthorizationModelID, IdentityWatermark: auth.IdentityWatermark,
		ACLWatermark: auth.ACLWatermark, Consistency: auth.Consistency, CheckedAt: enterpriseTestTime(),
	}
}
