package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

const (
	phase3AcceptanceModelID      = "01GAHCE4YVKPQEKZQHT2R89MQV"
	phase3AcceptanceToolName     = "knote_phase3_resources"
	phase3AcceptanceQuestion     = "run the phase3 resource query"
	phase3AcceptancePolicyCanary = "PHASE3_SCOPE_POLICY_INTERNAL_CANARY"
	phase3AcceptanceHiddenBody   = "PHASE3_UNAUTHORIZED_RETURN_BODY_CANARY"
	phase3AcceptanceToolComplete = "phase3 authorized tool complete"
	phase3AcceptanceAnswer       = "phase3 authorized answer"
)

var phase3AcceptanceNow = time.Date(2026, time.July, 19, 8, 0, 0, 0, time.UTC)

func TestPhase3PermissionedAcceptanceIntersectionGuardsInvocationAndResults(t *testing.T) {
	t.Run("authorized invocation publishes one decision per resource", func(t *testing.T) {
		harness := newPhase3AcceptanceHarness(t, "sess_phase3_allowed", nil)
		events := harness.startAndSend(t)
		if phase3AcceptanceHasEvent(events, protocol.EventError) {
			t.Fatalf("authorized tool invocation failed: %+v", events)
		}
		if harness.runner.invocationAttempts != 1 || harness.runner.executions != 1 ||
			harness.runner.resultAttempts != 1 || harness.runner.publicationAttempts != 1 {
			t.Fatalf(
				"authorized lifecycle attempts invocation=%d execution=%d result=%d publication=%d",
				harness.runner.invocationAttempts,
				harness.runner.executions,
				harness.runner.resultAttempts,
				harness.runner.publicationAttempts,
			)
		}
		if err := harness.runner.binding.ValidateFor(harness.authorization); err != nil {
			t.Fatalf("published binding: %v", err)
		}
		result := harness.runner.envelope.Result
		if len(result.Resources) != 2 || len(result.Decisions) != 2 {
			t.Fatalf("authorized result resources=%d decisions=%d", len(result.Resources), len(result.Decisions))
		}
		seen := make(map[protocol.ResourceID]bool, len(result.Decisions))
		for index, decision := range result.Decisions {
			if err := decision.ValidateFor(harness.authorization); err != nil {
				t.Fatalf("decision %d: %v", index, err)
			}
			if !decision.Authorized() || decision.PrincipalID != harness.authorization.PrincipalID ||
				decision.AgentID != harness.authorization.AgentID || decision.TaskID != harness.authorization.TaskID {
				t.Fatalf("decision %d does not preserve the user/agent/task intersection: %+v", index, decision)
			}
			seen[decision.Resource.ResourceID] = true
		}
		for _, resource := range []protocol.ResourceHandle{harness.resources.first, harness.resources.second} {
			if !seen[resource.ResourceID] {
				t.Fatalf("returned resource %s has no authorization decision", resource.ResourceID)
			}
		}
		if len(harness.oracle.resultChecks) != 2 {
			t.Fatalf("result gate calls=%d, want result and publication checks", len(harness.oracle.resultChecks))
		}
		for index, checked := range harness.oracle.resultChecks {
			if len(checked) != 2 {
				t.Fatalf("result gate call %d checked %d resources, want 2", index, len(checked))
			}
		}

		protectedEvents := 0
		for _, event := range events {
			if event.Type != protocol.EventToolComplete && event.Type != protocol.EventAssistantDone {
				continue
			}
			protectedEvents++
			if event.ProtectedContent == nil || event.ProtectedContent.BlockID != harness.runner.binding.BlockID {
				t.Fatalf("published event is not bound to the authorized result: %+v", event)
			}
		}
		if protectedEvents != 2 {
			t.Fatalf("protected published events=%d, want 2", protectedEvents)
		}
	})

	var invocationSurface string
	for _, dimension := range phase3AcceptanceScopeDimensions() {
		dimension := dimension
		t.Run("invocation denies missing "+dimension.name+" intersection", func(t *testing.T) {
			harness := newPhase3AcceptanceHarness(t, "sess_phase3_invocation", dimension.mutateAuthorization)
			events := harness.startAndSend(t)
			phase3AcceptanceAssertDeniedSurface(t, harness, events)
			if harness.runner.invocationAttempts != 1 || harness.runner.executions != 0 ||
				harness.runner.resultAttempts != 0 || len(harness.oracle.resultChecks) != 0 {
				t.Fatalf(
					"denied invocation crossed boundary: invocation=%d execution=%d result=%d result_checks=%d",
					harness.runner.invocationAttempts,
					harness.runner.executions,
					harness.runner.resultAttempts,
					len(harness.oracle.resultChecks),
				)
			}
			got := phase3AcceptanceObservableSurface(events)
			if invocationSurface == "" {
				invocationSurface = got
			} else if got != invocationSurface {
				t.Fatalf("%s denial surface differs:\n%s\nwant:\n%s", dimension.name, got, invocationSurface)
			}
		})
	}

	for _, dimension := range phase3AcceptanceScopeDimensions() {
		dimension := dimension
		t.Run("result denies revoked "+dimension.name+" intersection", func(t *testing.T) {
			harness := newPhase3AcceptanceHarness(t, "sess_phase3_result", nil)
			harness.runner.beforeResult = func() { dimension.mutateScope(&harness.oracle.scope) }
			events := harness.startAndSend(t)
			phase3AcceptanceAssertDeniedSurface(t, harness, events)
			if harness.runner.invocationAttempts != 1 || harness.runner.executions != 1 ||
				harness.runner.resultAttempts != 1 || harness.runner.publicationAttempts != 0 ||
				harness.runner.envelope.Version != "" {
				t.Fatalf(
					"revoked result lifecycle invocation=%d execution=%d result=%d publication=%d envelope=%+v",
					harness.runner.invocationAttempts,
					harness.runner.executions,
					harness.runner.resultAttempts,
					harness.runner.publicationAttempts,
					harness.runner.envelope,
				)
			}
			if got := phase3AcceptanceObservableSurface(events); got != invocationSurface {
				t.Fatalf("%s result denial surface differs:\n%s\nwant:\n%s", dimension.name, got, invocationSurface)
			}
		})
	}

	t.Run("one unauthorized returned resource suppresses the whole result", func(t *testing.T) {
		harness := newPhase3AcceptanceHarness(t, "sess_phase3_mixed_result", nil)
		harness.runner.resources = []protocol.ProtectedResourceBinding{
			{Resource: harness.resources.first, AuthorizationResource: harness.resources.first},
			{Resource: harness.resources.hidden, AuthorizationResource: harness.resources.hidden},
		}
		events := harness.startAndSend(t)
		phase3AcceptanceAssertDeniedSurface(t, harness, events)
		if harness.runner.executions != 1 || harness.runner.resultAttempts != 1 ||
			harness.runner.publicationAttempts != 0 || len(harness.oracle.resultChecks) != 1 {
			t.Fatalf(
				"mixed result crossed boundary: execution=%d result=%d publication=%d checks=%d",
				harness.runner.executions,
				harness.runner.resultAttempts,
				harness.runner.publicationAttempts,
				len(harness.oracle.resultChecks),
			)
		}
		checked := harness.oracle.resultChecks[0]
		if len(checked) != 2 || !phase3AcceptanceContainsID(checked, harness.resources.first.ResourceID) ||
			!phase3AcceptanceContainsID(checked, harness.resources.hidden.ResourceID) {
			t.Fatalf("result gate did not inspect every returned resource: %+v", checked)
		}
		if got := phase3AcceptanceObservableSurface(events); got != invocationSurface {
			t.Fatalf("mixed result denial surface differs:\n%s\nwant:\n%s", got, invocationSurface)
		}
	})
}

func TestPhase3PermissionedAcceptanceIntersectionGuardsReplayWithoutSideChannels(t *testing.T) {
	var replaySurface string
	for _, dimension := range phase3AcceptanceScopeDimensions() {
		dimension := dimension
		t.Run(dimension.name+" revocation", func(t *testing.T) {
			harness := newPhase3AcceptanceHarness(t, "sess_phase3_replay", nil)
			if _, err := harness.manager.Start(context.Background(), StartOptions{}); err != nil {
				t.Fatalf("start prime runtime: %v", err)
			}
			safe := harness.manager.Interrupt(context.Background())
			if len(safe) != 1 || safe[0].Type != protocol.EventStatusUpdate {
				t.Fatalf("safe local history was not created: %+v", safe)
			}
			safeMessage := safe[0].Message
			initial := harness.manager.SendMessage(context.Background(), phase3AcceptanceQuestion)
			if phase3AcceptanceHasEvent(initial, protocol.EventError) || harness.runner.binding.BlockID == "" {
				t.Fatalf("prime protected result failed: %+v", initial)
			}
			initialRuns := harness.runner.executions
			dimension.mutateScope(&harness.oracle.scope)

			resumed := New(Dependencies{
				Workspace:                    harness.workspace,
				Capabilities:                 PermissionedSessionCapabilityProfile(),
				Sessions:                     harness.store,
				EinoRunner:                   harness.runner,
				AuthorizationContextProvider: harness.provider,
				ProtectedContentAuthorizer:   harness.oracle.authorizeReplay,
			})
			events, err := resumed.Start(context.Background(), StartOptions{ResumeID: harness.authorization.SessionID})
			if err != nil {
				t.Fatalf("resume after %s revocation: %v", dimension.name, err)
			}
			if harness.oracle.replayChecks != 1 {
				t.Fatalf("protected replay checks=%d, want one check for the complete block", harness.oracle.replayChecks)
			}
			if harness.runner.executions != initialRuns {
				t.Fatalf("resume invoked the tool runner: before=%d after=%d", initialRuns, harness.runner.executions)
			}
			if !phase3AcceptanceHasMessage(events, protocol.EventStatusUpdate, safeMessage) {
				t.Fatalf("safe local history was not preserved: %+v", events)
			}
			phase3AcceptanceAssertNoUnauthorizedSurface(t, harness, events)
			for _, event := range events {
				if event.ProtectedContent != nil {
					t.Fatalf("revoked protected block %s replayed: %+v", harness.runner.binding.BlockID, event)
				}
			}
			got := phase3AcceptanceObservableSurface(events)
			if replaySurface == "" {
				replaySurface = got
			} else if got != replaySurface {
				t.Fatalf("%s replay denial surface differs:\n%s\nwant:\n%s", dimension.name, got, replaySurface)
			}
		})
	}
}

type phase3AcceptanceScopeDimension struct {
	name                string
	mutateAuthorization func(*protocol.AuthorizationContext)
	mutateScope         func(*protocol.AgentTaskScope)
}

func phase3AcceptanceScopeDimensions() []phase3AcceptanceScopeDimension {
	return []phase3AcceptanceScopeDimension{
		{
			name: "user",
			mutateAuthorization: func(authorization *protocol.AuthorizationContext) {
				authorization.PrincipalID = "mallory"
			},
			mutateScope: func(scope *protocol.AgentTaskScope) { scope.PrincipalID = "mallory" },
		},
		{
			name: "agent",
			mutateAuthorization: func(authorization *protocol.AuthorizationContext) {
				authorization.AgentID = "other-agent"
			},
			mutateScope: func(scope *protocol.AgentTaskScope) { scope.AgentID = "other-agent" },
		},
		{
			name: "task",
			mutateAuthorization: func(authorization *protocol.AuthorizationContext) {
				authorization.TaskID = "other-task"
			},
			mutateScope: func(scope *protocol.AgentTaskScope) { scope.TaskID = "other-task" },
		},
	}
}

type phase3AcceptanceResourceSet struct {
	first  protocol.ResourceHandle
	second protocol.ResourceHandle
	hidden protocol.ResourceHandle
}

type phase3AcceptanceHarness struct {
	workspace     string
	store         local.Store
	authorization protocol.AuthorizationContext
	provider      AuthorizationContextProvider
	resources     phase3AcceptanceResourceSet
	oracle        *phase3AcceptancePolicyOracle
	runner        *phase3AcceptanceToolRunner
	manager       *Manager
}

func newPhase3AcceptanceHarness(
	t *testing.T,
	sessionID string,
	mutateAuthorization func(*protocol.AuthorizationContext),
) *phase3AcceptanceHarness {
	t.Helper()
	scope := phase3AcceptanceAgentTaskScope()
	fingerprint, err := protocol.NewAgentTaskScopeFingerprint(scope)
	if err != nil {
		t.Fatalf("agent/task scope fingerprint: %v", err)
	}
	authorization := protocol.AuthorizationContext{
		Version: protocol.SecurityContractVersion, TenantID: scope.TenantID,
		KnowledgeBaseID: scope.KnowledgeBaseID, PrincipalID: scope.PrincipalID,
		SessionID: sessionID, RequestID: "request-phase3-acceptance",
		AuthorizationModelID: scope.AuthorizationModelID,
		IdentityWatermark:    scope.IdentityWatermark, ACLWatermark: scope.ACLWatermark,
		AgentID: scope.AgentID, TaskID: scope.TaskID, DelegationWatermark: scope.DelegationWatermark,
		AgentTaskScopeFingerprint: fingerprint,
		Consistency:               protocol.ConsistencyHigherConsistency,
	}
	if mutateAuthorization != nil {
		mutateAuthorization(&authorization)
	}
	if err := authorization.Validate(); err != nil {
		t.Fatalf("authorization context: %v", err)
	}

	resources := phase3AcceptanceResourceSet{
		first:  phase3AcceptanceResource(t, authorization, "visible-first", "phase3 visible first"),
		second: phase3AcceptanceResource(t, authorization, "visible-second", "phase3 visible second"),
		hidden: phase3AcceptanceResource(t, authorization, "hidden-return", phase3AcceptanceHiddenBody),
	}
	oracle := &phase3AcceptancePolicyOracle{
		scope: scope, currentDelegationWatermark: scope.DelegationWatermark,
		at: phase3AcceptanceNow,
		allowedResources: map[protocol.ResourceID]struct{}{
			resources.first.ResourceID:  {},
			resources.second.ResourceID: {},
		},
	}
	localAuthorizer, err := authz.NewLocalAuthorizer(phase3AcceptanceModelID, []authz.Tuple{
		{User: "user:alice", Relation: authz.RelationMember, Object: "organization:phase3"},
		{User: "organization:phase3", Relation: authz.RelationOrganization, Object: "knowledge_base:kb-phase3"},
		{User: "user:alice", Relation: authz.RelationViewer, Object: "knowledge_base:kb-phase3"},
	})
	if err != nil {
		t.Fatalf("local authorizer: %v", err)
	}
	registry, err := protocol.NewToolManifestRegistry([]protocol.ToolAuthorizationManifest{{
		Version: protocol.ToolAuthorizationContractVersion, ToolName: phase3AcceptanceToolName,
		Action: "read", Relation: authz.RelationCanView, ReturnObligation: protocol.ToolReturnResources,
	}})
	if err != nil {
		t.Fatalf("tool registry: %v", err)
	}
	gate, err := authz.NewToolAuthorizationGate(authz.ToolAuthorizationGateOptions{
		Authorizer: localAuthorizer, Registry: registry,
		FinalAuthorizationGate: oracle.authorizeScope,
		ResultGate:             oracle.authorizeResult,
		Now:                    func() time.Time { return phase3AcceptanceNow },
		NewCorrelationID:       func() (string, error) { return "tool-phase3-acceptance", nil },
	})
	if err != nil {
		t.Fatalf("tool authorization gate: %v", err)
	}
	runner := &phase3AcceptanceToolRunner{
		gate: gate,
		resources: []protocol.ProtectedResourceBinding{
			{Resource: resources.first, AuthorizationResource: resources.first},
			{Resource: resources.second, AuthorizationResource: resources.second},
		},
	}
	provider := func(ctx context.Context, requestedSessionID string) (protocol.AuthorizationContext, error) {
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		current := authorization
		current.SessionID = requestedSessionID
		return current, nil
	}
	workspace := t.TempDir()
	store := local.New(workspace)
	manager := New(Dependencies{
		Workspace: workspace, Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions: store, EinoRunner: runner,
		AuthorizationContextProvider: provider,
		ProtectedContentAuthorizer:   oracle.authorizeReplay,
		NewSessionID:                 func() string { return sessionID },
	})
	return &phase3AcceptanceHarness{
		workspace: workspace, store: store, authorization: authorization, provider: provider,
		resources: resources, oracle: oracle, runner: runner, manager: manager,
	}
}

func (h *phase3AcceptanceHarness) startAndSend(t *testing.T) []protocol.Event {
	t.Helper()
	if _, err := h.manager.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	return h.manager.SendMessage(context.Background(), phase3AcceptanceQuestion)
}

func phase3AcceptanceAgentTaskScope() protocol.AgentTaskScope {
	return protocol.AgentTaskScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: "tenant-phase3", KnowledgeBaseID: "kb-phase3", PrincipalID: "alice",
		AgentID: "research", TaskID: "answer", AuthorizationModelID: phase3AcceptanceModelID,
		IdentityWatermark: "identity-phase3-v1", ACLWatermark: "acl-phase3-v1",
		DelegationWatermark: "delegation-phase3-v1",
		IssuedAt:            phase3AcceptanceNow.Add(-time.Hour),
		ExpiresAt:           phase3AcceptanceNow.Add(time.Hour),
	}
}

func phase3AcceptanceResource(
	t *testing.T,
	authorization protocol.AuthorizationContext,
	source string,
	content string,
) protocol.ResourceHandle {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(
		authorization.TenantID,
		authorization.KnowledgeBaseID,
		protocol.ResourceDocument,
		source,
	)
	if err != nil {
		t.Fatalf("resource ID: %v", err)
	}
	return protocol.ResourceHandle{
		ResourceID: resourceID, Type: protocol.ResourceDocument,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		AuthorizationID:         "document:" + string(resourceID),
		AuthorizationResourceID: resourceID,
		ContentDigest:           protocol.NewContentDigest(content),
		Versions: protocol.ResourceVersions{
			Source: "source-phase3-v1", Content: "content-phase3-v1", ACL: authorization.ACLWatermark,
			Index: "index-phase3-v1", Graph: "graph-phase3-v1", Projection: "projection-phase3-v1",
		},
		ServingState: protocol.ServingActive,
	}
}

type phase3AcceptancePolicyOracle struct {
	scope                      protocol.AgentTaskScope
	currentDelegationWatermark string
	at                         time.Time
	allowedResources           map[protocol.ResourceID]struct{}
	resultChecks               [][]protocol.ResourceID
	replayChecks               int
}

func (o *phase3AcceptancePolicyOracle) authorizeScope(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) error {
	if ctx == nil {
		return errors.New(phase3AcceptancePolicyCanary + ": nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", phase3AcceptancePolicyCanary, err)
	}
	if err := authorization.ValidateAgentTaskScope(o.scope, o.currentDelegationWatermark, o.at); err != nil {
		return fmt.Errorf("%s: %w", phase3AcceptancePolicyCanary, err)
	}
	return nil
}

func (o *phase3AcceptancePolicyOracle) authorizeResult(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error {
	if err := o.authorizeScope(ctx, authorization); err != nil {
		return err
	}
	checked := make([]protocol.ResourceID, len(binding.Resources))
	for index, resource := range binding.Resources {
		checked[index] = resource.Resource.ResourceID
	}
	o.resultChecks = append(o.resultChecks, checked)
	return o.authorizeResources(binding)
}

func (o *phase3AcceptancePolicyOracle) authorizeReplay(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error {
	o.replayChecks++
	if err := o.authorizeScope(ctx, authorization); err != nil {
		return err
	}
	return o.authorizeResources(binding)
}

func (o *phase3AcceptancePolicyOracle) authorizeResources(binding protocol.ProtectedContentBinding) error {
	for _, resource := range binding.Resources {
		if _, allowed := o.allowedResources[resource.Resource.ResourceID]; !allowed {
			return fmt.Errorf(
				"%s: denied resource %s contains %s",
				phase3AcceptancePolicyCanary,
				resource.Resource.ResourceID,
				phase3AcceptanceHiddenBody,
			)
		}
	}
	return nil
}

type phase3AcceptanceToolRunner struct {
	gate         *authz.ToolAuthorizationGate
	resources    []protocol.ProtectedResourceBinding
	beforeResult func()

	invocationAttempts  int
	executions          int
	resultAttempts      int
	publicationAttempts int
	envelope            protocol.ToolAuthorizationEnvelope
	binding             protocol.ProtectedContentBinding
}

func (r *phase3AcceptanceToolRunner) Ready(context.Context) error {
	if r == nil || r.gate == nil {
		return errors.New("phase3 acceptance runner is unavailable")
	}
	return nil
}

func (*phase3AcceptanceToolRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return []RunnerToolInfo{{Name: phase3AcceptanceToolName, Description: "phase3 protected resource query"}}, nil
}

func (r *phase3AcceptanceToolRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok {
		return nil, errors.New("phase3 acceptance requires trusted authorization")
	}
	r.invocationAttempts++
	invocation, err := r.gate.AuthorizeInvocation(ctx, authorization, phase3AcceptanceToolName)
	if err != nil {
		return nil, err
	}
	r.executions++
	if r.beforeResult != nil {
		r.beforeResult()
	}
	binding, err := protocol.NewProtectedContentBindingFromResourcesForAuthorization(authorization, r.resources)
	if err != nil {
		return nil, err
	}
	r.resultAttempts++
	envelope, err := r.gate.AuthorizeResourceResult(ctx, authorization, invocation, binding.Resources)
	if err != nil {
		return nil, err
	}
	r.publicationAttempts++
	if err := r.gate.ValidateProtectedResultEnvelope(
		ctx,
		authorization,
		phase3AcceptanceToolName,
		envelope,
		binding,
	); err != nil {
		return nil, err
	}
	r.envelope = envelope
	r.binding = binding

	events := []protocol.Event{
		protocol.NewEvent(protocol.EventToolComplete, input.SessionID, phase3AcceptanceToolComplete, map[string]any{
			"tool": phase3AcceptanceToolName, "authorized_count": len(envelope.Result.Resources),
		}),
		protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, phase3AcceptanceAnswer, map[string]any{
			"tool": phase3AcceptanceToolName, "authorized_count": len(envelope.Result.Resources),
		}),
	}
	for index := range events {
		copy := binding
		events[index].ProtectedContent = &copy
	}
	return events, nil
}

func phase3AcceptanceAssertDeniedSurface(
	t *testing.T,
	harness *phase3AcceptanceHarness,
	events []protocol.Event,
) {
	t.Helper()
	want := strings.Join([]string{
		string(protocol.EventUserMessage) + "|" + phase3AcceptanceQuestion,
		string(protocol.EventError) + "|" + authz.ErrToolAuthorizationDenied.Error(),
	}, "\n")
	if got := phase3AcceptanceObservableSurface(events); got != want {
		t.Fatalf("denied public surface:\n%s\nwant:\n%s", got, want)
	}
	phase3AcceptanceAssertNoUnauthorizedSurface(t, harness, events)
}

func phase3AcceptanceAssertNoUnauthorizedSurface(
	t *testing.T,
	harness *phase3AcceptanceHarness,
	events []protocol.Event,
) {
	t.Helper()
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("encode events: %v", err)
	}
	forbidden := []string{
		phase3AcceptancePolicyCanary,
		phase3AcceptanceHiddenBody,
		phase3AcceptanceToolName,
		phase3AcceptanceToolComplete,
		phase3AcceptanceAnswer,
		string(harness.resources.first.ResourceID),
		string(harness.resources.second.ResourceID),
		string(harness.resources.hidden.ResourceID),
		`"authorized_count"`,
		`"resources"`,
		`"decisions"`,
		`"count"`,
		`"exists"`,
		`"pagination"`,
		`"trace"`,
	}
	for _, canary := range forbidden {
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("unauthorized public surface leaked %q: %s", canary, encoded)
		}
	}
	for _, event := range events {
		if event.ProtectedContent != nil || event.Type == protocol.EventToolComplete || event.Type == protocol.EventAssistantDone {
			t.Fatalf("unauthorized result event was published: %+v", event)
		}
	}
}

func phase3AcceptanceObservableSurface(events []protocol.Event) string {
	parts := make([]string, len(events))
	for index, event := range events {
		parts[index] = string(event.Type) + "|" + event.Message
	}
	return strings.Join(parts, "\n")
}

func phase3AcceptanceHasEvent(events []protocol.Event, eventType protocol.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func phase3AcceptanceHasMessage(events []protocol.Event, eventType protocol.EventType, message string) bool {
	for _, event := range events {
		if event.Type == eventType && event.Message == message {
			return true
		}
	}
	return false
}

func phase3AcceptanceContainsID(ids []protocol.ResourceID, want protocol.ResourceID) bool {
	for _, resourceID := range ids {
		if resourceID == want {
			return true
		}
	}
	return false
}
