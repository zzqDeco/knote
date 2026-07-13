package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

const (
	permissionedAcceptanceProjectionVersion = "projection_fake_v1"
	permissionedAcceptanceRetrieverVersion  = "fixture-retriever-v1"
	permissionedAcceptancePromptVersion     = "fixture-prompt-v1"

	permissionedAcceptanceIntroID        protocol.ResourceID = "res_00000000000000000000000000000001"
	permissionedAcceptanceDeniedID       protocol.ResourceID = "res_00000000000000000000000000000002"
	permissionedAcceptanceOverviewID     protocol.ResourceID = "res_00000000000000000000000000000003"
	permissionedAcceptanceIntroContent                       = "knote is local-first."
	permissionedAcceptanceDeniedContent                      = "DENIED CANARY BODY must never cross the authorization boundary"
	permissionedAcceptanceDeniedCitation                     = "cite_denied_canary"
	permissionedAcceptancePrivateReaders                     = "group:fixture-private-readers"

	permissionedAcceptancePropagationSamples = 128
	permissionedAcceptanceP95SLO             = 25 * time.Millisecond
	permissionedAcceptanceP99SLO             = 100 * time.Millisecond
)

var permissionedAcceptanceHiddenCanaries = []string{
	string(permissionedAcceptanceDeniedID),
	permissionedAcceptanceDeniedContent,
	permissionedAcceptanceDeniedCitation,
}

func TestPermissionedAcceptanceRevocationDeniesCacheCitationAndSessionReplay(t *testing.T) {
	const invariant = "revocation denies old cache, citation, and protected session replay"
	harness := newPermissionedAcceptanceHarness(t, fixture.Alice, "sess_acceptance_revocation")

	_, err := harness.manager.Start(context.Background(), StartOptions{})
	permissionedAcceptanceNoError(t, invariant, err)
	slashEvents := harness.manager.SendMessage(context.Background(), "/help")
	permissionedAcceptanceRequire(t, invariant, hasEvent(slashEvents, protocol.EventAssistantDone),
		"safe slash command did not complete: %+v", slashEvents)
	localEvents := harness.manager.Interrupt(context.Background())
	permissionedAcceptanceRequire(t, invariant,
		len(localEvents) == 1 && localEvents[0].Type == protocol.EventStatusUpdate,
		"safe local runtime history was not created: %+v", localEvents)
	safeLocalMessage := localEvents[0].Message

	queryEvents := harness.manager.SendMessage(context.Background(), "What is knote?")
	permissionedAcceptanceRequire(t, invariant, !hasEvent(queryEvents, protocol.EventError),
		"initial permissioned query failed: %+v", queryEvents)
	initial := harness.runner.snapshot()
	permissionedAcceptanceRequire(t, invariant, len(initial.result.Evidence.Items) == 2,
		"initial authorized evidence count = %d, want 2", len(initial.result.Evidence.Items))
	intro, ok := permissionedAcceptanceEvidenceByID(initial.result, permissionedAcceptanceIntroID)
	permissionedAcceptanceRequire(t, invariant, ok,
		"initial query did not contain the revocation target: %+v", initial.result.Evidence.Items)
	permissionedAcceptanceRequire(t, invariant, initial.binding.BlockID != "",
		"initial query did not produce a protected content binding")

	opened, err := harness.application.Service.OpenCitation(
		context.Background(), initial.authorization, initial.result.Evidence, intro.Citation.Handle,
	)
	permissionedAcceptanceNoError(t, invariant, err)
	permissionedAcceptanceRequire(t, invariant, opened.Content == permissionedAcceptanceIntroContent,
		"citation content before revocation = %q", opened.Content)

	err = harness.application.RemoveTuple(authz.Tuple{
		User:     "user:" + fixture.Alice,
		Relation: authz.RelationMember,
		Object:   permissionedAcceptancePrivateReaders,
	})
	permissionedAcceptanceNoError(t, invariant, err)
	report, err := harness.application.Apply(context.Background(), authorized.RevocationRequest{
		Authorization: initial.authorization,
		Binding:       initial.binding,
		ResourceIDs:   []protocol.ResourceID{permissionedAcceptanceIntroID},
		RevokedAt:     time.Now().UTC(),
	})
	permissionedAcceptanceNoError(t, invariant, err)
	permissionedAcceptanceRequire(t, invariant,
		report.InvalidatedResourceCount == 1 && report.DeniedCount == 1 && report.AllowedCount == 1,
		"revocation report = %#v", report)

	_, err = harness.application.Service.OpenCitation(
		context.Background(), initial.authorization, initial.result.Evidence, intro.Citation.Handle,
	)
	permissionedAcceptanceRequire(t, invariant, errors.Is(err, authorized.ErrCitationUnavailable),
		"old citation remained available: %v", err)

	postRevocation, err := harness.application.Service.Query(context.Background(), protocol.QueryRequest{
		Question:      "What is knote?",
		Authorization: fixture.Authorization(fixture.Alice, harness.sessionID),
	})
	permissionedAcceptanceNoError(t, invariant, err)
	permissionedAcceptanceRequire(t, invariant, len(postRevocation.Evidence.Items) == 1,
		"post-revocation cache/query evidence count = %d, want 1", len(postRevocation.Evidence.Items))
	permissionedAcceptanceRequire(t, invariant,
		postRevocation.Evidence.Items[0].Resource.ResourceID == permissionedAcceptanceOverviewID,
		"post-revocation cache/query returned resource %s, want %s",
		postRevocation.Evidence.Items[0].Resource.ResourceID, permissionedAcceptanceOverviewID)
	permissionedAcceptanceAssertNoCanaries(t, invariant, postRevocation)

	replayRunner := &permissionedAcceptanceRunner{application: harness.application}
	replayManager := New(Dependencies{
		Workspace:                    harness.workspace,
		Sessions:                     harness.store,
		EinoRunner:                   replayRunner,
		AuthorizationContextProvider: permissionedAcceptanceProvider(fixture.Alice),
		ProtectedContentAuthorizer:   harness.application.AuthorizeProtectedContent,
	})
	replayed, err := replayManager.Start(context.Background(), StartOptions{ResumeID: harness.sessionID})
	permissionedAcceptanceNoError(t, invariant, err)
	permissionedAcceptanceRequire(t, invariant, permissionedAcceptanceHasSafeSlash(replayed),
		"safe slash/local history was not preserved: %+v", replayed)
	permissionedAcceptanceRequire(t, invariant,
		strings.Contains(permissionedAcceptanceEventText(replayed), safeLocalMessage),
		"safe local runtime history %q was not preserved: %+v", safeLocalMessage, replayed)
	permissionedAcceptanceRequire(t, invariant, !permissionedAcceptanceHasBlock(replayed, initial.binding.BlockID),
		"revoked protected block %s replayed", initial.binding.BlockID)
	permissionedAcceptanceRequire(t, invariant,
		!strings.Contains(permissionedAcceptanceEventText(replayed), initial.result.Generation.Answer),
		"old protected answer replayed: %+v", replayed)
	permissionedAcceptanceAssertNoCanaries(t, invariant, replayed)
	t.Logf("revocation propagation=%s invalidated=%d denied=%d projection=%s authz=%s",
		report.PropagationLatency, report.InvalidatedResourceCount, report.DeniedCount,
		permissionedAcceptanceProjectionVersion, fixture.AuthorizationModelID)
}

func TestPermissionedAcceptanceSideChannelSurfacesHideCanaries(t *testing.T) {
	const invariant = "authorized side-channel surfaces reveal no hidden canary"
	harness := newPermissionedAcceptanceHarness(t, fixture.Bob, "sess_acceptance_surfaces")

	_, err := harness.manager.Start(context.Background(), StartOptions{})
	permissionedAcceptanceNoError(t, invariant, err)
	events := harness.manager.SendMessage(context.Background(), "What is knote?")
	permissionedAcceptanceRequire(t, invariant, !hasEvent(events, protocol.EventError),
		"Bob permissioned query failed: %+v", events)

	rawRetrievals := harness.probe.retrieveSnapshots()
	permissionedAcceptanceRequire(t, invariant, len(rawRetrievals) == 1,
		"raw retrieve calls = %d, want 1", len(rawRetrievals))
	permissionedAcceptanceRequire(t, invariant,
		permissionedAcceptanceCandidatesContain(rawRetrievals[0].Candidates, permissionedAcceptanceDeniedID),
		"fake KAG oracle did not contain hidden candidate %s", permissionedAcceptanceDeniedID)

	generated := harness.probe.generateSnapshots()
	permissionedAcceptanceRequire(t, invariant, len(generated) == 1,
		"generate calls = %d, want 1", len(generated))
	permissionedAcceptanceRequire(t, invariant, len(generated[0].Evidence) == 1,
		"generator received %d evidence items, want 1", len(generated[0].Evidence))
	permissionedAcceptanceRequire(t, invariant,
		generated[0].Evidence[0].Resource.ResourceID == permissionedAcceptanceOverviewID,
		"generator received resource %s, want %s",
		generated[0].Evidence[0].Resource.ResourceID, permissionedAcceptanceOverviewID)
	permissionedAcceptanceAssertNoCanaries(t, invariant, generated)

	snapshot := harness.runner.snapshot()
	permissionedAcceptanceRequire(t, invariant, len(snapshot.result.Evidence.Items) == 1,
		"Bob visible evidence count = %d, want 1", len(snapshot.result.Evidence.Items))
	permissionedAcceptanceRequire(t, invariant, snapshot.result.Generation.Trace.Count == 1,
		"authorized trace count = %d, want 1", snapshot.result.Generation.Trace.Count)
	permissionedAcceptanceRequire(t, invariant,
		permissionedAcceptancePayloadHasSurfaces(events,
			"count", "exists", "autocomplete", "pagination", "errors", "traces", "debug", "status"),
		"runtime events did not expose every acceptance surface: %+v", events)
	permissionedAcceptanceAssertNoCanaries(t, invariant, events)

	denied := newPermissionedAcceptanceHarness(t, "mallory", "sess_acceptance_denied_error")
	_, err = denied.manager.Start(context.Background(), StartOptions{})
	permissionedAcceptanceNoError(t, invariant, err)
	deniedEvents := denied.manager.SendMessage(context.Background(), "What is knote?")
	permissionedAcceptanceRequire(t, invariant, hasEvent(deniedEvents, protocol.EventError),
		"unknown principal did not receive a fail-closed error: %+v", deniedEvents)
	permissionedAcceptanceRequire(t, invariant, len(denied.probe.generateSnapshots()) == 0,
		"unknown principal reached generation")
	permissionedAcceptanceAssertNoCanaries(t, invariant, deniedEvents)
}

func TestPermissionedAcceptanceProtectedReplayFailsClosed(t *testing.T) {
	const invariant = "protected replay fails closed when authorization dependencies are incomplete"
	prime := newPermissionedAcceptanceHarness(t, fixture.Alice, "sess_acceptance_fail_closed")
	_, err := prime.manager.Start(context.Background(), StartOptions{})
	permissionedAcceptanceNoError(t, invariant, err)
	prime.manager.SendMessage(context.Background(), "/help")
	localEvents := prime.manager.Interrupt(context.Background())
	permissionedAcceptanceRequire(t, invariant,
		len(localEvents) == 1 && localEvents[0].Type == protocol.EventStatusUpdate,
		"safe local runtime history was not created: %+v", localEvents)
	safeLocalMessage := localEvents[0].Message
	queryEvents := prime.manager.SendMessage(context.Background(), "What is knote?")
	permissionedAcceptanceRequire(t, invariant, !hasEvent(queryEvents, protocol.EventError),
		"fixture query failed while priming replay: %+v", queryEvents)
	protected := prime.runner.snapshot()

	tests := []struct {
		name       string
		provider   AuthorizationContextProvider
		authorizer ProtectedContentAuthorizer
		wantError  bool
		canary     string
	}{
		{name: "provider missing", authorizer: prime.application.AuthorizeProtectedContent},
		{
			name: "provider unavailable",
			provider: func(context.Context, string) (protocol.AuthorizationContext, error) {
				return protocol.AuthorizationContext{}, errors.New("AUTH_PROVIDER_FAILURE_CANARY")
			},
			authorizer: prime.application.AuthorizeProtectedContent,
			wantError:  true,
			canary:     "AUTH_PROVIDER_FAILURE_CANARY",
		},
		{name: "authorizer missing", provider: permissionedAcceptanceProvider(fixture.Alice)},
		{
			name:     "authorizer unavailable",
			provider: permissionedAcceptanceProvider(fixture.Alice),
			authorizer: func(context.Context, protocol.AuthorizationContext, protocol.ProtectedContentBinding) error {
				return errors.New("AUTHORIZER_FAILURE_CANARY")
			},
			canary: "AUTHORIZER_FAILURE_CANARY",
		},
		{
			name:     "authorizer partial",
			provider: permissionedAcceptanceProvider(fixture.Alice),
			authorizer: func(_ context.Context, _ protocol.AuthorizationContext, binding protocol.ProtectedContentBinding) error {
				if len(binding.Resources) < 2 {
					return errors.New("fixture did not contain enough resources for a partial decision")
				}
				return fmt.Errorf("PARTIAL_DECISION_CANARY: 1/%d decisions", len(binding.Resources))
			},
			canary: "PARTIAL_DECISION_CANARY",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := New(Dependencies{
				Workspace:                    prime.workspace,
				Sessions:                     prime.store,
				EinoRunner:                   &permissionedAcceptanceRunner{application: prime.application},
				AuthorizationContextProvider: test.provider,
				ProtectedContentAuthorizer:   test.authorizer,
			})
			events, startErr := manager.Start(context.Background(), StartOptions{ResumeID: prime.sessionID})
			if test.wantError {
				permissionedAcceptanceRequire(t, invariant,
					startErr != nil && startErr.Error() == permissionedResumeErrorMessage,
					"provider-unavailable resume error = %v", startErr)
				permissionedAcceptanceRequire(t, invariant, len(events) == 0,
					"provider-unavailable resume returned events: %+v", events)
			} else {
				permissionedAcceptanceNoError(t, invariant, startErr)
				permissionedAcceptanceRequire(t, invariant, permissionedAcceptanceHasSafeSlash(events),
					"safe slash/local history was dropped: %+v", events)
				permissionedAcceptanceRequire(t, invariant,
					strings.Contains(permissionedAcceptanceEventText(events), safeLocalMessage),
					"safe local runtime history %q was dropped: %+v", safeLocalMessage, events)
				permissionedAcceptanceRequire(t, invariant,
					!permissionedAcceptanceHasBlock(events, protected.binding.BlockID),
					"protected block %s replayed", protected.binding.BlockID)
				permissionedAcceptanceRequire(t, invariant,
					!strings.Contains(permissionedAcceptanceEventText(events), protected.result.Generation.Answer),
					"protected answer replayed: %+v", events)
			}
			permissionedAcceptanceAssertNoCanaries(t, invariant, events)
			if test.canary != "" {
				permissionedAcceptanceAssertAbsent(t, invariant, test.canary, events, startErr)
			}
		})
	}
}

func TestPermissionedAcceptanceRevocationPropagationPercentiles(t *testing.T) {
	const invariant = "revocation propagation satisfies bounded P95 and P99 fixture SLOs"
	prime := newPermissionedAcceptanceHarness(t, fixture.Alice, "sess_acceptance_latency")
	_, err := prime.manager.Start(context.Background(), StartOptions{})
	permissionedAcceptanceNoError(t, invariant, err)
	events := prime.manager.SendMessage(context.Background(), "What is knote?")
	permissionedAcceptanceRequire(t, invariant, !hasEvent(events, protocol.EventError),
		"fixture query failed while creating latency binding: %+v", events)
	protected := prime.runner.snapshot()

	samples := make([]time.Duration, 0, permissionedAcceptancePropagationSamples)
	for index := 0; index < permissionedAcceptancePropagationSamples; index++ {
		cache, cacheErr := authorized.NewQueryCache(4)
		permissionedAcceptanceNoError(t, invariant, cacheErr)
		application, applicationErr := fixture.NewApplication(prime.probe, fixture.ApplicationOptions{
			Cache:            cache,
			RetrieverVersion: permissionedAcceptanceRetrieverVersion,
			PromptVersion:    permissionedAcceptancePromptVersion,
		})
		permissionedAcceptanceNoError(t, invariant, applicationErr)
		removeErr := application.RemoveTuple(authz.Tuple{
			User:     "user:" + fixture.Alice,
			Relation: authz.RelationMember,
			Object:   permissionedAcceptancePrivateReaders,
		})
		permissionedAcceptanceNoError(t, invariant, removeErr)

		revokedAt := time.Now().UTC()
		report, applyErr := application.Apply(context.Background(), authorized.RevocationRequest{
			Authorization: protected.authorization,
			Binding:       protected.binding,
			ResourceIDs:   []protocol.ResourceID{permissionedAcceptanceIntroID},
			RevokedAt:     revokedAt,
		})
		permissionedAcceptanceNoError(t, invariant, applyErr)
		permissionedAcceptanceRequire(t, invariant, report.PropagationLatency >= 0,
			"sample %d reported negative propagation latency %s", index, report.PropagationLatency)
		permissionedAcceptanceRequire(t, invariant, report.DeniedCount == 1,
			"sample %d did not observe the revoked authorization: %#v", index, report)
		samples = append(samples, report.PropagationLatency)
	}

	p95 := permissionedAcceptancePercentile(samples, 95)
	p99 := permissionedAcceptancePercentile(samples, 99)
	permissionedAcceptanceRequire(t, invariant, p95 <= permissionedAcceptanceP95SLO,
		"P95 propagation %s exceeds %s across %d no-sleep samples",
		p95, permissionedAcceptanceP95SLO, len(samples))
	permissionedAcceptanceRequire(t, invariant, p99 <= permissionedAcceptanceP99SLO,
		"P99 propagation %s exceeds %s across %d no-sleep samples",
		p99, permissionedAcceptanceP99SLO, len(samples))
	t.Logf("revocation samples=%d p95=%s/%s p99=%s/%s projection=%s authz=%s",
		len(samples), p95, permissionedAcceptanceP95SLO, p99, permissionedAcceptanceP99SLO,
		permissionedAcceptanceProjectionVersion, fixture.AuthorizationModelID)
}

type permissionedAcceptanceHarness struct {
	workspace   string
	sessionID   string
	store       local.Store
	application *fixture.Application
	probe       *permissionedAcceptanceKAGProbe
	runner      *permissionedAcceptanceRunner
	manager     *Manager
}

func newPermissionedAcceptanceHarness(t *testing.T, principal, sessionID string) permissionedAcceptanceHarness {
	t.Helper()
	const invariant = "acceptance harness initializes deterministic fake KAG and local authorization"
	workspace := t.TempDir()
	cache, err := authorized.NewQueryCache(32)
	permissionedAcceptanceNoError(t, invariant, err)
	probe := &permissionedAcceptanceKAGProbe{backend: kag.Client{
		AdapterPath: "adapters/kag/knote_kag_adapter.py",
		Workspace:   workspace,
		Fake:        true,
	}}
	application, err := fixture.NewApplication(probe, fixture.ApplicationOptions{
		Cache:            cache,
		RetrieverVersion: permissionedAcceptanceRetrieverVersion,
		PromptVersion:    permissionedAcceptancePromptVersion,
	})
	permissionedAcceptanceNoError(t, invariant, err)
	store := local.New(workspace)
	runner := &permissionedAcceptanceRunner{application: application}
	manager := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		EinoRunner:                   runner,
		AuthorizationContextProvider: permissionedAcceptanceProvider(principal),
		ProtectedContentAuthorizer:   application.AuthorizeProtectedContent,
		NewSessionID:                 func() string { return sessionID },
	})
	return permissionedAcceptanceHarness{
		workspace: workspace, sessionID: sessionID, store: store,
		application: application, probe: probe, runner: runner, manager: manager,
	}
}

func permissionedAcceptanceProvider(principal string) AuthorizationContextProvider {
	return func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		return fixture.Authorization(principal, sessionID), nil
	}
}

type permissionedAcceptanceRunSnapshot struct {
	authorization protocol.AuthorizationContext
	result        authorized.QueryResult
	binding       protocol.ProtectedContentBinding
	history       []protocol.Event
}

type permissionedAcceptanceRunner struct {
	application *fixture.Application

	mu   sync.Mutex
	last permissionedAcceptanceRunSnapshot
}

func (r *permissionedAcceptanceRunner) Ready(context.Context) error {
	if r == nil || r.application == nil || r.application.Service == nil {
		return errors.New("permissioned acceptance runner is unavailable")
	}
	return nil
}

func (*permissionedAcceptanceRunner) ToolInventory(context.Context) ([]RunnerToolInfo, error) {
	return []RunnerToolInfo{{Name: "knote_query", Description: "permissioned acceptance query"}}, nil
}

func (r *permissionedAcceptanceRunner) Run(ctx context.Context, input EinoRunInput) ([]protocol.Event, error) {
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok {
		return nil, errors.New("permissioned acceptance query requires trusted authorization")
	}
	result, err := r.application.Service.Query(ctx, protocol.QueryRequest{
		Question: input.Message, Authorization: authorization,
	})
	if err != nil {
		return nil, err
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
	if err != nil {
		return nil, err
	}
	surfaces := permissionedAcceptanceSurfaces(result)
	events := []protocol.Event{
		protocol.NewEvent(protocol.EventToolComplete, input.SessionID, "authorized query complete", map[string]any{
			"tool": "knote_query", "surfaces": surfaces,
		}),
		protocol.NewEvent(protocol.EventStatusUpdate, input.SessionID, "authorized projection serving", surfaces["status"]),
		protocol.NewEvent(protocol.EventAssistantDone, input.SessionID, result.Generation.Answer, map[string]any{
			"citations": result.Generation.Citations, "surfaces": surfaces,
		}),
	}
	for index := range events {
		copy := binding
		events[index].ProtectedContent = &copy
	}
	r.mu.Lock()
	r.last = permissionedAcceptanceRunSnapshot{
		authorization: authorization,
		result:        result,
		binding:       binding,
		history:       append([]protocol.Event(nil), input.History...),
	}
	r.mu.Unlock()
	return events, nil
}

func (r *permissionedAcceptanceRunner) snapshot() permissionedAcceptanceRunSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := r.last
	snapshot.history = append([]protocol.Event(nil), r.last.history...)
	return snapshot
}

func permissionedAcceptanceSurfaces(result authorized.QueryResult) map[string]any {
	resourceIDs := make([]protocol.ResourceID, len(result.Evidence.Items))
	autocomplete := make([]string, len(result.Evidence.Items))
	exists := make(map[string]bool, len(result.Evidence.Items))
	for index, item := range result.Evidence.Items {
		resourceIDs[index] = item.Resource.ResourceID
		autocomplete[index] = item.Citation.Handle
		exists[item.Citation.Handle] = true
	}
	return map[string]any{
		"count":        len(resourceIDs),
		"exists":       exists,
		"autocomplete": autocomplete,
		"pagination": map[string]any{
			"items": resourceIDs, "next_cursor": "",
		},
		"errors": []string{},
		"traces": result.Generation.Trace,
		"debug": map[string]any{
			"authorized_resource_ids": resourceIDs,
			"projection_version":      result.Evidence.ProjectionVersion,
			"authorization_model_id":  result.Evidence.AuthorizationModelID,
		},
		"status": map[string]any{
			"state": "serving", "visible": len(resourceIDs),
			"projection_version": result.Evidence.ProjectionVersion,
		},
	}
}

type permissionedAcceptanceKAGProbe struct {
	backend kag.PrimitiveBackend

	mu        sync.Mutex
	retrieved []kag.RetrieveResult
	generated []kag.GenerateRequest
}

func (p *permissionedAcceptanceKAGProbe) Retrieve(ctx context.Context, request kag.RetrieveRequest) (kag.RetrieveResult, error) {
	result, err := p.backend.Retrieve(ctx, request)
	if err != nil {
		return result, err
	}
	result.Candidates = append([]kag.CandidateHandle(nil), result.Candidates...)
	p.mu.Lock()
	p.retrieved = append(p.retrieved, result)
	p.mu.Unlock()
	return result, nil
}

func (p *permissionedAcceptanceKAGProbe) Expand(ctx context.Context, request kag.ExpandRequest) (kag.ExpandResult, error) {
	return p.backend.Expand(ctx, request)
}

func (p *permissionedAcceptanceKAGProbe) Generate(ctx context.Context, request kag.GenerateRequest) (kag.GenerateResult, error) {
	copy := request
	copy.Evidence = append([]kag.AuthorizedEvidence(nil), request.Evidence...)
	p.mu.Lock()
	p.generated = append(p.generated, copy)
	p.mu.Unlock()
	return p.backend.Generate(ctx, request)
}

func (p *permissionedAcceptanceKAGProbe) retrieveSnapshots() []kag.RetrieveResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]kag.RetrieveResult(nil), p.retrieved...)
}

func (p *permissionedAcceptanceKAGProbe) generateSnapshots() []kag.GenerateRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]kag.GenerateRequest(nil), p.generated...)
}

func permissionedAcceptanceEvidenceByID(result authorized.QueryResult, resourceID protocol.ResourceID) (protocol.EvidenceItem, bool) {
	for _, item := range result.Evidence.Items {
		if item.Resource.ResourceID == resourceID {
			return item, true
		}
	}
	return protocol.EvidenceItem{}, false
}

func permissionedAcceptanceCandidatesContain(candidates []kag.CandidateHandle, resourceID protocol.ResourceID) bool {
	for _, candidate := range candidates {
		if candidate.Resource.ResourceID == resourceID {
			return true
		}
	}
	return false
}

func permissionedAcceptanceHasSafeSlash(events []protocol.Event) bool {
	for _, event := range events {
		if event.Type == protocol.EventAssistantDone && eventPayloadValue(event.Payload, "source") == "slash" {
			return true
		}
	}
	return false
}

func permissionedAcceptanceHasBlock(events []protocol.Event, blockID string) bool {
	for _, event := range events {
		if event.ProtectedContent != nil && event.ProtectedContent.BlockID == blockID {
			return true
		}
	}
	return false
}

func permissionedAcceptancePayloadHasSurfaces(events []protocol.Event, names ...string) bool {
	for _, event := range events {
		payload, ok := event.Payload.(map[string]any)
		if !ok {
			continue
		}
		surfaces, ok := payload["surfaces"].(map[string]any)
		if !ok {
			continue
		}
		for _, name := range names {
			if _, ok := surfaces[name]; !ok {
				return false
			}
		}
		return true
	}
	return false
}

func permissionedAcceptanceEventText(events []protocol.Event) string {
	var builder strings.Builder
	for _, event := range events {
		builder.WriteString(event.Message)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func permissionedAcceptancePercentile(samples []time.Duration, percentile int) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*percentile+99)/100 - 1
	if index < 0 {
		index = 0
	}
	return ordered[index]
}

func permissionedAcceptanceAssertNoCanaries(t *testing.T, invariant string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	permissionedAcceptanceNoError(t, invariant, err)
	for _, canary := range permissionedAcceptanceHiddenCanaries {
		permissionedAcceptanceRequire(t, invariant, !strings.Contains(string(encoded), canary),
			"surface leaked hidden canary %q: %s", canary, encoded)
	}
}

func permissionedAcceptanceAssertAbsent(t *testing.T, invariant, canary string, values ...any) {
	t.Helper()
	for _, value := range values {
		if value == nil {
			continue
		}
		encoded := fmt.Sprintf("%+v", value)
		permissionedAcceptanceRequire(t, invariant, !strings.Contains(encoded, canary),
			"authorization dependency detail %q leaked: %s", canary, encoded)
	}
}

func permissionedAcceptanceNoError(t *testing.T, invariant string, err error) {
	t.Helper()
	permissionedAcceptanceRequire(t, invariant, err == nil, "unexpected error: %v", err)
}

func permissionedAcceptanceRequire(t *testing.T, invariant string, condition bool, format string, args ...any) {
	t.Helper()
	if condition {
		return
	}
	prefix := []any{invariant, permissionedAcceptanceProjectionVersion, fixture.AuthorizationModelID}
	t.Fatalf("invariant=%s projection=%s authz=%s: "+format, append(prefix, args...)...)
}
