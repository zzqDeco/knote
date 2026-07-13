package authorized_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestPermissionedAcceptancePolicyOracleAndRetrievalMetrics(t *testing.T) {
	const invariant = "policy oracle permits only principal-authorized evidence"
	backend := newAcceptanceBackend(fixtureCandidates()...)
	service, err := fixture.New(backend)
	if err != nil {
		acceptanceFatalf(t, invariant, "create fixture service: %v", err)
	}

	tests := []struct {
		principal string
		session   string
		want      []protocol.ResourceID
	}{
		{principal: fixture.Alice, session: "session-acceptance-alice", want: []protocol.ResourceID{fixtureIntroID, fixtureOverviewID}},
		{principal: fixture.Bob, session: "session-acceptance-bob", want: []protocol.ResourceID{fixtureOverviewID}},
	}
	truePositives := 0
	authorizedRelevant := 0
	returned := 0
	dropped := 0
	emptyResults := 0
	unauthorizedEvidence := 0
	falseAllows := 0
	queryLatencies := make([]time.Duration, 0, len(tests))

	for _, test := range tests {
		authorization := fixture.Authorization(test.principal, test.session)
		started := time.Now()
		result, queryErr := service.Query(context.Background(), protocol.QueryRequest{
			Question: "What is knote?", Authorization: authorization,
		})
		queryLatencies = append(queryLatencies, time.Since(started))
		if queryErr != nil {
			emptyResults++
			acceptanceFatalf(t, invariant, "%s query failed: %v", test.principal, queryErr)
		}
		if err := result.Evidence.ValidateFor(authorization); err != nil {
			acceptanceFatalf(t, invariant, "%s evidence package is invalid: %v", test.principal, err)
		}
		if result.Evidence.ProjectionVersion != acceptanceProjectionVersion ||
			result.Evidence.AuthorizationModelID != fixture.AuthorizationModelID {
			acceptanceFatalf(t, invariant, "%s result version binding = projection %q, authz %q",
				test.principal, result.Evidence.ProjectionVersion, result.Evidence.AuthorizationModelID)
		}

		got := resourceIDs(result.Evidence.Items)
		if !reflect.DeepEqual(got, test.want) {
			acceptanceFatalf(t, invariant, "%s evidence = %v, want %v", test.principal, got, test.want)
		}
		if !reflect.DeepEqual(result.Generation.EvidenceResourceIDs, test.want) {
			acceptanceFatalf(t, invariant, "%s generation evidence = %v, want %v",
				test.principal, result.Generation.EvidenceResourceIDs, test.want)
		}

		allowed := make(map[protocol.ResourceID]bool, len(test.want))
		for _, resourceID := range test.want {
			allowed[resourceID] = true
		}
		authorizedRelevant += len(allowed)
		returned += len(got)
		dropped += len(fixtureCandidates()) - len(got)
		if len(got) == 0 {
			emptyResults++
		}
		for _, resourceID := range got {
			if allowed[resourceID] {
				truePositives++
				continue
			}
			unauthorizedEvidence++
		}
		for _, decision := range result.Evidence.Decisions {
			if decision.Authorized() && !allowed[decision.Resource.ResourceID] {
				falseAllows++
			}
		}

		if strings.Contains(result.Generation.Answer, fixtureDeniedCanaryContent) {
			acceptanceFatalf(t, invariant, "%s answer contains the denied canary", test.principal)
		}
		if test.principal == fixture.Bob && strings.Contains(result.Generation.Answer, fixtureIntroContent) {
			acceptanceFatalf(t, invariant, "Bob answer contains Alice-only evidence")
		}
	}

	recallAt3 := float64(truePositives) / float64(authorizedRelevant)
	precisionAt3 := float64(truePositives) / float64(returned)
	dropRate := float64(dropped) / float64(len(tests)*len(fixtureCandidates()))
	emptyResultRate := float64(emptyResults) / float64(len(tests))
	if recallAt3 != 1 || precisionAt3 != 1 || dropRate != 0.5 || emptyResultRate != 0 {
		acceptanceFatalf(t, invariant,
			"metrics recall@3=%.3f precision@3=%.3f drop_rate=%.3f empty_result_rate=%.3f",
			recallAt3, precisionAt3, dropRate, emptyResultRate)
	}
	if unauthorizedEvidence != 0 || falseAllows != 0 {
		acceptanceFatalf(t, invariant, "unauthorized_evidence=%d false_allows=%d",
			unauthorizedEvidence, falseAllows)
	}
	if maximum := maxDuration(queryLatencies); maximum > acceptanceQueryBudget {
		acceptanceFatalf(t, invariant, "query latency %s exceeds budget %s", maximum, acceptanceQueryBudget)
	}

	stats := backend.stats()
	if len(stats.retrieveRequests) != 2 || len(stats.generateRequests) != 2 || stats.expandCalls != 0 {
		acceptanceFatalf(t, invariant, "backend calls retrieve=%d generate=%d expand=%d",
			len(stats.retrieveRequests), len(stats.generateRequests), stats.expandCalls)
	}
	for _, request := range stats.retrieveRequests {
		if request.Limit != 3 {
			acceptanceFatalf(t, invariant, "retrieve limit=%d, want 3", request.Limit)
		}
	}
	if maximum := maxDuration(stats.retrieveLatencies); maximum > acceptanceRetrievalBudget {
		acceptanceFatalf(t, invariant, "retrieval latency %s exceeds budget %s", maximum, acceptanceRetrievalBudget)
	}
	t.Logf(
		"projection=%s authz_model=%s recall@3=%.3f precision@3=%.3f drop_rate=%.3f empty_result_rate=%.3f unauthorized_evidence=%d false_allows=%d retrieval_p99=%s query_p99=%s",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, recallAt3, precisionAt3, dropRate,
		emptyResultRate, unauthorizedEvidence, falseAllows,
		percentileDuration(stats.retrieveLatencies, 0.99), percentileDuration(queryLatencies, 0.99),
	)
}

func TestPermissionedAcceptanceVisibleEntityHiddenClaim(t *testing.T) {
	const invariant = "visible entity does not make a protected claim visible"
	const (
		sourceContent = "authorized source document"
		entityContent = "visible entity"
		claimContent  = "protected claim"
	)
	source := acceptanceResource(acceptanceSourceID, protocol.ResourceDocument, sourceContent)
	entity := acceptanceResource(acceptanceEntityID, protocol.ResourceEntity, entityContent)
	claim := acceptanceResource(acceptanceDeniedID, protocol.ResourceClaim, claimContent)
	backend := newAcceptanceBackend(
		kag.CandidateHandle{Resource: entity, Score: 0.95},
		kag.CandidateHandle{Resource: claim, Score: 0.90},
	)
	loader := &acceptanceLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		entity.ResourceID: acceptanceEvidenceItem(entity, entityContent, protocol.DerivationAnySupport, []protocol.ProvenanceSupport{{
			SupportID: "support_visible_entity", Resource: entity,
			Evidence: []protocol.ResourceHandle{source}, Complete: true,
		}}),
		claim.ResourceID: acceptanceEvidenceItem(claim, claimContent, protocol.DerivationAnySupport, []protocol.ProvenanceSupport{{
			SupportID: "support_hidden_claim", Resource: claim,
			Evidence: []protocol.ResourceHandle{source}, Complete: true,
		}}),
	}}
	authorizer := localRecordingAuthorizer(t, invariant, []protocol.ResourceHandle{source, entity, claim}, map[protocol.ResourceID]bool{
		source.ResourceID: true,
		entity.ResourceID: true,
	})
	service := acceptanceService(t, invariant, backend, authorizer, loader, 2, 2)
	authorization := acceptanceAuthorization("session-visible-entity")

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "Which claims are visible?", Authorization: authorization,
	})
	if err != nil {
		acceptanceFatalf(t, invariant, "query failed: %v", err)
	}
	if got, want := resourceIDs(result.Evidence.Items), []protocol.ResourceID{entity.ResourceID}; !reflect.DeepEqual(got, want) {
		acceptanceFatalf(t, invariant, "evidence=%v, want %v", got, want)
	}
	if strings.Contains(result.Generation.Answer, claimContent) ||
		containsResource(loader.recordedCalls(), claim.ResourceID) {
		acceptanceFatalf(t, invariant, "protected claim reached loader or generation")
	}
	for _, decision := range result.Evidence.Decisions {
		if decision.Resource.ResourceID == claim.ResourceID {
			acceptanceFatalf(t, invariant, "protected claim received an evidence decision")
		}
	}

	authzStats := authorizer.stats()
	if len(authzStats.requests) != 2 || totalBatchChecks(authzStats.requests) != 4 {
		acceptanceFatalf(t, invariant, "BatchCheck calls=%d checks=%d, want calls=2 checks=4",
			len(authzStats.requests), totalBatchChecks(authzStats.requests))
	}
	if maximum := maxDuration(authzStats.latencies); maximum > acceptanceBatchCheckBudget {
		acceptanceFatalf(t, invariant, "BatchCheck latency %s exceeds budget %s", maximum, acceptanceBatchCheckBudget)
	}
	t.Logf("projection=%s authz_model=%s BatchCheck_count=%d BatchCheck_checks=%d BatchCheck_p99=%s unauthorized_evidence=0 false_allows=0",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, len(authzStats.requests),
		totalBatchChecks(authzStats.requests), percentileDuration(authzStats.latencies, 0.99))
}

func TestPermissionedAcceptanceProvenancePathSemantics(t *testing.T) {
	const invariant = "provenance mode and every participating path obey authorization"
	const (
		sourceContent    = "path source"
		entityContent    = "path entity"
		deniedContent    = "denied intermediate claim"
		alternateContent = "alternate supporting claim"
		derivedContent   = "derived path answer"
	)
	source := acceptanceResource(acceptanceSourceID, protocol.ResourceDocument, sourceContent)
	entity := acceptanceResource(acceptanceEntityID, protocol.ResourceEntity, entityContent)
	denied := acceptanceResource(acceptanceDeniedID, protocol.ResourceClaim, deniedContent)
	alternate := acceptanceResource(acceptanceAlternateID, protocol.ResourceClaim, alternateContent)
	derived := acceptanceResource(acceptanceDerivedID, protocol.ResourceDerivedArtifact, derivedContent)
	allResources := []protocol.ResourceHandle{source, entity, denied, alternate, derived}
	entitySupport := func(complete bool) protocol.ProvenanceSupport {
		return protocol.ProvenanceSupport{
			SupportID: "support_entity", Resource: entity,
			Evidence: []protocol.ResourceHandle{source}, Complete: complete,
		}
	}
	claimSupport := func(resource protocol.ResourceHandle, supportID string, complete bool) protocol.ProvenanceSupport {
		return protocol.ProvenanceSupport{
			SupportID: supportID, Resource: resource,
			Evidence: []protocol.ResourceHandle{source}, Complete: complete,
		}
	}

	tests := []struct {
		name               string
		mode               protocol.DerivationMode
		supports           []protocol.ProvenanceSupport
		allowed            map[protocol.ResourceID]bool
		wantSuccess        bool
		wantPathResources  int
		wantBatchCalls     int
		wantBatchChecks    int
		deniedIntermediate bool
	}{
		{
			name: "any-support complete entity branch", mode: protocol.DerivationAnySupport,
			supports:    []protocol.ProvenanceSupport{entitySupport(true)},
			allowed:     map[protocol.ResourceID]bool{derived.ResourceID: true, entity.ResourceID: true, source.ResourceID: true},
			wantSuccess: true, wantPathResources: 3, wantBatchCalls: 2, wantBatchChecks: 4,
		},
		{
			name: "any-support complete alternate branch", mode: protocol.DerivationAnySupport,
			supports:    []protocol.ProvenanceSupport{claimSupport(alternate, "support_alternate", true)},
			allowed:     map[protocol.ResourceID]bool{derived.ResourceID: true, alternate.ResourceID: true, source.ResourceID: true},
			wantSuccess: true, wantPathResources: 3, wantBatchCalls: 2, wantBatchChecks: 4,
		},
		{
			name: "any-support rejects incomplete branch", mode: protocol.DerivationAnySupport,
			supports:    []protocol.ProvenanceSupport{entitySupport(false)},
			allowed:     map[protocol.ResourceID]bool{derived.ResourceID: true, entity.ResourceID: true, source.ResourceID: true},
			wantSuccess: false, wantBatchCalls: 1, wantBatchChecks: 1,
		},
		{
			name: "all-required combines partial supports", mode: protocol.DerivationAllRequired,
			supports: []protocol.ProvenanceSupport{
				entitySupport(false), claimSupport(alternate, "support_alternate", false),
			},
			allowed: map[protocol.ResourceID]bool{
				derived.ResourceID: true, entity.ResourceID: true,
				alternate.ResourceID: true, source.ResourceID: true,
			},
			wantSuccess: true, wantPathResources: 4, wantBatchCalls: 2, wantBatchChecks: 5,
		},
		{
			name: "all-required denied intermediate blocks path", mode: protocol.DerivationAllRequired,
			supports: []protocol.ProvenanceSupport{
				entitySupport(false), claimSupport(denied, "support_denied", false),
			},
			allowed: map[protocol.ResourceID]bool{
				derived.ResourceID: true, entity.ResourceID: true, source.ResourceID: true,
			},
			wantSuccess: false, wantPathResources: 4, wantBatchCalls: 2, wantBatchChecks: 5,
			deniedIntermediate: true,
		},
	}

	expectedCompletePaths := 0
	completePaths := 0
	unauthorizedPathParticipation := 0
	batchCalls := 0
	batchChecks := 0
	var batchLatencies []time.Duration
	var retrievalLatencies []time.Duration
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newAcceptanceBackend(kag.CandidateHandle{Resource: derived, Score: 0.99})
			loader := &acceptanceLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				derived.ResourceID: acceptanceEvidenceItem(derived, derivedContent, test.mode, test.supports),
			}}
			authorizer := localRecordingAuthorizer(t, invariant, allResources, test.allowed)
			service := acceptanceService(t, invariant, backend, authorizer, loader, 1, 1)
			result, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "Is the path authorized?", Authorization: acceptanceAuthorization("session-" + strings.ReplaceAll(test.name, " ", "-")),
			})

			backendStats := backend.stats()
			authzStats := authorizer.stats()
			batchCalls += len(authzStats.requests)
			batchChecks += totalBatchChecks(authzStats.requests)
			batchLatencies = append(batchLatencies, authzStats.latencies...)
			retrievalLatencies = append(retrievalLatencies, backendStats.retrieveLatencies...)
			if len(authzStats.requests) != test.wantBatchCalls || totalBatchChecks(authzStats.requests) != test.wantBatchChecks {
				acceptanceFatalf(t, invariant, "BatchCheck calls=%d checks=%d, want calls=%d checks=%d",
					len(authzStats.requests), totalBatchChecks(authzStats.requests), test.wantBatchCalls, test.wantBatchChecks)
			}
			if len(loader.recordedCalls()) != 1 {
				acceptanceFatalf(t, invariant, "loader calls=%d, want 1", len(loader.recordedCalls()))
			}

			if test.wantSuccess {
				expectedCompletePaths++
				if err != nil {
					acceptanceFatalf(t, invariant, "authorized path failed: %v", err)
				}
				if len(result.Evidence.Decisions) != test.wantPathResources {
					acceptanceFatalf(t, invariant, "authorized path decisions=%d, want %d",
						len(result.Evidence.Decisions), test.wantPathResources)
				}
				if len(backendStats.generateRequests) != 1 ||
					!reflect.DeepEqual(evidenceIDs(backendStats.generateRequests[0].Evidence), []protocol.ResourceID{derived.ResourceID}) {
					acceptanceFatalf(t, invariant, "authorized path generation requests=%v", backendStats.generateRequests)
				}
				completePaths++
				return
			}

			if err == nil {
				acceptanceFatalf(t, invariant, "unauthorized or incomplete path succeeded")
			}
			if len(backendStats.generateRequests) != 0 {
				unauthorizedPathParticipation += len(backendStats.generateRequests)
				acceptanceFatalf(t, invariant, "blocked path reached generation")
			}
			if test.deniedIntermediate {
				foundDeniedCheck := false
				for _, request := range authzStats.requests {
					for _, check := range request.Checks {
						if check.Object == denied.AuthorizationID {
							foundDeniedCheck = true
						}
					}
				}
				if !foundDeniedCheck {
					acceptanceFatalf(t, invariant, "denied intermediate was not checked as path provenance")
				}
			}
		})
	}

	pathCompleteness := float64(completePaths) / float64(expectedCompletePaths)
	if pathCompleteness != 1 || unauthorizedPathParticipation != 0 {
		acceptanceFatalf(t, invariant, "path_completeness=%.3f unauthorized_path_participation=%d",
			pathCompleteness, unauthorizedPathParticipation)
	}
	if maximum := maxDuration(batchLatencies); maximum > acceptanceBatchCheckBudget {
		acceptanceFatalf(t, invariant, "BatchCheck latency %s exceeds budget %s", maximum, acceptanceBatchCheckBudget)
	}
	if maximum := maxDuration(retrievalLatencies); maximum > acceptanceRetrievalBudget {
		acceptanceFatalf(t, invariant, "retrieval latency %s exceeds budget %s", maximum, acceptanceRetrievalBudget)
	}
	t.Logf("projection=%s authz_model=%s path_completeness=%.3f unauthorized_path_participation=%d BatchCheck_count=%d BatchCheck_checks=%d BatchCheck_p99=%s retrieval_p99=%s",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, pathCompleteness,
		unauthorizedPathParticipation, batchCalls, batchChecks,
		percentileDuration(batchLatencies, 0.99), percentileDuration(retrievalLatencies, 0.99))
}

func TestPermissionedAcceptanceAuthorizationFailuresFailClosed(t *testing.T) {
	const invariant = "authorization timeout or partial decision fails closed"
	first := acceptanceResource(acceptanceSourceID, protocol.ResourceDocument, "first document")
	second := acceptanceResource(acceptanceSecondDocID, protocol.ResourceDocument, "second document")
	candidates := []kag.CandidateHandle{{Resource: first, Score: 0.9}, {Resource: second, Score: 0.8}}

	tests := []struct {
		name      string
		decide    batchDecisionFunc
		wantError error
	}{
		{
			name: "timeout",
			decide: func(context.Context, int, authz.BatchCheckRequest) ([]authz.Decision, error) {
				return nil, fmt.Errorf("%w: deterministic acceptance timeout", authz.ErrTimeout)
			},
			wantError: authz.ErrTimeout,
		},
		{
			name: "partial decision",
			decide: func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				decisions := acceptanceDecisions(request, true)
				return decisions[:len(decisions)-1], nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newAcceptanceBackend(candidates...)
			loader := &acceptanceLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				first.ResourceID:  selfEvidenceItem(first, "first document"),
				second.ResourceID: selfEvidenceItem(second, "second document"),
			}}
			authorizer := &recordingAuthorizer{decide: test.decide}
			service := acceptanceService(t, invariant, backend, authorizer, loader, 2, 2)
			started := time.Now()
			_, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "fail closed", Authorization: acceptanceAuthorization("session-fail-closed-" + test.name),
			})
			if elapsed := time.Since(started); elapsed > acceptanceQueryBudget {
				acceptanceFatalf(t, invariant, "%s query latency %s exceeds budget %s", test.name, elapsed, acceptanceQueryBudget)
			}
			if err == nil {
				acceptanceFatalf(t, invariant, "%s query succeeded", test.name)
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				acceptanceFatalf(t, invariant, "%s error=%v, want %v", test.name, err, test.wantError)
			}
			if calls := loader.recordedCalls(); len(calls) != 0 {
				acceptanceFatalf(t, invariant, "%s reached loader: %v", test.name, calls)
			}
			backendStats := backend.stats()
			if len(backendStats.generateRequests) != 0 {
				acceptanceFatalf(t, invariant, "%s reached generation", test.name)
			}
			authzStats := authorizer.stats()
			if len(authzStats.requests) != 1 || totalBatchChecks(authzStats.requests) != 2 {
				acceptanceFatalf(t, invariant, "%s BatchCheck calls=%d checks=%d, want calls=1 checks=2",
					test.name, len(authzStats.requests), totalBatchChecks(authzStats.requests))
			}
		})
	}
}

func TestPermissionedAcceptanceCrossTenantStopsBeforeContentBoundaries(t *testing.T) {
	const invariant = "cross-tenant candidate never reaches authorization, loader, or generator"
	crossTenant := acceptanceResource(acceptanceSourceID, protocol.ResourceDocument, "cross tenant")
	crossTenant.TenantID = "tenant_other"
	backend := newAcceptanceBackend(kag.CandidateHandle{Resource: crossTenant, Score: 0.99})
	loader := &acceptanceLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		crossTenant.ResourceID: selfEvidenceItem(crossTenant, "cross tenant"),
	}}
	authorizer := &recordingAuthorizer{decide: func(_ context.Context, _ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return acceptanceDecisions(request, true), nil
	}}
	service := acceptanceService(t, invariant, backend, authorizer, loader, 1, 1)

	_, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "cross tenant", Authorization: acceptanceAuthorization("session-cross-tenant"),
	})
	if err == nil {
		acceptanceFatalf(t, invariant, "cross-tenant query succeeded")
	}
	if len(authorizer.stats().requests) != 0 {
		acceptanceFatalf(t, invariant, "cross-tenant candidate reached BatchCheck")
	}
	if len(loader.recordedCalls()) != 0 {
		acceptanceFatalf(t, invariant, "cross-tenant candidate reached loader")
	}
	stats := backend.stats()
	if len(stats.generateRequests) != 0 {
		acceptanceFatalf(t, invariant, "cross-tenant candidate reached generator")
	}
	if maximum := maxDuration(stats.retrieveLatencies); maximum > acceptanceRetrievalBudget {
		acceptanceFatalf(t, invariant, "retrieval latency %s exceeds budget %s", maximum, acceptanceRetrievalBudget)
	}
	t.Logf("projection=%s authz_model=%s cross_tenant_loader_count=0 cross_tenant_generator_count=0 unauthorized_evidence=0 false_allows=0",
		acceptanceProjectionVersion, fixture.AuthorizationModelID)
}

func TestPermissionedAcceptanceRevocationSLO(t *testing.T) {
	const invariant = "revocation denies cached replay, citation, and subsequent evidence within SLO"
	const revocationSamples = 16
	latencies := make([]time.Duration, 0, revocationSamples)
	unauthorizedEvidence := 0

	for sample := 0; sample < revocationSamples; sample++ {
		backend := newAcceptanceBackend(fixtureCandidates()...)
		cache, err := authorized.NewQueryCache(8)
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d create cache: %v", sample, err)
		}
		application, err := fixture.NewApplication(backend, fixture.ApplicationOptions{
			Cache: cache, RetrieverVersion: "acceptance-retriever-v1", PromptVersion: "acceptance-prompt-v1",
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d create fixture application: %v", sample, err)
		}
		authorization := fixture.Authorization(fixture.Alice, fmt.Sprintf("session-revocation-%02d", sample))
		result, err := application.Service.Query(context.Background(), protocol.QueryRequest{
			Question: "What is knote?", Authorization: authorization,
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d initial query: %v", sample, err)
		}
		if got, want := resourceIDs(result.Evidence.Items), []protocol.ResourceID{fixtureIntroID, fixtureOverviewID}; !reflect.DeepEqual(got, want) {
			acceptanceFatalf(t, invariant, "sample %d initial evidence=%v, want %v", sample, got, want)
		}
		binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d create protected binding: %v", sample, err)
		}
		if err := application.AuthorizeProtectedContent(context.Background(), authorization, binding); err != nil {
			acceptanceFatalf(t, invariant, "sample %d protected content denied before revocation: %v", sample, err)
		}
		if err := application.RemoveTuple(authz.Tuple{
			User: "user:" + fixture.Alice, Relation: authz.RelationMember, Object: "group:fixture-private-readers",
		}); err != nil {
			acceptanceFatalf(t, invariant, "sample %d remove reader tuple: %v", sample, err)
		}

		revokedAt := time.Now().UTC()
		report, err := application.Apply(context.Background(), authorized.RevocationRequest{
			Authorization: authorization,
			Binding:       binding,
			ResourceIDs:   []protocol.ResourceID{fixtureIntroID},
			RevokedAt:     revokedAt,
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d apply revocation: %v", sample, err)
		}
		latencies = append(latencies, report.PropagationLatency)
		if report.InvalidatedResourceCount != 1 || report.DeniedCount != 1 || report.AllowedCount != 1 {
			acceptanceFatalf(t, invariant, "sample %d revocation report=%+v", sample, report)
		}
		if err := application.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, authorized.ErrProtectedContentUnavailable) {
			acceptanceFatalf(t, invariant, "sample %d old protected session access error=%v", sample, err)
		}
		if _, err := application.Service.OpenCitation(
			context.Background(), authorization, result.Evidence, "cite_intro",
		); !errors.Is(err, authorized.ErrCitationUnavailable) {
			acceptanceFatalf(t, invariant, "sample %d old citation access error=%v", sample, err)
		}

		after, err := application.Service.Query(context.Background(), protocol.QueryRequest{
			Question: "What is knote?", Authorization: authorization,
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d post-revocation query: %v", sample, err)
		}
		if got, want := resourceIDs(after.Evidence.Items), []protocol.ResourceID{fixtureOverviewID}; !reflect.DeepEqual(got, want) {
			acceptanceFatalf(t, invariant, "sample %d post-revocation evidence=%v, want %v", sample, got, want)
		}
		if strings.Contains(after.Generation.Answer, fixtureIntroContent) ||
			strings.Contains(after.Generation.Answer, fixtureDeniedCanaryContent) {
			unauthorizedEvidence++
			acceptanceFatalf(t, invariant, "sample %d post-revocation answer leaked revoked evidence", sample)
		}
		for _, resourceID := range after.Generation.EvidenceResourceIDs {
			if resourceID == fixtureIntroID || resourceID == fixtureDeniedCanaryID {
				unauthorizedEvidence++
				acceptanceFatalf(t, invariant, "sample %d post-revocation generation used %s", sample, resourceID)
			}
		}
		stats := backend.stats()
		if maximum := maxDuration(stats.retrieveLatencies); maximum > acceptanceRetrievalBudget {
			acceptanceFatalf(t, invariant, "sample %d retrieval latency %s exceeds budget %s",
				sample, maximum, acceptanceRetrievalBudget)
		}
	}

	p95 := percentileDuration(latencies, 0.95)
	p99 := percentileDuration(latencies, 0.99)
	if p95 > acceptanceRevocationSLO || p99 > acceptanceRevocationSLO {
		acceptanceFatalf(t, invariant, "revocation p95=%s p99=%s exceeds SLO %s", p95, p99, acceptanceRevocationSLO)
	}
	if unauthorizedEvidence != 0 {
		acceptanceFatalf(t, invariant, "unauthorized_evidence=%d", unauthorizedEvidence)
	}
	t.Logf("projection=%s authz_model=%s samples=%d revocation_p95=%s revocation_p99=%s revocation_slo=%s unauthorized_evidence=0 false_allows=0",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, revocationSamples, p95, p99, acceptanceRevocationSLO)
}
