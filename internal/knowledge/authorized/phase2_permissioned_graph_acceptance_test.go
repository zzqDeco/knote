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

func TestPhase2PermissionedGraphPolicyOracleAcceptanceMetrics(t *testing.T) {
	const (
		invariant = "Phase 2 graph outputs contain only complete principal-authorized paths"
		rounds    = 4
	)
	type cohort struct {
		principal       string
		wantEvidence    []protocol.ResourceID
		wantPaths       [][]protocol.ResourceID
		wantHopDrops    []authorized.TraversalHopDrop
		wantExpandCalls int
	}
	type positiveMetric struct {
		truePositives      int
		authorizedRelevant int
		returned           int
		queries            int
		emptyResults       int
	}
	cohorts := []cohort{
		{
			principal:    fixture.Alice,
			wantEvidence: []protocol.ResourceID{phase2SharedTerminalID, phase2DeepTerminalID},
			wantPaths: [][]protocol.ResourceID{
				{phase2StartID, phase2BridgeClaimID, phase2MiddleID, phase2AlternateClaimID, phase2SharedTerminalID},
				{phase2StartID, phase2BridgeClaimID, phase2MiddleID, phase2FanoutClaimID, phase2FanoutEntityID, phase2DeepClaimID, phase2DeepTerminalID},
			},
			wantHopDrops: []authorized.TraversalHopDrop{
				{Hop: 0, Phase: authorized.TraversalPhaseDiscovery, CandidateCount: 6, AllowedCount: 5, DroppedCount: 1},
				{Hop: 0, Phase: authorized.TraversalPhaseStart, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
				{Hop: 1, Phase: authorized.TraversalPhaseClaim, CandidateCount: 2, AllowedCount: 1, DroppedCount: 1},
				{Hop: 1, Phase: authorized.TraversalPhaseObject, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
				{Hop: 2, Phase: authorized.TraversalPhaseClaim, CandidateCount: 4, AllowedCount: 3, DroppedCount: 1},
				{Hop: 2, Phase: authorized.TraversalPhaseObject, CandidateCount: 3, AllowedCount: 3, DroppedCount: 0},
				{Hop: 3, Phase: authorized.TraversalPhaseClaim, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
				{Hop: 3, Phase: authorized.TraversalPhaseObject, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
			},
			wantExpandCalls: 6,
		},
		{
			principal:    fixture.Bob,
			wantEvidence: []protocol.ResourceID{phase2SharedTerminalID},
			wantPaths: [][]protocol.ResourceID{
				{phase2StartID, phase2BridgeClaimID, phase2MiddleID, phase2AlternateClaimID, phase2SharedTerminalID},
			},
			wantHopDrops: []authorized.TraversalHopDrop{
				{Hop: 0, Phase: authorized.TraversalPhaseDiscovery, CandidateCount: 6, AllowedCount: 3, DroppedCount: 3},
				{Hop: 0, Phase: authorized.TraversalPhaseStart, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
				{Hop: 1, Phase: authorized.TraversalPhaseClaim, CandidateCount: 2, AllowedCount: 1, DroppedCount: 1},
				{Hop: 1, Phase: authorized.TraversalPhaseObject, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
				{Hop: 2, Phase: authorized.TraversalPhaseClaim, CandidateCount: 4, AllowedCount: 1, DroppedCount: 3},
				{Hop: 2, Phase: authorized.TraversalPhaseObject, CandidateCount: 1, AllowedCount: 1, DroppedCount: 0},
				{Hop: 3, Phase: authorized.TraversalPhaseClaim, CandidateCount: 0, AllowedCount: 0, DroppedCount: 0},
			},
			wantExpandCalls: 5,
		},
		{
			principal: phase2UnknownPrincipal,
			wantHopDrops: []authorized.TraversalHopDrop{
				{Hop: 0, Phase: authorized.TraversalPhaseDiscovery, CandidateCount: 6, AllowedCount: 0, DroppedCount: 6},
			},
		},
	}
	var (
		truePositives                 int
		authorizedRelevant            int
		returned                      int
		positiveQueries               int
		positiveEmptyResults          int
		negativeQueries               int
		negativeEmptyResults          int
		falseAllows                   int
		unauthorizedPathParticipation int
		unauthorizedGeneratorUse      int
		selectedPaths                 int
		completePaths                 int
		hopCandidates                 int
		hopAllowed                    int
		hopDropped                    int
		finalFilterCandidates         int
		finalFilterAllowed            int
		finalFilterDropped            int
		batchSizes                    []int
		batchRPCs                     []int
		batchLatencies                []time.Duration
		queryLatencies                []time.Duration
	)
	queryByPrincipal := make(map[string][]time.Duration, len(cohorts))
	positiveByPrincipal := make(map[string]*positiveMetric, len(cohorts)-1)
	baselines := make(map[string]phase2CohortFingerprint, len(cohorts))

	for round := 0; round < rounds; round++ {
		for _, cohort := range cohorts {
			graph := newPhase2PermissionedGraphFixture()
			oracle := graph.newPolicyOracle(t, invariant)
			service := graph.newService(t, invariant, oracle, nil, phase2TraversalConfig(3))
			authorization := fixture.Authorization(
				cohort.principal,
				fmt.Sprintf("session-phase2-%s-%02d", cohort.principal, round),
			)
			result, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "Which Phase 2 graph facts are authorized?", Authorization: authorization,
			})
			backendStats := graph.backend.graphStats()
			oracleStats := oracle.stats()
			allowed := graph.allowedResourceIDs(cohort.principal)
			if result.Traversal == nil {
				acceptanceFatalf(t, invariant, "%s round %d omitted the traversal report", cohort.principal, round)
			}
			report := result.Traversal
			if backendStats.discoverCalls != 1 || len(backendStats.expands) != cohort.wantExpandCalls {
				acceptanceFatalf(t, invariant,
					"%s round %d graph calls discover=%d expand=%d, want 1/%d",
					cohort.principal, round, backendStats.discoverCalls, len(backendStats.expands), cohort.wantExpandCalls)
			}
			if !reflect.DeepEqual(report.HopDrops, cohort.wantHopDrops) {
				acceptanceFatalf(t, invariant, "%s round %d hop drops=%#v, want %#v",
					cohort.principal, round, report.HopDrops, cohort.wantHopDrops)
			}
			if report.BatchCheckRPCCount != len(oracleStats.requests) {
				acceptanceFatalf(t, invariant, "%s round %d report RPCs=%d, recorded=%d",
					cohort.principal, round, report.BatchCheckRPCCount, len(oracleStats.requests))
			}
			if want := time.Duration(report.BatchCheckRPCCount) * phase2BatchCheckDuration; report.BatchCheckLatency != want {
				acceptanceFatalf(t, invariant, "%s round %d BatchCheck latency=%s, want synthetic %s",
					cohort.principal, round, report.BatchCheckLatency, want)
			}
			batchRPCs = append(batchRPCs, report.BatchCheckRPCCount)
			queryLatencies = append(queryLatencies, report.QueryLatency)
			queryByPrincipal[cohort.principal] = append(queryByPrincipal[cohort.principal], report.QueryLatency)
			for _, request := range oracleStats.requests {
				batchSizes = append(batchSizes, len(request.Checks))
				batchLatencies = append(batchLatencies, phase2BatchCheckDuration)
			}
			for _, drop := range report.HopDrops {
				hopCandidates += drop.CandidateCount
				hopAllowed += drop.AllowedCount
				hopDropped += drop.DroppedCount
			}
			finalFilterCandidates += report.FinalFilterCandidateCount
			finalFilterAllowed += report.FinalFilterAllowedCount
			finalFilterDropped += report.FinalFilterDroppedCount
			for _, retrieve := range backendStats.retrieveRequests {
				for _, resource := range retrieve.AllowedResources {
					if !allowed[resource.ResourceID] {
						acceptanceFatalf(t, invariant,
							"%s unauthorized resource %s reached relevance retrieval",
							cohort.principal, resource.ResourceID)
					}
				}
			}

			fingerprint := phase2Fingerprint(result, backendStats)
			if baseline, ok := baselines[cohort.principal]; ok {
				if !reflect.DeepEqual(fingerprint, baseline) {
					acceptanceFatalf(t, invariant, "%s fixture varied between deterministic rounds", cohort.principal)
				}
			} else {
				baselines[cohort.principal] = fingerprint
			}

			if len(cohort.wantEvidence) == 0 {
				negativeQueries++
				if err != nil && len(result.Evidence.Items) == 0 {
					negativeEmptyResults++
				}
				if err == nil {
					acceptanceFatalf(t, invariant, "%s round %d unexpectedly returned evidence", cohort.principal, round)
				}
				if len(backendStats.retrieveRequests) != 0 || len(backendStats.generateRequests) != 0 ||
					len(graph.loader.recordedCalls()) != 0 {
					acceptanceFatalf(t, invariant, "%s crossed retrieval/content/generation after policy denial", cohort.principal)
				}
				continue
			}
			positiveQueries++
			principalMetric := positiveByPrincipal[cohort.principal]
			if principalMetric == nil {
				principalMetric = &positiveMetric{}
				positiveByPrincipal[cohort.principal] = principalMetric
			}
			principalMetric.queries++
			if err != nil || len(result.Evidence.Items) == 0 {
				positiveEmptyResults++
				principalMetric.emptyResults++
			}

			if err != nil {
				acceptanceFatalf(t, invariant, "%s round %d query failed: %v", cohort.principal, round, err)
			}
			if err := result.Evidence.ValidateFor(authorization); err != nil {
				acceptanceFatalf(t, invariant, "%s round %d evidence package: %v", cohort.principal, round, err)
			}
			gotEvidence := resourceIDs(result.Evidence.Items)
			if !reflect.DeepEqual(gotEvidence, cohort.wantEvidence) ||
				!reflect.DeepEqual(result.Generation.EvidenceResourceIDs, cohort.wantEvidence) {
				acceptanceFatalf(t, invariant, "%s round %d evidence=%v generation=%v, want %v",
					cohort.principal, round, gotEvidence, result.Generation.EvidenceResourceIDs, cohort.wantEvidence)
			}
			if len(backendStats.retrieveRequests) != 1 || len(backendStats.generateRequests) != 1 {
				acceptanceFatalf(t, invariant, "%s retrieve/generate calls=%d/%d, want 1/1",
					cohort.principal, len(backendStats.retrieveRequests), len(backendStats.generateRequests))
			}
			generate := backendStats.generateRequests[0]
			gotPaths := phase2GeneratePathIDs(generate.Paths)
			if !reflect.DeepEqual(gotPaths, cohort.wantPaths) {
				acceptanceFatalf(t, invariant, "%s generated paths=%v, want %v", cohort.principal, gotPaths, cohort.wantPaths)
			}
			if report.AuthorizedPathCompleteness != 1 ||
				report.SelectedPathCount != len(cohort.wantPaths) ||
				report.CompletePathCount != len(cohort.wantPaths) {
				acceptanceFatalf(t, invariant, "%s path report=%+v", cohort.principal, report)
			}
			selectedPaths += report.SelectedPathCount
			completePaths += report.CompletePathCount

			authorizedRelevant += len(cohort.wantEvidence)
			returned += len(gotEvidence)
			principalMetric.authorizedRelevant += len(cohort.wantEvidence)
			principalMetric.returned += len(gotEvidence)
			for _, resourceID := range gotEvidence {
				if allowed[resourceID] {
					truePositives++
					principalMetric.truePositives++
				}
			}
			for _, decision := range result.Evidence.Decisions {
				if decision.Authorized() && !allowed[decision.Resource.ResourceID] {
					falseAllows++
				}
			}
			for _, path := range generate.Paths {
				seen := make(map[protocol.ResourceID]struct{}, len(path.Resources))
				for _, resource := range path.Resources {
					if !allowed[resource.ResourceID] {
						unauthorizedPathParticipation++
					}
					if _, duplicate := seen[resource.ResourceID]; duplicate {
						acceptanceFatalf(t, invariant, "%s generated a cyclic path %v", cohort.principal, phase2PathResourceIDs(path))
					}
					seen[resource.ResourceID] = struct{}{}
				}
			}
			for _, evidence := range generate.Evidence {
				if !allowed[evidence.Resource.ResourceID] {
					unauthorizedGeneratorUse++
				}
			}
			phase2AssertProtectedCanariesAbsent(t, invariant, result, generate)
			phase2AssertDynamicSupports(t, invariant, graph, result)
			phase2AssertFilteredExpansionFrontiers(t, invariant, cohort.principal, backendStats.expands)
		}
	}

	recallAt4 := float64(truePositives) / float64(authorizedRelevant)
	precisionAt4 := float64(truePositives) / float64(returned)
	positiveEmptyRate := float64(positiveEmptyResults) / float64(positiveQueries)
	negativeEmptyRate := float64(negativeEmptyResults) / float64(negativeQueries)
	pathCompleteness := float64(completePaths) / float64(selectedPaths)
	hopAuthorizationDropRate := float64(hopDropped) / float64(hopCandidates)
	postFilterDropRate := float64(finalFilterDropped) / float64(finalFilterCandidates)
	if recallAt4 != 1 || precisionAt4 != 1 || positiveEmptyRate != 0 || negativeEmptyRate != 1 || pathCompleteness != 1 {
		acceptanceFatalf(t, invariant,
			"recall@4=%.3f precision@4=%.3f positive_empty_rate=%.3f negative_empty_rate=%.3f path_completeness=%.3f",
			recallAt4, precisionAt4, positiveEmptyRate, negativeEmptyRate, pathCompleteness)
	}
	if falseAllows != 0 || unauthorizedPathParticipation != 0 || unauthorizedGeneratorUse != 0 {
		acceptanceFatalf(t, invariant,
			"false_allow=%d unauthorized_path_participation=%d unauthorized_generator_participation=%d",
			falseAllows, unauthorizedPathParticipation, unauthorizedGeneratorUse)
	}
	if hopCandidates != rounds*40 || hopAllowed != rounds*24 || hopDropped != rounds*16 || hopAuthorizationDropRate != 0.4 {
		acceptanceFatalf(t, invariant,
			"aggregate hops candidates=%d allowed=%d dropped=%d authorization_drop_rate=%.3f",
			hopCandidates, hopAllowed, hopDropped, hopAuthorizationDropRate)
	}
	if finalFilterCandidates != rounds*3 || finalFilterAllowed != rounds*3 || finalFilterDropped != 0 || postFilterDropRate != 0 {
		acceptanceFatalf(t, invariant,
			"final filter candidates=%d allowed=%d dropped=%d drop_rate=%.3f",
			finalFilterCandidates, finalFilterAllowed, finalFilterDropped, postFilterDropRate)
	}
	for principal, metric := range positiveByPrincipal {
		principalRecallAt4 := float64(metric.truePositives) / float64(metric.authorizedRelevant)
		principalPrecisionAt4 := float64(metric.truePositives) / float64(metric.returned)
		principalEmptyRate := float64(metric.emptyResults) / float64(metric.queries)
		if principalRecallAt4 != 1 || principalPrecisionAt4 != 1 || principalEmptyRate != 0 {
			acceptanceFatalf(t, invariant,
				"%s recall@4=%.3f precision@4=%.3f positive_empty_rate=%.3f",
				principal, principalRecallAt4, principalPrecisionAt4, principalEmptyRate)
		}
		t.Logf("principal=%s recall@4=%.3f precision@4=%.3f positive_empty_rate=%.3f samples=%d",
			principal, principalRecallAt4, principalPrecisionAt4, principalEmptyRate, metric.queries)
	}
	for principal, durations := range queryByPrincipal {
		if variance := phase2DurationVariance(durations); variance != 0 {
			acceptanceFatalf(t, invariant, "%s synthetic graph timing variance=%s, want 0", principal, variance)
		}
	}
	if p99 := percentileDuration(queryLatencies, 0.99); p99 > 100*time.Millisecond {
		acceptanceFatalf(t, invariant, "synthetic graph query p99=%s exceeds 100ms fixture budget", p99)
	}
	if maximum := phase2MaxInt(batchSizes); maximum > authz.MaxBatchChecks {
		acceptanceFatalf(t, invariant, "BatchCheck size=%d exceeds provider max=%d", maximum, authz.MaxBatchChecks)
	}
	t.Logf(
		"projection=%s authz_model=%s samples=%d recall@4=%.3f precision@4=%.3f positive_empty_rate=%.3f negative_empty_rate=%.3f path_completeness=%.3f false_allow=%d unauthorized_path_participation=%d unauthorized_generator_participation=%d hop_candidates=%d hop_allowed=%d hop_dropped=%d hop_authorization_drop_rate=%.3f final_filter_candidates=%d final_filter_allowed=%d final_filter_dropped=%d post_filter_drop_rate=%.3f BatchCheck_size_p95=%d BatchCheck_size_p99=%d BatchCheck_RPC_p95=%d BatchCheck_RPC_p99=%d BatchCheck_latency_p95=%s BatchCheck_latency_p99=%s graph_query_p95=%s graph_query_p99=%s timing_variance=0s",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, rounds*len(cohorts),
		recallAt4, precisionAt4, positiveEmptyRate, negativeEmptyRate, pathCompleteness, falseAllows,
		unauthorizedPathParticipation, unauthorizedGeneratorUse, hopCandidates, hopAllowed, hopDropped,
		hopAuthorizationDropRate, finalFilterCandidates, finalFilterAllowed, finalFilterDropped,
		postFilterDropRate, phase2PercentileInt(batchSizes, 0.95), phase2PercentileInt(batchSizes, 0.99),
		phase2PercentileInt(batchRPCs, 0.95), phase2PercentileInt(batchRPCs, 0.99),
		percentileDuration(batchLatencies, 0.95), percentileDuration(batchLatencies, 0.99),
		percentileDuration(queryLatencies, 0.95), percentileDuration(queryLatencies, 0.99),
	)
}

func TestPhase2PermissionedGraphDerivationBudgetsAndFailures(t *testing.T) {
	const invariant = "Phase 2 derivation and traversal limits fail closed before unauthorized generation"

	t.Run("all-required support denial drops only incomplete terminal", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		oracle := graph.newPolicyOracle(t, invariant)
		if err := oracle.removeViewer(fixture.Alice, graph.requiredB); err != nil {
			acceptanceFatalf(t, invariant, "remove required support viewer: %v", err)
		}
		service := graph.newService(t, invariant, oracle, nil, phase2TraversalConfig(3))
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "dynamic all-required denial", Authorization: fixture.Authorization(fixture.Alice, "session-phase2-all-deny"),
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "query failed: %v", err)
		}
		if got, want := result.Generation.EvidenceResourceIDs, []protocol.ResourceID{phase2SharedTerminalID}; !reflect.DeepEqual(got, want) {
			acceptanceFatalf(t, invariant, "generation evidence=%v, want %v", got, want)
		}
		if result.Traversal == nil || result.Traversal.SelectedPathCount != 2 ||
			result.Traversal.CompletePathCount != 1 || result.Traversal.AuthorizedPathCompleteness != 0.5 ||
			result.Traversal.FinalFilterCandidateCount != 2 || result.Traversal.FinalFilterAllowedCount != 1 ||
			result.Traversal.FinalFilterDroppedCount != 1 {
			acceptanceFatalf(t, invariant, "all-required denial report=%+v", result.Traversal)
		}
		if strings.Contains(result.Generation.Answer, "deep authorized terminal") {
			acceptanceFatalf(t, invariant, "all-required terminal reached generation after one required support was denied")
		}
	})

	t.Run("depth bound returns the complete prefix terminal", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		oracle := graph.newPolicyOracle(t, invariant)
		service := graph.newService(t, invariant, oracle, nil, phase2TraversalConfig(1))
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "depth one", Authorization: fixture.Authorization(fixture.Alice, "session-phase2-depth"),
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "depth query failed: %v", err)
		}
		stats := graph.backend.graphStats()
		wantPath := []protocol.ResourceID{phase2StartID, phase2BridgeClaimID, phase2MiddleID}
		if got := result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{phase2MiddleID}) {
			acceptanceFatalf(t, invariant, "depth-bounded evidence=%v", got)
		}
		if len(stats.generateRequests) != 1 || len(stats.generateRequests[0].Paths) != 1 ||
			!reflect.DeepEqual(phase2PathResourceIDs(stats.generateRequests[0].Paths[0]), wantPath) {
			acceptanceFatalf(t, invariant, "depth-bounded generated paths=%v", stats.generateRequests)
		}
		if len(stats.expands) != 2 || result.Traversal == nil || result.Traversal.AuthorizedPathCompleteness != 1 {
			acceptanceFatalf(t, invariant, "depth-bounded expansion/report=%d/%+v", len(stats.expands), result.Traversal)
		}
	})

	t.Run("fanout budget stops before load and generation", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		oracle := graph.newPolicyOracle(t, invariant)
		config := phase2TraversalConfig(3)
		config.Limits.MaxCandidatesPerHop = 2
		service := graph.newService(t, invariant, oracle, nil, config)
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "fanout limit", Authorization: fixture.Authorization(fixture.Alice, "session-phase2-fanout-limit"),
		})
		if err == nil {
			acceptanceFatalf(t, invariant, "fanout-limited query succeeded")
		}
		stats := graph.backend.graphStats()
		if len(graph.loader.recordedCalls()) != 0 || len(stats.generateRequests) != 0 {
			acceptanceFatalf(t, invariant, "fanout limit crossed load/generate boundary")
		}
		wantLast := authorized.TraversalHopDrop{
			Hop: 2, Phase: authorized.TraversalPhaseClaim, CandidateCount: 4, AllowedCount: 3, DroppedCount: 1,
		}
		if result.Traversal == nil || len(result.Traversal.HopDrops) == 0 ||
			result.Traversal.HopDrops[len(result.Traversal.HopDrops)-1] != wantLast {
			acceptanceFatalf(t, invariant, "fanout-limited report=%+v", result.Traversal)
		}
	})

	t.Run("wall-clock budget cancels a blocked graph primitive", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		graph.backend.setExpandHook(func(ctx context.Context, _ int, _ kag.ExpandRequest) error {
			<-ctx.Done()
			return ctx.Err()
		})
		oracle := graph.newPolicyOracle(t, invariant)
		config := phase2TraversalConfig(3)
		config.Limits.MaxWallClockMillis = 5
		service := graph.newService(t, invariant, oracle, nil, config)
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "blocked expansion", Authorization: fixture.Authorization(fixture.Alice, "session-phase2-time-budget"),
		})
		if err == nil {
			acceptanceFatalf(t, invariant, "wall-clock-limited query succeeded")
		}
		if result.Traversal == nil || len(graph.loader.recordedCalls()) != 0 ||
			len(graph.backend.graphStats().generateRequests) != 0 {
			acceptanceFatalf(t, invariant, "wall-clock limit crossed load/generate boundary")
		}
	})

	t.Run("caller cancellation stops before graph access", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		oracle := graph.newPolicyOracle(t, invariant)
		service := graph.newService(t, invariant, oracle, nil, phase2TraversalConfig(3))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := service.Query(ctx, protocol.QueryRequest{
			Question: "cancelled graph", Authorization: fixture.Authorization(fixture.Alice, "session-phase2-cancel"),
		})
		if !errors.Is(err, context.Canceled) {
			acceptanceFatalf(t, invariant, "cancellation error=%v, want context canceled", err)
		}
		stats := graph.backend.graphStats()
		if result.Traversal == nil || stats.discoverCalls != 0 || len(stats.retrieveRequests) != 0 ||
			len(stats.expands) != 0 || len(stats.generateRequests) != 0 {
			acceptanceFatalf(t, invariant, "cancelled query reached graph backend: %+v", stats)
		}
	})

	t.Run("partial final authorization response cannot generate", func(t *testing.T) {
		graph := newPhase2PermissionedGraphFixture()
		oracle := graph.newPolicyOracle(t, invariant)
		oracle.setHook(func(
			_ context.Context,
			request authz.BatchCheckRequest,
			decisions []authz.Decision,
			err error,
		) ([]authz.Decision, error) {
			if err == nil && len(request.Checks) > 1 && strings.HasPrefix(request.Checks[0].CorrelationID, "tr-final-") {
				return decisions[:len(decisions)-1], nil
			}
			return decisions, err
		})
		service := graph.newService(t, invariant, oracle, nil, phase2TraversalConfig(3))
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "partial final authorization", Authorization: fixture.Authorization(fixture.Alice, "session-phase2-partial-auth"),
		})
		if err == nil {
			acceptanceFatalf(t, invariant, "partial authorization response succeeded")
		}
		stats := graph.backend.graphStats()
		if result.Traversal == nil || len(stats.generateRequests) != 0 {
			acceptanceFatalf(t, invariant, "partial authorization reached generation")
		}
		if len(graph.loader.recordedCalls()) != 1 {
			acceptanceFatalf(t, invariant, "partial final authorization loader calls=%d, want 1",
				len(graph.loader.recordedCalls()))
		}
	})
}

func TestPhase2PermissionedGraphCacheCitationRevocationAndSessionReplay(t *testing.T) {
	const invariant = "Phase 2 cached paths, citations, and replay reauthorize every selected graph resource"
	graph := newPhase2PermissionedGraphFixture()
	oracle := graph.newPolicyOracle(t, invariant)
	cache, err := authorized.NewQueryCache(8)
	if err != nil {
		acceptanceFatalf(t, invariant, "create query cache: %v", err)
	}
	service := graph.newService(t, invariant, oracle, cache, phase2TraversalConfig(3))
	const sessionID = "session-phase2-replay"
	firstAuthorization := fixture.Authorization(fixture.Alice, sessionID)
	request := protocol.QueryRequest{
		Question: "cache the authorized Phase 2 paths", Authorization: firstAuthorization,
	}
	first, err := service.Query(context.Background(), request)
	if err != nil {
		acceptanceFatalf(t, invariant, "prime query: %v", err)
	}
	request.Authorization = fixture.Authorization(fixture.Alice, sessionID)
	second, err := service.Query(context.Background(), request)
	if err != nil {
		acceptanceFatalf(t, invariant, "cache query: %v", err)
	}
	stats := graph.backend.graphStats()
	if len(stats.generateRequests) != 1 {
		acceptanceFatalf(t, invariant, "cache replay generated %d times, want 1", len(stats.generateRequests))
	}
	if second.Traversal == nil || second.Traversal.AuthorizedPathCompleteness != 1 ||
		!reflect.DeepEqual(second.Generation.EvidenceResourceIDs, first.Generation.EvidenceResourceIDs) {
		acceptanceFatalf(t, invariant, "cache replay result=%+v", second)
	}

	binding, err := protocol.NewProtectedContentBinding(firstAuthorization, first.Evidence)
	if err != nil {
		acceptanceFatalf(t, invariant, "create protected binding: %v", err)
	}
	current := fixture.Authorization(fixture.Alice, sessionID)
	if report, err := service.AuthorizeProtectedContent(context.Background(), current, binding); err != nil || !report.Allowed() {
		acceptanceFatalf(t, invariant, "same-session replay report=%+v error=%v", report, err)
	}
	citationHandle := first.Evidence.Items[0].Citation.Handle
	opened, err := service.OpenCitation(context.Background(), current, first.Evidence, citationHandle)
	if err != nil {
		acceptanceFatalf(t, invariant, "open citation before revocation: %v", err)
	}
	if got, want := opened.Supports, []protocol.ProvenanceSupport{phase2Support("support_visible", graph.visibleSupport, true)}; !reflect.DeepEqual(got, want) {
		acceptanceFatalf(t, invariant, "opened any-support branches=%#v, want %#v", got, want)
	}
	otherSession := fixture.Authorization(fixture.Alice, "session-phase2-other")
	if _, err := service.AuthorizeProtectedContent(context.Background(), otherSession, binding); !errors.Is(err, authorized.ErrProtectedContentUnavailable) {
		acceptanceFatalf(t, invariant, "cross-session replay error=%v", err)
	}
	if _, err := service.OpenCitation(context.Background(), otherSession, first.Evidence, citationHandle); !errors.Is(err, authorized.ErrCitationUnavailable) {
		acceptanceFatalf(t, invariant, "cross-session citation error=%v", err)
	}

	if err := oracle.removeViewer(fixture.Alice, graph.alternateClaim); err != nil {
		acceptanceFatalf(t, invariant, "remove alternate Claim viewer: %v", err)
	}
	coordinator, err := authorized.NewRevocationCoordinator(service)
	if err != nil {
		acceptanceFatalf(t, invariant, "create revocation coordinator: %v", err)
	}
	revokedAt := time.Now().UTC()
	revocation, err := coordinator.Apply(context.Background(), authorized.RevocationRequest{
		Authorization: current,
		Binding:       binding,
		ResourceIDs:   []protocol.ResourceID{graph.alternateClaim.ResourceID},
		RevokedAt:     revokedAt,
	})
	if err != nil {
		acceptanceFatalf(t, invariant, "apply alternate Claim revocation: %v", err)
	}
	if revocation.InvalidatedResourceCount != 1 || revocation.RemovedEntryCount != 1 ||
		revocation.DeniedCount != 1 || revocation.ObservedAt.Before(revokedAt) ||
		revocation.PropagationLatency != revocation.ObservedAt.Sub(revokedAt) {
		acceptanceFatalf(t, invariant, "revocation report=%+v", revocation)
	}
	if _, err := service.AuthorizeProtectedContent(context.Background(), current, binding); !errors.Is(err, authorized.ErrProtectedContentUnavailable) {
		acceptanceFatalf(t, invariant, "revoked session replay error=%v", err)
	}
	loaderCalls := len(graph.loader.recordedCalls())
	if _, err := service.OpenCitation(context.Background(), current, first.Evidence, citationHandle); !errors.Is(err, authorized.ErrCitationUnavailable) {
		acceptanceFatalf(t, invariant, "revoked citation error=%v", err)
	}
	if got := len(graph.loader.recordedCalls()); got != loaderCalls {
		acceptanceFatalf(t, invariant, "revoked citation loaded content: calls=%d, want %d", got, loaderCalls)
	}

	request.Authorization = fixture.Authorization(fixture.Alice, sessionID)
	after, err := service.Query(context.Background(), request)
	if err != nil {
		acceptanceFatalf(t, invariant, "post-revocation query: %v", err)
	}
	if got, want := after.Generation.EvidenceResourceIDs, []protocol.ResourceID{phase2DeepTerminalID}; !reflect.DeepEqual(got, want) {
		acceptanceFatalf(t, invariant, "post-revocation generation=%v, want %v", got, want)
	}
	stats = graph.backend.graphStats()
	if len(stats.generateRequests) != 2 {
		acceptanceFatalf(t, invariant, "post-revocation generation calls=%d, want 2", len(stats.generateRequests))
	}
	for _, request := range stats.generateRequests[1:] {
		for _, path := range request.Paths {
			for _, resource := range path.Resources {
				if resource.ResourceID == graph.alternateClaim.ResourceID {
					acceptanceFatalf(t, invariant, "revoked alternate Claim participated in generation")
				}
			}
		}
	}
	t.Logf(
		"projection=%s authz_model=%s cache_generation_calls=1 replay_allowed=1 cross_session_denied=1 citation_allowed=1 revoked_entries=%d revocation_latency=%s post_revocation_false_allow=0 post_revocation_generator_participation=0",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, revocation.RemovedEntryCount, revocation.PropagationLatency,
	)
}

func TestPhase2PermissionedGraphRevocationLatencyBudget(t *testing.T) {
	const (
		invariant = "Phase 2 graph revocation propagation remains bounded in one clock domain"
		samples   = 128
		p95Budget = 25 * time.Millisecond
		p99Budget = 100 * time.Millisecond
	)
	latencies := make([]time.Duration, 0, samples)
	for sample := 0; sample < samples; sample++ {
		graph := newPhase2PermissionedGraphFixture()
		oracle := graph.newPolicyOracle(t, invariant)
		cache, err := authorized.NewQueryCache(4)
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d create cache: %v", sample, err)
		}
		service := graph.newService(t, invariant, oracle, cache, phase2TraversalConfig(3))
		sessionID := fmt.Sprintf("session-phase2-revocation-latency-%02d", sample)
		authorization := fixture.Authorization(fixture.Alice, sessionID)
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "measure Phase 2 graph revocation", Authorization: authorization,
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d prime query: %v", sample, err)
		}
		binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d create binding: %v", sample, err)
		}
		if err := oracle.removeViewer(fixture.Alice, graph.alternateClaim); err != nil {
			acceptanceFatalf(t, invariant, "sample %d remove viewer: %v", sample, err)
		}
		coordinator, err := authorized.NewRevocationCoordinator(service)
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d create coordinator: %v", sample, err)
		}
		revokedAt := time.Now().UTC()
		report, err := coordinator.Apply(context.Background(), authorized.RevocationRequest{
			Authorization: fixture.Authorization(fixture.Alice, sessionID),
			Binding:       binding,
			ResourceIDs:   []protocol.ResourceID{graph.alternateClaim.ResourceID},
			RevokedAt:     revokedAt,
		})
		if err != nil {
			acceptanceFatalf(t, invariant, "sample %d apply revocation: %v", sample, err)
		}
		if report.RemovedEntryCount != 1 || report.DeniedCount != 1 ||
			report.ObservedAt.Before(revokedAt) ||
			report.PropagationLatency != report.ObservedAt.Sub(revokedAt) {
			acceptanceFatalf(t, invariant, "sample %d report=%+v", sample, report)
		}
		latencies = append(latencies, report.PropagationLatency)
	}
	p95 := percentileDuration(latencies, 0.95)
	p99 := percentileDuration(latencies, 0.99)
	if p95 > p95Budget || p99 > p99Budget {
		acceptanceFatalf(t, invariant, "revocation p95=%s budget=%s p99=%s budget=%s", p95, p95Budget, p99, p99Budget)
	}
	t.Logf(
		"projection=%s authz_model=%s samples=%d graph_revocation_p95=%s graph_revocation_p95_budget=%s graph_revocation_p99=%s graph_revocation_p99_budget=%s false_allow=0",
		acceptanceProjectionVersion, fixture.AuthorizationModelID, samples, p95, p95Budget, p99, p99Budget,
	)
}

type phase2CohortFingerprint struct {
	evidence       []protocol.ResourceID
	paths          [][]protocol.ResourceID
	hopDrops       []authorized.TraversalHopDrop
	batchRPCs      int
	batchLatency   time.Duration
	queryLatency   time.Duration
	expandPhases   []kag.ExpandPhase
	expandFrontier [][]protocol.ResourceID
}

func phase2Fingerprint(
	result authorized.QueryResult,
	stats phase2GraphBackendStats,
) phase2CohortFingerprint {
	fingerprint := phase2CohortFingerprint{
		evidence: resourceIDs(result.Evidence.Items),
	}
	if result.Traversal != nil {
		fingerprint.hopDrops = append([]authorized.TraversalHopDrop(nil), result.Traversal.HopDrops...)
		fingerprint.batchRPCs = result.Traversal.BatchCheckRPCCount
		fingerprint.batchLatency = result.Traversal.BatchCheckLatency
		fingerprint.queryLatency = result.Traversal.QueryLatency
	}
	if len(stats.generateRequests) > 0 {
		fingerprint.paths = phase2GeneratePathIDs(stats.generateRequests[len(stats.generateRequests)-1].Paths)
	}
	for _, observation := range stats.expands {
		fingerprint.expandPhases = append(fingerprint.expandPhases, observation.phase)
		ids := make([]protocol.ResourceID, len(observation.frontier))
		for index, resource := range observation.frontier {
			ids[index] = resource.ResourceID
		}
		fingerprint.expandFrontier = append(fingerprint.expandFrontier, ids)
	}
	return fingerprint
}

func phase2GeneratePathIDs(paths []kag.GeneratePath) [][]protocol.ResourceID {
	result := make([][]protocol.ResourceID, len(paths))
	for index, path := range paths {
		result[index] = phase2PathResourceIDs(path)
	}
	return result
}

func phase2AssertProtectedCanariesAbsent(
	t testing.TB,
	invariant string,
	result authorized.QueryResult,
	generate kag.GenerateRequest,
) {
	t.Helper()
	encoded := fmt.Sprintf("%+v %+v", result, generate)
	for _, canary := range []string{
		phase2HiddenClaimCanary,
		phase2DeniedClaimCanary,
		phase2HiddenSupportCanary,
		string(phase2HiddenClaimID),
		string(phase2DeniedClaimID),
		string(phase2HiddenSupportID),
	} {
		if strings.Contains(encoded, canary) {
			acceptanceFatalf(t, invariant, "protected canary %q reached evidence or generation", canary)
		}
	}
}

func phase2AssertDynamicSupports(
	t testing.TB,
	invariant string,
	graph *phase2PermissionedGraphFixture,
	result authorized.QueryResult,
) {
	t.Helper()
	if len(result.Evidence.Items) == 0 {
		acceptanceFatalf(t, invariant, "dynamic support assertion received no evidence")
	}
	shared := result.Evidence.Items[0]
	wantShared := []protocol.ProvenanceSupport{phase2Support("support_visible", graph.visibleSupport, true)}
	if shared.Resource.ResourceID != graph.sharedTerminal.ResourceID ||
		shared.Derivation != protocol.DerivationAnySupport || !reflect.DeepEqual(shared.Supports, wantShared) {
		acceptanceFatalf(t, invariant, "selected any-support item=%#v, want visible branch only", shared)
	}
	if len(result.Evidence.Items) == 1 {
		return
	}
	deep := result.Evidence.Items[1]
	wantDeep := []protocol.ProvenanceSupport{
		phase2Support("support_required_a", graph.requiredA, false),
		phase2Support("support_required_b", graph.requiredB, false),
	}
	if deep.Resource.ResourceID != graph.deepTerminal.ResourceID ||
		deep.Derivation != protocol.DerivationAllRequired || !reflect.DeepEqual(deep.Supports, wantDeep) {
		acceptanceFatalf(t, invariant, "selected all-required item=%#v, want both required supports", deep)
	}
}

func phase2AssertFilteredExpansionFrontiers(
	t testing.TB,
	invariant string,
	principal string,
	expands []phase2ExpandObservation,
) {
	t.Helper()
	alternateSeen := false
	cycleSeen := false
	for _, observation := range expands {
		if observation.phase != kag.ExpandPhaseClaimToObject {
			continue
		}
		if phase2FrontierContains(observation, phase2HiddenClaimID) ||
			phase2FrontierContains(observation, phase2DeniedClaimID) {
			acceptanceFatalf(t, invariant, "%s expanded a hidden or denied intermediate Claim", principal)
		}
		alternateSeen = alternateSeen || phase2FrontierContains(observation, phase2AlternateClaimID)
		cycleSeen = cycleSeen || phase2FrontierContains(observation, phase2CycleClaimID)
	}
	if !alternateSeen {
		acceptanceFatalf(t, invariant, "%s did not use the complete alternate path", principal)
	}
	if principal == fixture.Alice && !cycleSeen {
		acceptanceFatalf(t, invariant, "Alice fixture did not exercise the cycle candidate")
	}
}

func phase2DurationVariance(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	minimum := values[0]
	maximum := values[0]
	for _, value := range values[1:] {
		if value < minimum {
			minimum = value
		}
		if value > maximum {
			maximum = value
		}
	}
	return maximum - minimum
}

func phase2MaxInt(values []int) int {
	maximum := 0
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}

func phase2PercentileInt(values []int, percentile float64) int {
	durations := make([]time.Duration, len(values))
	for index, value := range values {
		durations[index] = time.Duration(value)
	}
	return int(percentileDuration(durations, percentile))
}
