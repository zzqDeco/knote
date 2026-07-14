package authorized

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestQueryAnySupportPrunesDeniedBranchesBeforeProtectedOutputs(t *testing.T) {
	artifact := queryTestDerivedArtifact(queryTestModelID, "content", "projection-v1")
	visible := queryTestDocument(queryTestOtherID, "a", "projection-v1")
	hidden := queryTestDocument(queryTestThirdID, "b", "projection-v1")
	item := queryTestDerivedItem(artifact, protocol.DerivationAnySupport,
		queryTestSupport("support-hidden", hidden, true),
		queryTestSupport("support-visible", visible, true),
	)
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(artifact)}
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != hidden.AuthorizationID
		}), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{artifact.ResourceID: item}}
	service := queryTestService(t, backend, authorizer, loader, 0, 1)
	authorization := queryTestAuthorization("alice", "request-any-support-prune")

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Evidence.ValidateFor(authorization); err != nil {
		t.Fatalf("evidence package: %v", err)
	}
	if got, want := result.Evidence.Items[0].Supports, []protocol.ProvenanceSupport{item.Supports[1]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected supports = %#v, want %#v", got, want)
	}
	if len(loader.items[artifact.ResourceID].Supports) != 2 {
		t.Fatal("authorization selection mutated loader-owned provenance")
	}
	if got := evidenceDecisionResourceIDs(result.Evidence); !reflect.DeepEqual(got, []protocol.ResourceID{artifact.ResourceID, visible.ResourceID}) {
		t.Fatalf("evidence decisions = %v", got)
	}
	encoded, err := json.Marshal(struct {
		Result   QueryResult
		Generate kag.GenerateRequest
	}{Result: result, Generate: backend.lastGenerate})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(hidden.ResourceID)) || strings.Contains(string(encoded), hidden.AuthorizationID) {
		t.Fatalf("denied support reached protected output: %s", encoded)
	}
	if !batchChecksObject(authorizer.calls, hidden.AuthorizationID) {
		t.Fatal("the complete any_support set was not evaluated before branch selection")
	}
}

func TestQueryAnySupportCacheReplacesDeniedBranchAndReplaysSelectedSubset(t *testing.T) {
	artifact := queryTestDerivedArtifact(queryTestModelID, "content", "projection-v1")
	visible := queryTestDocument(queryTestOtherID, "a", "projection-v1")
	hidden := queryTestDocument(queryTestThirdID, "b", "projection-v1")
	item := queryTestDerivedItem(artifact, protocol.DerivationAnySupport,
		queryTestSupport("support-hidden", hidden, true),
		queryTestSupport("support-visible", visible, true),
	)
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(artifact)}
	denyHidden := false
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return !denyHidden || check.Object != hidden.AuthorizationID
		}), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{artifact.ResourceID: item}}
	service := cacheTestService(
		t, backend, authorizer, loader, mustQueryCache(t, 4), "retriever-v1", "prompt-v1",
	)
	request := protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-any-cache-prime"),
	}

	first, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Evidence.Items[0].Supports) != 2 {
		t.Fatalf("primed supports = %#v", first.Evidence.Items[0].Supports)
	}

	denyHidden = true
	request.Authorization.RequestID = "request-any-cache-replace"
	second, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := second.Evidence.Items[0].Supports, []protocol.ProvenanceSupport{item.Supports[1]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("replacement supports = %#v, want %#v", got, want)
	}
	if backend.retrieveCalls != 2 || backend.generateCalls != 2 {
		t.Fatalf("stale branch did not rebuild exactly once: retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
	}

	request.Authorization.RequestID = "request-any-cache-hit"
	third, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := third.Evidence.Items[0].Supports, []protocol.ProvenanceSupport{item.Supports[1]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed supports = %#v, want %#v", got, want)
	}
	if backend.retrieveCalls != 2 || backend.generateCalls != 2 {
		t.Fatalf("selected subset was not cacheable: retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
	}
}

func TestAnySupportProtectedReplayAndCitationIgnoreUnboundAlternatives(t *testing.T) {
	artifact := queryTestDerivedArtifact(queryTestModelID, "content", "projection-v1")
	visible := queryTestDocument(queryTestOtherID, "a", "projection-v1")
	hidden := queryTestDocument(queryTestThirdID, "b", "projection-v1")
	item := queryTestDerivedItem(artifact, protocol.DerivationAnySupport,
		queryTestSupport("support-hidden", hidden, true),
		queryTestSupport("support-visible", visible, true),
	)
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(artifact)}
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != hidden.AuthorizationID
		}), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{artifact.ResourceID: item}}
	service := queryTestService(t, backend, authorizer, loader, 0, 1)
	authorization := queryTestAuthorization("alice", "request-any-protected")
	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	current := authorization
	current.RequestID = "request-any-protected-current"
	if report, err := service.AuthorizeProtectedContent(context.Background(), current, binding); err != nil || !report.Allowed() {
		t.Fatalf("protected replay = %#v, %v", report, err)
	}
	opened, err := service.OpenCitation(context.Background(), current, result.Evidence, item.Citation.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := opened.Supports, []protocol.ProvenanceSupport{item.Supports[1]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("opened supports = %#v, want %#v", got, want)
	}
	encoded, err := json.Marshal(opened)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(hidden.ResourceID)) || strings.Contains(string(encoded), hidden.AuthorizationID) {
		t.Fatalf("opened citation leaked an unbound alternative: %s", encoded)
	}

	drifted := cloneEvidenceItems([]protocol.EvidenceItem{item})[0]
	drifted.Supports = []protocol.ProvenanceSupport{drifted.Supports[0]}
	loader.items[artifact.ResourceID] = drifted
	if _, err := service.AuthorizeProtectedContent(context.Background(), current, binding); !errors.Is(err, ErrProtectedContentUnavailable) {
		t.Fatalf("protected replay accepted a missing selected branch: %v", err)
	}
}

func TestReloadSelectedEvidenceRequiresEveryAllRequiredSupport(t *testing.T) {
	artifact := queryTestDerivedArtifact(queryTestModelID, "content", "projection-v1")
	first := queryTestDocument(queryTestOtherID, "a", "projection-v1")
	second := queryTestDocument(queryTestThirdID, "b", "projection-v1")
	selected := queryTestDerivedItem(artifact, protocol.DerivationAllRequired,
		queryTestSupport("support-first", first, false),
	)
	loaded := cloneEvidenceItems([]protocol.EvidenceItem{selected})[0]
	loaded.Supports = append(loaded.Supports, queryTestSupport("support-second", second, false))
	if _, ok := reloadSelectedEvidenceItem(loaded, selected); ok {
		t.Fatal("all_required replay accepted an unbound support")
	}
}

func TestQueryDerivedPolicyRejectsWithoutACompleteAuthorizedSupportSet(t *testing.T) {
	artifact := queryTestDerivedArtifact(queryTestModelID, "content", "projection-v1")
	visible := queryTestDocument(queryTestOtherID, "a", "projection-v1")
	hidden := queryTestDocument(queryTestThirdID, "b", "projection-v1")

	for _, test := range []struct {
		name     string
		mode     protocol.DerivationMode
		allowOne bool
	}{
		{name: "any support with every branch denied", mode: protocol.DerivationAnySupport},
		{name: "all required with one branch denied", mode: protocol.DerivationAllRequired, allowOne: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := queryTestDerivedItem(artifact, test.mode,
				queryTestSupport("support-visible", visible, test.mode == protocol.DerivationAnySupport),
				queryTestSupport("support-hidden", hidden, test.mode == protocol.DerivationAnySupport),
			)
			backend := &queryTestKAG{retrieveResult: queryTestRetrieve(artifact)}
			authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
				return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
					if check.Object == artifact.AuthorizationID {
						return true
					}
					return test.allowOne && check.Object == visible.AuthorizationID
				}), nil
			}}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{artifact.ResourceID: item}}
			service := queryTestService(t, backend, authorizer, loader, 0, 1)

			_, err := service.Query(context.Background(), protocol.QueryRequest{
				Question: "q", Authorization: queryTestAuthorization("alice", "request-"+strings.ReplaceAll(test.name, " ", "-")),
			})
			if !errors.Is(err, errNoEvidence) {
				t.Fatalf("error = %v, want no authorized evidence", err)
			}
			if backend.generateCalls != 0 {
				t.Fatal("derived artifact without an authorized complete support set reached generation")
			}
		})
	}
}

func TestTraversalAnySupportPrunesDeniedBranchesBeforeGeneration(t *testing.T) {
	terminal := traversalTestResource(1, protocol.ResourceEntity, "a")
	visible := traversalTestResource(90, protocol.ResourceDocument, "parent")
	hidden := traversalTestResource(91, protocol.ResourceDocument, "parent")
	item := queryTestDerivedItem(terminal, protocol.DerivationAnySupport,
		queryTestSupport("support-hidden", hidden, true),
		queryTestSupport("support-visible", visible, true),
	)
	backend := &traversalTestBackend{retrieve: traversalTestRetrieve(terminal)}
	authorizer := &traversalTestAuthorizer{decide: func(
		_ context.Context, _ int, request authz.BatchCheckRequest,
	) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != hidden.AuthorizationID
		}), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{terminal.ResourceID: item}}
	service := traversalTestService(t, backend, authorizer, loader, traversalTestConfig(0))

	result, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "q", Authorization: queryTestAuthorization("alice", "request-traversal-any-support"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.Evidence.Items[0].Supports, []protocol.ProvenanceSupport{item.Supports[1]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected traversal supports = %#v, want %#v", got, want)
	}
	if got := traversalDecisionResourceIDs(result.Evidence); !reflect.DeepEqual(got, []protocol.ResourceID{terminal.ResourceID, visible.ResourceID}) {
		t.Fatalf("traversal evidence decisions = %v", got)
	}
	encoded, err := json.Marshal(struct {
		Result   QueryResult
		Generate kag.GenerateRequest
	}{Result: result, Generate: backend.lastGenerate})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(hidden.ResourceID)) || strings.Contains(string(encoded), hidden.AuthorizationID) {
		t.Fatalf("denied traversal support reached protected output: %s", encoded)
	}
	if !batchChecksObject(authorizer.calls, hidden.AuthorizationID) {
		t.Fatal("the traversal final check did not evaluate the complete any_support set")
	}
}

func queryTestDerivedArtifact(id protocol.ResourceID, content, projection string) protocol.ResourceHandle {
	resource := queryTestDocument(id, content, projection)
	resource.Type = protocol.ResourceDerivedArtifact
	resource.AuthorizationID = "derived_artifact:" + string(id)
	return resource
}

func queryTestDerivedItem(
	resource protocol.ResourceHandle,
	mode protocol.DerivationMode,
	supports ...protocol.ProvenanceSupport,
) protocol.EvidenceItem {
	return protocol.EvidenceItem{
		Resource: resource, Content: queryTestContent(resource), Derivation: mode,
		Supports: supports,
		Citation: protocol.Citation{Handle: "citation-" + string(resource.ResourceID), Resource: resource},
	}
}

func queryTestSupport(id string, resource protocol.ResourceHandle, complete bool) protocol.ProvenanceSupport {
	return protocol.ProvenanceSupport{
		SupportID: id, Resource: resource,
		Evidence: []protocol.ResourceHandle{resource}, Complete: complete,
	}
}

func evidenceDecisionResourceIDs(evidence protocol.EvidencePackage) []protocol.ResourceID {
	result := make([]protocol.ResourceID, len(evidence.Decisions))
	for index, decision := range evidence.Decisions {
		result[index] = decision.Resource.ResourceID
	}
	return result
}

func batchChecksObject(requests []authz.BatchCheckRequest, object string) bool {
	for _, request := range requests {
		for _, check := range request.Checks {
			if check.Object == object {
				return true
			}
		}
	}
	return false
}
