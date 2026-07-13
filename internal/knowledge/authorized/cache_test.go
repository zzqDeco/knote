package authorized

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

const cacheTestLocalModel = "01GAHCE4YVKPQEKZQHT2R89MQV"

func TestQueryCacheRebindsValidatedHitToCurrentRequest(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		document.ResourceID: queryTestItem(document),
	}}
	cache := mustQueryCache(t, 8)
	service := cacheTestService(t, backend, authorizer, loader, cache, "retriever-v1", "prompt-v1")

	firstAuthorization := queryTestAuthorization("alice", "request-cache-1")
	first, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "cache question", Authorization: firstAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	first.Generation.Answer = "mutated answer"
	first.Generation.Citations[0].Handle = "mutated-citation"
	first.Evidence.Items[0].Content = "mutated content"
	first.Evidence.Items[0].Supports[0].Evidence = nil

	current := firstAuthorization
	current.SessionID = "session-2"
	current.RequestID = "request-cache-2"
	second, err := service.Query(context.Background(), protocol.QueryRequest{
		Question: "cache question", Authorization: current,
	})
	if err != nil {
		t.Fatal(err)
	}
	if backend.retrieveCalls != 1 || backend.generateCalls != 1 {
		t.Fatalf("valid hit called retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
	}
	if len(authorizer.calls) != 4 {
		t.Fatalf("authorization calls = %d, want fresh and cache pre/final checks", len(authorizer.calls))
	}
	if len(loader.calls) != 2 {
		t.Fatalf("loader calls = %d, want exact reload on cache hit", len(loader.calls))
	}
	if second.Generation.Answer != "authorized answer" || second.Generation.Citations[0].Handle == "mutated-citation" {
		t.Fatalf("cache was mutated through caller result: %#v", second.Generation)
	}
	if second.Evidence.Items[0].Content != "content" || len(second.Evidence.Items[0].Supports[0].Evidence) != 1 {
		t.Fatalf("cached evidence was mutated through caller result: %#v", second.Evidence.Items[0])
	}
	if err := second.Evidence.ValidateFor(current); err != nil {
		t.Fatalf("current evidence binding: %v", err)
	}
	for _, decision := range second.Evidence.Decisions {
		if decision.RequestID != current.RequestID || decision.SessionID != current.SessionID {
			t.Fatalf("stale cached decision binding: %#v", decision)
		}
	}
}

func TestQueryCacheSeparatesVisibilityAndExecutionVersions(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		document.ResourceID: queryTestItem(document),
	}}
	cache := mustQueryCache(t, 32)
	service := cacheTestService(t, backend, authorizer, loader, cache, "retriever-v1", "prompt-v1")
	base := queryTestAuthorization("alice", "request-base")
	query := func(current protocol.AuthorizationContext, currentService *Service) {
		t.Helper()
		if _, err := currentService.Query(context.Background(), protocol.QueryRequest{
			Question: "same question", Authorization: current,
		}); err != nil {
			t.Fatal(err)
		}
	}
	query(base, service)

	variations := []struct {
		name   string
		change func(*protocol.AuthorizationContext)
	}{
		{name: "principal", change: func(value *protocol.AuthorizationContext) { value.PrincipalID = "bob" }},
		{name: "model", change: func(value *protocol.AuthorizationContext) { value.AuthorizationModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAA" }},
		{name: "identity watermark", change: func(value *protocol.AuthorizationContext) { value.IdentityWatermark = "identity-v2" }},
		{name: "acl watermark", change: func(value *protocol.AuthorizationContext) { value.ACLWatermark = "acl-v2" }},
		{name: "agent", change: func(value *protocol.AuthorizationContext) { value.AgentID = "agent-2" }},
		{name: "task", change: func(value *protocol.AuthorizationContext) { value.TaskID = "task-2" }},
		{name: "consistency", change: func(value *protocol.AuthorizationContext) { value.Consistency = protocol.ConsistencyMinimizeLatency }},
	}
	for index, variation := range variations {
		t.Run(variation.name, func(t *testing.T) {
			current := base
			current.RequestID = fmt.Sprintf("request-variation-%d", index)
			variation.change(&current)
			before := backend.retrieveCalls
			query(current, service)
			if backend.retrieveCalls != before+1 {
				t.Fatalf("variation reused another visibility scope")
			}
		})
	}

	for _, test := range []struct {
		name      string
		retriever string
		prompt    string
	}{
		{name: "retriever", retriever: "retriever-v2", prompt: "prompt-v1"},
		{name: "prompt", retriever: "retriever-v1", prompt: "prompt-v2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			versioned := cacheTestService(t, backend, authorizer, loader, cache, test.retriever, test.prompt)
			current := base
			current.RequestID = "request-" + test.name
			before := backend.retrieveCalls
			query(current, versioned)
			if backend.retrieveCalls != before+1 {
				t.Fatalf("%s version reused another cache entry", test.name)
			}
		})
	}
}

func TestQueryCacheSeparatesQueryPlanLimits(t *testing.T) {
	request := protocol.QueryRequest{
		Question: "same plan question", Authorization: queryTestAuthorization("alice", "request-plan"),
	}
	base := newQueryCacheKey(request, "retriever-v1", "prompt-v1", 10, 1, 0)
	for name, changed := range map[string]queryCacheKey{
		"retrieve": newQueryCacheKey(request, "retriever-v1", "prompt-v1", 11, 1, 0),
		"evidence": newQueryCacheKey(request, "retriever-v1", "prompt-v1", 10, 2, 0),
		"expand":   newQueryCacheKey(request, "retriever-v1", "prompt-v1", 10, 1, 1),
	} {
		if base == changed {
			t.Fatalf("%s limit did not change cache key", name)
		}
	}

	documentA := queryTestDocument(queryTestModelID, "a", "projection-v1")
	documentB := queryTestDocument(queryTestOtherID, "b", "projection-v1")
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(documentA, documentB)}
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		documentA.ResourceID: queryTestItem(documentA),
		documentB.ResourceID: queryTestItem(documentB),
	}}
	cache := mustQueryCache(t, 4)
	small := cacheTestServiceWithLimits(
		t, backend, authorizer, loader, cache, "retriever-v1", "prompt-v1", 10, 1, 0,
	)
	large := cacheTestServiceWithLimits(
		t, backend, authorizer, loader, cache, "retriever-v1", "prompt-v1", 10, 2, 0,
	)
	first, err := small.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Evidence.Items) != 1 {
		t.Fatalf("small plan evidence count = %d", len(first.Evidence.Items))
	}
	request.Authorization.RequestID = "request-plan-large"
	second, err := large.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if backend.retrieveCalls != 2 || backend.generateCalls != 2 {
		t.Fatalf("larger plan reused smaller result: retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
	}
	if len(second.Evidence.Items) != 2 {
		t.Fatalf("large plan evidence count = %d, want 2", len(second.Evidence.Items))
	}
}

func TestQueryCacheRevocationFallsBackToFreshAuthorizedEvidence(t *testing.T) {
	revoked := queryTestDocument(queryTestModelID, "content", "projection-v1")
	alternative := queryTestDocument(queryTestOtherID, "b", "projection-v1")
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(revoked)}
	allowedObject := revoked.AuthorizationID
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object == allowedObject
		}), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		revoked.ResourceID:     queryTestItem(revoked),
		alternative.ResourceID: queryTestItem(alternative),
	}}
	cache := mustQueryCache(t, 8)
	service := cacheTestService(t, backend, authorizer, loader, cache, "retriever-v1", "prompt-v1")
	authorization := queryTestAuthorization("alice", "request-before-revoke")
	authorization.Consistency = protocol.ConsistencyMinimizeLatency
	request := protocol.QueryRequest{Question: "revoked question", Authorization: authorization}
	first, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Generation.EvidenceResourceIDs, []protocol.ResourceID{revoked.ResourceID}) {
		t.Fatalf("initial generation evidence = %v", first.Generation.EvidenceResourceIDs)
	}

	allowedObject = alternative.AuthorizationID
	backend.retrieveResult = queryTestRetrieve(revoked, alternative)
	request.Authorization.RequestID = "request-after-revoke"
	second, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatalf("fresh fallback after cache revocation: %v", err)
	}
	if got := second.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{alternative.ResourceID}) {
		t.Fatalf("fresh generation evidence = %v", got)
	}
	if len(backend.lastGenerate.Evidence) != 1 || backend.lastGenerate.Evidence[0].Resource != alternative {
		t.Fatalf("unauthorized evidence reached generation: %#v", backend.lastGenerate.Evidence)
	}
	if backend.retrieveCalls != 2 || backend.generateCalls != 2 {
		t.Fatalf("fresh fallback calls: retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
	}
	if got := authorizer.calls[2].Consistency; got != authz.ConsistencyHigherConsistency {
		t.Fatalf("cache live recheck consistency = %q", got)
	}

	request.Authorization.RequestID = "request-after-refresh"
	third, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if backend.retrieveCalls != 2 || backend.generateCalls != 2 {
		t.Fatalf("fresh result was not cached: retrieve=%d generate=%d", backend.retrieveCalls, backend.generateCalls)
	}
	if got := third.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{alternative.ResourceID}) {
		t.Fatalf("refreshed cache evidence = %v", got)
	}
	if err := third.Evidence.ValidateFor(request.Authorization); err != nil {
		t.Fatalf("refreshed cache binding: %v", err)
	}
}

func TestQueryCacheStaleRevisionDoesNotDeleteConcurrentRefresh(t *testing.T) {
	stale := queryTestDocument(queryTestModelID, "content", "projection-v1")
	fresh := queryTestDocument(queryTestOtherID, "b", "projection-v1")
	backend := &queryTestKAG{retrieveResult: queryTestRetrieve(stale)}
	cacheCheckStarted := make(chan struct{})
	continueCacheCheck := make(chan struct{})
	freshCheckStarted := make(chan struct{})
	continueFreshCheck := make(chan struct{})
	authorizer := &queryTestAuthorizer{decide: func(call int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		switch call {
		case 2:
			close(cacheCheckStarted)
			<-continueCacheCheck
		case 4:
			close(freshCheckStarted)
			<-continueFreshCheck
		}
		return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
	}}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		stale.ResourceID: queryTestItem(stale), fresh.ResourceID: queryTestItem(fresh),
	}}
	cache := mustQueryCache(t, 8)
	service := cacheTestService(t, backend, authorizer, loader, cache, "retriever-v1", "prompt-v1")
	request := protocol.QueryRequest{
		Question: "revision race", Authorization: queryTestAuthorization("alice", "request-prime"),
	}
	prime, err := service.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	key := cacheTestKey(request, "retriever-v1", "prompt-v1")
	staleSnapshot, ok := cache.get(key)
	if !ok {
		t.Fatal("primed cache entry missing")
	}

	backend.retrieveResult = queryTestRetrieve(fresh)
	request.Authorization.RequestID = "request-racing"
	type queryOutcome struct {
		result QueryResult
		err    error
	}
	outcomes := make(chan queryOutcome, 1)
	go func() {
		result, queryErr := service.Query(context.Background(), request)
		outcomes <- queryOutcome{result: result, err: queryErr}
	}()
	<-cacheCheckStarted

	concurrent := cloneQueryResult(prime)
	concurrent.Generation.Answer = "concurrent refresh"
	if !cache.put(key, concurrent) {
		t.Fatal("concurrent cache refresh was rejected")
	}
	refreshedSnapshot, ok := cache.get(key)
	if !ok || refreshedSnapshot.revision == staleSnapshot.revision {
		t.Fatalf("concurrent refresh revision = %d, stale = %d", refreshedSnapshot.revision, staleSnapshot.revision)
	}
	close(continueCacheCheck)
	select {
	case <-freshCheckStarted:
	case outcome := <-outcomes:
		t.Fatalf("stale revision returned before fresh path: result=%#v err=%v", outcome.result, outcome.err)
	}

	duringFresh, ok := cache.get(key)
	if !ok || duringFresh.revision != refreshedSnapshot.revision || duringFresh.result.Generation.Answer != "concurrent refresh" {
		t.Fatalf("concurrent refresh was deleted: %#v", duringFresh)
	}
	close(continueFreshCheck)
	outcome := <-outcomes
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if got := outcome.result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{fresh.ResourceID}) {
		t.Fatalf("fresh race result evidence = %v", got)
	}
	finalSnapshot, ok := cache.get(key)
	if !ok || finalSnapshot.revision <= refreshedSnapshot.revision {
		t.Fatalf("fresh result did not replace concurrent cache entry: %#v", finalSnapshot)
	}
	if got := finalSnapshot.result.Generation.EvidenceResourceIDs; !reflect.DeepEqual(got, []protocol.ResourceID{fresh.ResourceID}) {
		t.Fatalf("final cache evidence = %v", got)
	}
}

func TestQueryCacheReauthorizesLocalTupleRevocations(t *testing.T) {
	for _, test := range []struct {
		name      string
		principal string
		tuples    []authz.Tuple
		revoke    authz.Tuple
	}{
		{
			name: "direct share", principal: "bob",
			tuples: []authz.Tuple{
				{User: "user:bob", Relation: authz.RelationMember, Object: "organization:acme"},
				{User: "organization:acme", Relation: authz.RelationOrganization, Object: "document:" + string(queryTestModelID)},
				{User: "user:bob", Relation: authz.RelationViewer, Object: "document:" + string(queryTestModelID)},
			},
			revoke: authz.Tuple{User: "user:bob", Relation: authz.RelationViewer, Object: "document:" + string(queryTestModelID)},
		},
		{
			name: "group removal", principal: "alice",
			tuples: []authz.Tuple{
				{User: "user:alice", Relation: authz.RelationMember, Object: "group:engineering"},
				{User: "group:engineering#member", Relation: authz.RelationMember, Object: "organization:acme"},
				{User: "organization:acme", Relation: authz.RelationOrganization, Object: "document:" + string(queryTestModelID)},
				{User: "group:engineering#member", Relation: authz.RelationViewer, Object: "document:" + string(queryTestModelID)},
			},
			revoke: authz.Tuple{User: "user:alice", Relation: authz.RelationMember, Object: "group:engineering"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := queryTestDocument(queryTestModelID, "content", "projection-v1")
			backend := &queryTestKAG{retrieveResult: queryTestRetrieve(document)}
			local, err := authz.NewLocalAuthorizer(cacheTestLocalModel, test.tuples)
			if err != nil {
				t.Fatal(err)
			}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				document.ResourceID: queryTestItem(document),
			}}
			cache := mustQueryCache(t, 4)
			service := cacheTestService(t, backend, local, loader, cache, "retriever-v1", "prompt-v1")
			authorization := queryTestAuthorization(test.principal, "request-before")
			authorization.AuthorizationModelID = cacheTestLocalModel
			authorization.Consistency = protocol.ConsistencyMinimizeLatency
			request := protocol.QueryRequest{Question: "tuple revoke", Authorization: authorization}
			if _, err := service.Query(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if err := local.RemoveTuple(test.revoke); err != nil {
				t.Fatal(err)
			}
			request.Authorization.RequestID = "request-after"
			_, err = service.Query(context.Background(), request)
			if !errors.Is(err, errNoEvidence) {
				t.Fatalf("revoked tuple returned error %v", err)
			}
			if backend.retrieveCalls != 2 || backend.generateCalls != 1 {
				t.Fatalf("revoked tuple returned a cached answer")
			}
			if strings.Contains(err.Error(), test.principal) ||
				strings.Contains(err.Error(), string(document.ResourceID)) {
				t.Fatalf("revoked tuple error leaked metadata or content: %v", err)
			}
		})
	}
}

func TestQueryCacheInvalidationMeasuresLatencyAndCoversProvenance(t *testing.T) {
	now := time.Date(2026, 7, 13, 6, 0, 5, 0, time.UTC)
	cache, err := newQueryCache(2, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	parent := queryTestDocument(queryTestOtherID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestModelID, parent, "chunk")
	request := protocol.QueryRequest{Question: "sensitive question", Authorization: queryTestAuthorization("alice", "request-invalidate")}
	cache.put(cacheTestKey(request, "retriever-v1", "prompt-v1"), QueryResult{
		Generation: kag.GenerateResult{Answer: "sensitive answer"},
		Evidence: protocol.EvidencePackage{Items: []protocol.EvidenceItem{
			queryTestChunkItem(chunk, parent),
		}},
	})
	key := cacheTestKey(request, "retriever-v1", "prompt-v1")
	snapshot, ok := cache.get(key)
	if !ok {
		t.Fatal("cache entry missing before invalidation")
	}

	report, err := cache.InvalidateResource(parent.ResourceID, now.Add(-3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if report.ObservedAt != now || report.PropagationLatency != 3*time.Second || report.RemovedEntries != 1 {
		t.Fatalf("invalidation report = %#v", report)
	}
	if strings.Contains(fmt.Sprintf("%+v", report), request.Question) || strings.Contains(fmt.Sprintf("%+v", report), "sensitive answer") {
		t.Fatalf("invalidation report leaked content: %#v", report)
	}
	if cache.containsRevision(key, snapshot.revision) {
		t.Fatal("in-flight snapshot remained current after invalidation")
	}
	if _, ok := cache.get(key); ok {
		t.Fatal("provenance-bound cache entry survived parent revocation")
	}
	if accepted := cache.put(key, QueryResult{
		Evidence: protocol.EvidencePackage{Items: []protocol.EvidenceItem{
			queryTestChunkItem(chunk, parent),
		}},
	}); accepted {
		t.Fatal("in-flight result was accepted after resource invalidation")
	}
	if _, ok := cache.get(key); ok {
		t.Fatal("in-flight result repopulated a resource-invalidated cache entry")
	}
}

func TestQueryCacheClonesValuesAndEvictsOldestDeterministically(t *testing.T) {
	cache := mustQueryCache(t, 2)
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	result := QueryResult{
		Generation: kag.GenerateResult{
			Answer:              "answer",
			Citations:           []kag.CitationHandle{{Handle: "citation", ResourceID: document.ResourceID}},
			EvidenceResourceIDs: []protocol.ResourceID{document.ResourceID},
			Trace:               kag.GenerationTrace{ResourceIDs: []protocol.ResourceID{document.ResourceID}, Count: 1},
		},
		Evidence: protocol.EvidencePackage{Items: []protocol.EvidenceItem{queryTestItem(document)}},
	}
	key := func(question string) queryCacheKey {
		return cacheTestKey(protocol.QueryRequest{
			Question: question, Authorization: queryTestAuthorization("alice", "request-"+question),
		}, "retriever-v1", "prompt-v1")
	}
	cache.put(key("one"), result)
	cache.put(key("two"), result)
	first, ok := cache.get(key("one"))
	if !ok {
		t.Fatal("first entry missing")
	}
	first.result.Generation.Citations[0].Handle = "changed"
	first.result.Generation.Trace.ResourceIDs[0] = queryTestOtherID
	first.result.Evidence.Items[0].Supports[0].Evidence[0] = queryTestDocument(queryTestOtherID, "parent", "projection-v1")
	again, ok := cache.get(key("one"))
	if !ok || again.result.Generation.Citations[0].Handle != "citation" ||
		again.result.Generation.Trace.ResourceIDs[0] != document.ResourceID ||
		again.result.Evidence.Items[0].Supports[0].Evidence[0] != document {
		t.Fatalf("cache returned caller-mutated value: %#v", again.result)
	}

	cache.put(key("three"), result)
	if _, ok := cache.get(key("one")); ok {
		t.Fatal("oldest inserted entry was not evicted")
	}
	if _, ok := cache.get(key("two")); !ok {
		t.Fatal("second entry was evicted instead of oldest")
	}
	if _, ok := cache.get(key("three")); !ok {
		t.Fatal("new entry missing")
	}
}

func TestQueryCacheConcurrentAccess(t *testing.T) {
	cache := mustQueryCache(t, 16)
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	result := QueryResult{
		Generation: kag.GenerateResult{Answer: "answer"},
		Evidence:   protocol.EvidencePackage{Items: []protocol.EvidenceItem{queryTestItem(document)}},
	}
	revokedAt := time.Now().Add(-time.Second)
	var workers sync.WaitGroup
	for worker := 0; worker < 24; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for iteration := 0; iteration < 50; iteration++ {
				request := protocol.QueryRequest{
					Question:      fmt.Sprintf("question-%d", (worker+iteration)%20),
					Authorization: queryTestAuthorization("alice", fmt.Sprintf("request-%d-%d", worker, iteration)),
				}
				key := cacheTestKey(request, "retriever-v1", "prompt-v1")
				cache.put(key, result)
				cache.get(key)
				if iteration%10 == 0 {
					if _, err := cache.InvalidateResource(document.ResourceID, revokedAt); err != nil {
						t.Errorf("invalidate: %v", err)
						return
					}
				}
			}
		}(worker)
	}
	workers.Wait()
}

func TestQueryCacheConfigurationFailsClosed(t *testing.T) {
	if _, err := NewQueryCache(0); err == nil {
		t.Fatal("zero cache capacity succeeded")
	}
	cache := mustQueryCache(t, 1)
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	options := Options{
		KAG:        &queryTestKAG{retrieveResult: queryTestRetrieve(document)},
		Authorizer: &queryTestAuthorizer{},
		Loader: &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
			document.ResourceID: queryTestItem(document),
		}},
		Cache: cache,
	}
	if _, err := New(options); err == nil || !strings.Contains(err.Error(), "retriever_version") {
		t.Fatalf("missing cache versions error = %v", err)
	}
	options.RetrieverVersion = "retriever-v1"
	if _, err := New(options); err == nil || !strings.Contains(err.Error(), "prompt_version") {
		t.Fatalf("missing prompt version error = %v", err)
	}
	if _, err := cache.InvalidateResource("not-a-resource", time.Now()); err == nil {
		t.Fatal("invalid resource invalidation succeeded")
	}
	if _, err := cache.InvalidateResource(queryTestModelID, time.Time{}); err == nil {
		t.Fatal("zero revocation timestamp succeeded")
	}
}

func mustQueryCache(t *testing.T, capacity int) *QueryCache {
	t.Helper()
	cache, err := NewQueryCache(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

func cacheTestService(
	t *testing.T,
	backend *queryTestKAG,
	authorizer authz.BatchChecker,
	loader *queryTestLoader,
	cache *QueryCache,
	retrieverVersion string,
	promptVersion string,
) *Service {
	return cacheTestServiceWithLimits(
		t, backend, authorizer, loader, cache, retrieverVersion, promptVersion, 10, 4, 0,
	)
}

func cacheTestServiceWithLimits(
	t *testing.T,
	backend *queryTestKAG,
	authorizer authz.BatchChecker,
	loader *queryTestLoader,
	cache *QueryCache,
	retrieverVersion string,
	promptVersion string,
	retrieveLimit int,
	evidenceLimit int,
	expandLimit int,
) *Service {
	t.Helper()
	service, err := New(Options{
		KAG: backend, Authorizer: authorizer, Loader: loader, Cache: cache,
		RetrieverVersion: retrieverVersion, PromptVersion: promptVersion,
		RetrieveLimit: retrieveLimit, EvidenceLimit: evidenceLimit, ExpandLimit: expandLimit,
		Now: func() time.Time { return time.Date(2026, 7, 13, 6, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestQueryCacheQuestionDigestIsExact(t *testing.T) {
	base := protocol.QueryRequest{Question: "question", Authorization: queryTestAuthorization("alice", "request-1")}
	changed := base
	changed.Question = "question "
	if reflect.DeepEqual(
		cacheTestKey(base, "retriever-v1", "prompt-v1"),
		cacheTestKey(changed, "retriever-v1", "prompt-v1"),
	) {
		t.Fatal("different exact questions shared a cache key")
	}
}

func cacheTestKey(request protocol.QueryRequest, retrieverVersion, promptVersion string) queryCacheKey {
	return newQueryCacheKey(request, retrieverVersion, promptVersion, 10, 4, 0)
}
