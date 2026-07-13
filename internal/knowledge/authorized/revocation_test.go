package authorized

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestAuthorizeProtectedContentRechecksDirectAndGroupRevocationsWithStaleWatermarks(t *testing.T) {
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
			document := queryTestDocument(queryTestModelID, "STALE_WATERMARK_CONTENT_CANARY", "projection-v1")
			authorization := queryTestAuthorization(test.principal, "request-live-recheck")
			authorization.AuthorizationModelID = cacheTestLocalModel
			authorization.Consistency = protocol.ConsistencyMinimizeLatency
			binding := revocationTestBinding(t, authorization, document)
			local, err := authz.NewLocalAuthorizer(cacheTestLocalModel, test.tuples)
			if err != nil {
				t.Fatal(err)
			}
			service := revocationTestService(t, local, nil, time.Now)

			before, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
			if err != nil || !before.Allowed() {
				t.Fatalf("authorization before revoke = %#v, %v", before, err)
			}
			if err := local.RemoveTuple(test.revoke); err != nil {
				t.Fatal(err)
			}
			after, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
			if !errors.Is(err, ErrProtectedContentUnavailable) || after.DeniedCount != 1 {
				t.Fatalf("authorization after revoke = %#v, %v", after, err)
			}
			if strings.Contains(err.Error(), test.principal) || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("live revocation error leaked protected data: %v", err)
			}
		})
	}
}

func TestAuthorizeProtectedContentUsesCurrentModelAndHigherConsistency(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "MODEL_CONTENT_CANARY", "projection-v1")
	original := queryTestAuthorization("alice", "request-old-model")
	binding := revocationTestBinding(t, original, document)
	current := original
	current.RequestID = "request-new-model"
	current.AuthorizationModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
	current.Consistency = protocol.ConsistencyMinimizeLatency
	authorizer := &queryTestAuthorizer{}
	service := revocationTestService(t, authorizer, nil, func() time.Time {
		return time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	})

	report, err := service.AuthorizeProtectedContent(context.Background(), current, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Allowed() || report.Consistency != protocol.ConsistencyHigherConsistency {
		t.Fatalf("live authorization report = %#v", report)
	}
	if len(authorizer.calls) != 1 {
		t.Fatalf("live authorization calls = %d", len(authorizer.calls))
	}
	call := authorizer.calls[0]
	if call.AuthorizationModelID != current.AuthorizationModelID || call.Consistency != authz.ConsistencyHigherConsistency {
		t.Fatalf("live authorization request = %#v", call)
	}
}

func TestRevocationCoordinatorInvalidatesAndReportsMetadataOnly(t *testing.T) {
	cacheNow := time.Date(2026, 7, 13, 9, 0, 5, 0, time.UTC)
	cache, err := newQueryCache(4, func() time.Time { return cacheNow })
	if err != nil {
		t.Fatal(err)
	}
	document := queryTestDocument(queryTestModelID, "REPORT_CONTENT_CANARY", "projection-v1")
	authorization := queryTestAuthorization("alice", "REPORT_REQUEST_CANARY")
	authorization.Consistency = protocol.ConsistencyMinimizeLatency
	binding := revocationTestBinding(t, authorization, document)
	allowed := false
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return allowed }), nil
	}}
	service := revocationTestService(t, authorizer, cache, func() time.Time {
		return time.Date(2026, 7, 13, 9, 0, 6, 0, time.UTC)
	})
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.QueryRequest{Question: "REPORT_QUESTION_CANARY", Authorization: authorization}
	key := cacheTestKey(request, "retriever-v1", "prompt-v1")
	if !cache.put(key, QueryResult{
		Generation: kag.GenerateResult{Answer: "REPORT_ANSWER_CANARY"},
		Evidence:   protocol.EvidencePackage{Items: []protocol.EvidenceItem{{Resource: document}}},
	}) {
		t.Fatal("cache entry was not accepted before revocation")
	}
	revokedAt := cacheNow.Add(-3 * time.Second)

	report, err := coordinator.Apply(context.Background(), RevocationRequest{
		Authorization: authorization, Binding: binding, ResourceIDs: []protocol.ResourceID{document.ResourceID}, RevokedAt: revokedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.ObservedAt != cacheNow || report.PropagationLatency != 3*time.Second ||
		report.ProtectedResourceCount != 1 || report.InvalidatedResourceCount != 1 ||
		report.RemovedEntryCount != 1 || report.AllowedCount != 0 || report.DeniedCount != 1 {
		t.Fatalf("revocation report = %#v", report)
	}
	if len(report.Decisions) != 1 || report.Decisions[0].ResourceID != document.ResourceID ||
		report.Decisions[0].Outcome != protocol.DecisionDeny {
		t.Fatalf("revocation decisions = %#v", report.Decisions)
	}
	if got := authorizer.calls[0].Consistency; got != authz.ConsistencyHigherConsistency {
		t.Fatalf("revocation consistency = %q", got)
	}
	encoded := fmt.Sprintf("%+v", report)
	for _, canary := range []string{"REPORT_CONTENT_CANARY", "REPORT_REQUEST_CANARY", "REPORT_QUESTION_CANARY", "REPORT_ANSWER_CANARY"} {
		if strings.Contains(encoded, canary) {
			t.Fatalf("revocation report leaked %q: %s", canary, encoded)
		}
	}
	if _, ok := cache.get(key); ok {
		t.Fatal("revoked cache entry survived coordinator application")
	}
	if cache.put(key, QueryResult{Evidence: protocol.EvidencePackage{Items: []protocol.EvidenceItem{{Resource: document}}}}) {
		t.Fatal("revoked cache resource was repopulated")
	}
}

func TestRevocationFailuresAreGenericAndStillTombstone(t *testing.T) {
	cache := mustQueryCache(t, 2)
	document := queryTestDocument(queryTestModelID, "ERROR_CONTENT_CANARY", "projection-v1")
	authorization := queryTestAuthorization("alice", "request-error")
	binding := revocationTestBinding(t, authorization, document)
	authorizer := &queryTestAuthorizer{decide: func(_ int, _ authz.BatchCheckRequest) ([]authz.Decision, error) {
		return nil, errors.New("AUTHORIZER_ERROR_CANARY")
	}}
	service := revocationTestService(t, authorizer, cache, time.Now)
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) ||
		strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("protected content error = %v", err)
	}
	_, err = coordinator.Apply(context.Background(), RevocationRequest{
		Authorization: authorization, Binding: binding, ResourceIDs: []protocol.ResourceID{document.ResourceID}, RevokedAt: time.Now().Add(-time.Second),
	})
	if !errors.Is(err, ErrRevocationUnavailable) || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("revocation error = %v", err)
	}
	key := cacheTestKey(protocol.QueryRequest{Question: "q", Authorization: authorization}, "retriever-v1", "prompt-v1")
	if cache.put(key, QueryResult{Evidence: protocol.EvidencePackage{Items: []protocol.EvidenceItem{{Resource: document}}}}) {
		t.Fatal("failed live report did not preserve revocation tombstone")
	}
}

func TestRevocationPreventsInFlightQueryResult(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	backend := &blockingGenerateKAG{
		document: document, started: make(chan struct{}), release: make(chan struct{}),
	}
	cache := mustQueryCache(t, 2)
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		document.ResourceID: queryTestItem(document),
	}}
	service, err := New(Options{
		KAG: backend, Authorizer: authorizer, Loader: loader, Cache: cache,
		RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1", RetrieveLimit: 10, EvidenceLimit: 2,
		Now: func() time.Time { return time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-in-flight")
	authorization.Consistency = protocol.ConsistencyMinimizeLatency
	binding := revocationTestBinding(t, authorization, document)
	type queryOutcome struct {
		result QueryResult
		err    error
	}
	done := make(chan queryOutcome, 1)
	go func() {
		result, err := service.Query(context.Background(), protocol.QueryRequest{
			Question: "IN_FLIGHT_QUESTION_CANARY", Authorization: authorization,
		})
		done <- queryOutcome{result: result, err: err}
	}()
	<-backend.started
	if _, err := coordinator.Apply(context.Background(), RevocationRequest{
		Authorization: authorization, Binding: binding, ResourceIDs: []protocol.ResourceID{document.ResourceID}, RevokedAt: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	close(backend.release)
	outcome := <-done
	if !errors.Is(outcome.err, ErrProtectedContentUnavailable) {
		t.Fatalf("in-flight query error = %v", outcome.err)
	}
	if strings.Contains(outcome.err.Error(), "CANARY") || outcome.result.Generation.Answer != "" {
		t.Fatalf("in-flight query leaked protected result: %#v, %v", outcome.result, outcome.err)
	}
}

func TestRevocationTombstoneDeniesReplayAndCitationWhenAuthorizationStillAllows(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	cache := mustQueryCache(t, 4)
	authorizer := &queryTestAuthorizer{}
	service, err := New(Options{
		KAG:        &queryTestKAG{retrieveResult: queryTestRetrieve(document)},
		Authorizer: authorizer,
		Loader: &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
			document.ResourceID: queryTestItem(document),
		}},
		Cache: cache, RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 10, EvidenceLimit: 2,
		Now: func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-resource-revoke")
	result, err := service.Query(context.Background(), protocol.QueryRequest{Question: "q", Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, result.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	report, err := coordinator.Apply(context.Background(), RevocationRequest{
		Authorization: authorization,
		Binding:       binding,
		ResourceIDs:   []protocol.ResourceID{document.ResourceID},
		RevokedAt:     time.Now().Add(-time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.AllowedCount != 1 || report.DeniedCount != 0 {
		t.Fatalf("authorization unexpectedly changed during resource revocation: %#v", report)
	}
	if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) {
		t.Fatalf("revoked protected block remained replayable: %v", err)
	}
	citationHandle := result.Evidence.Items[0].Citation.Handle
	if _, err := service.OpenCitation(context.Background(), authorization, result.Evidence, citationHandle); !errors.Is(err, ErrCitationUnavailable) {
		t.Fatalf("revoked citation remained openable: %v", err)
	}
}

func TestAuthorizeProtectedContentRejectsChangedExactResourceHandle(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		document.ResourceID: queryTestItem(document),
	}}
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: &queryTestAuthorizer{}, Loader: loader,
		Cache: mustQueryCache(t, 2), RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-exact-replay")
	binding := revocationTestBinding(t, authorization, document)
	if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); err != nil {
		t.Fatalf("current exact handle was denied: %v", err)
	}
	changed := document
	changed.Versions.Content = "content-v2"
	loader.items[document.ResourceID] = queryTestItem(changed)
	if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) {
		t.Fatalf("changed exact handle remained replayable: %v", err)
	}
}

func TestAuthorizeProtectedContentRejectsChangedChunkAuthorizationBoundaryHandle(t *testing.T) {
	parent := queryTestDocument(queryTestModelID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestOtherID, parent, "chunk")
	loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
		chunk.ResourceID: queryTestChunkItem(chunk, parent),
	}}
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: &queryTestAuthorizer{}, Loader: loader,
		Cache: mustQueryCache(t, 2), RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-boundary-replay")
	binding, err := protocol.NewProtectedContentBindingFromResources(
		authorization.SessionID,
		authorization.RequestID,
		[]protocol.ProtectedResourceBinding{{Resource: chunk, AuthorizationResource: parent}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); err != nil {
		t.Fatalf("current authorization boundary was denied: %v", err)
	}

	changedParent := parent
	changedParent.Versions.Content = "content-v2"
	loader.items[chunk.ResourceID] = queryTestChunkItem(chunk, changedParent)
	if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) {
		t.Fatalf("changed authorization boundary remained replayable: %v", err)
	}
}

func TestAuthorizeProtectedContentRejectsTombstoneIntroducedDuringExactLoad(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	cache := mustQueryCache(t, 2)
	loadStarted := make(chan struct{})
	releaseLoad := make(chan struct{})
	loader := &queryTestLoader{load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
		close(loadStarted)
		<-releaseLoad
		return []protocol.EvidenceItem{queryTestItem(document)}, nil
	}}
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: &queryTestAuthorizer{}, Loader: loader,
		Cache: cache, RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-concurrent-revoke")
	binding := revocationTestBinding(t, authorization, document)
	done := make(chan error, 1)
	go func() {
		_, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
		done <- err
	}()

	<-loadStarted
	if _, err := cache.InvalidateResource(document.ResourceID, time.Now()); err != nil {
		close(releaseLoad)
		t.Fatal(err)
	}
	close(releaseLoad)
	if err := <-done; !errors.Is(err, ErrProtectedContentUnavailable) {
		t.Fatalf("protected content survived concurrent tombstone: %v", err)
	}
}

func TestRevocationRejectsMissingOrUnboundTargetsBeforeInvalidation(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	cache := mustQueryCache(t, 4)
	service := revocationTestService(t, &queryTestAuthorizer{}, cache, time.Now)
	coordinator, err := NewRevocationCoordinator(service)
	if err != nil {
		t.Fatal(err)
	}
	authorization := queryTestAuthorization("alice", "request-invalid-target")
	binding := revocationTestBinding(t, authorization, document)
	for _, targets := range [][]protocol.ResourceID{
		nil,
		{queryTestOtherID},
	} {
		_, err := coordinator.Apply(context.Background(), RevocationRequest{
			Authorization: authorization, Binding: binding, ResourceIDs: targets, RevokedAt: time.Now(),
		})
		if !errors.Is(err, ErrRevocationUnavailable) {
			t.Fatalf("invalid revocation targets %v error = %v", targets, err)
		}
	}
	key := cacheTestKey(protocol.QueryRequest{Question: "q", Authorization: authorization}, "retriever-v1", "prompt-v1")
	if !cache.put(key, QueryResult{Evidence: protocol.EvidencePackage{Items: []protocol.EvidenceItem{{Resource: document}}}}) {
		t.Fatal("invalid revocation target left a tombstone")
	}
}

type blockingGenerateKAG struct {
	document protocol.ResourceHandle
	started  chan struct{}
	release  chan struct{}
}

func (b *blockingGenerateKAG) Retrieve(context.Context, kag.RetrieveRequest) (kag.RetrieveResult, error) {
	return queryTestRetrieve(b.document), nil
}

func (*blockingGenerateKAG) Expand(context.Context, kag.ExpandRequest) (kag.ExpandResult, error) {
	return kag.ExpandResult{}, nil
}

func (b *blockingGenerateKAG) Generate(ctx context.Context, request kag.GenerateRequest) (kag.GenerateResult, error) {
	close(b.started)
	select {
	case <-ctx.Done():
		return kag.GenerateResult{}, ctx.Err()
	case <-b.release:
	}
	fake := &queryTestKAG{}
	return fake.Generate(ctx, request)
}

func revocationTestBinding(
	t *testing.T,
	authorization protocol.AuthorizationContext,
	resource protocol.ResourceHandle,
) protocol.ProtectedContentBinding {
	t.Helper()
	binding, err := protocol.NewProtectedContentBindingFromResources(
		authorization.SessionID,
		authorization.RequestID,
		[]protocol.ProtectedResourceBinding{{Resource: resource, AuthorizationResource: resource}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func revocationTestService(
	t *testing.T,
	authorizer authz.BatchChecker,
	cache *QueryCache,
	now func() time.Time,
) *Service {
	t.Helper()
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: &queryTestLoader{}, Cache: cache,
		RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 10, EvidenceLimit: 2, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
