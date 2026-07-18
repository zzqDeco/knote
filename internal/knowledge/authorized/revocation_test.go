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
			service := revocationTestService(t, local, nil, time.Now, revocationTestItem(document, "STALE_WATERMARK_CONTENT_CANARY"))

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
	}, revocationTestItem(document, "MODEL_CONTENT_CANARY"))

	report, err := service.AuthorizeProtectedContent(context.Background(), current, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Allowed() || report.Consistency != protocol.ConsistencyHigherConsistency {
		t.Fatalf("live authorization report = %#v", report)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("live authorization calls = %d", len(authorizer.calls))
	}
	for _, call := range authorizer.calls {
		if call.AuthorizationModelID != current.AuthorizationModelID || call.Consistency != authz.ConsistencyHigherConsistency {
			t.Fatalf("live authorization request = %#v", call)
		}
	}
}

func TestAuthorizeProtectedContentReauthorizesIntermediateClaimWithoutLoadingIt(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	claim := revocationTestClaim(t, "authorization-only-claim")
	authorization := queryTestAuthorization("alice", "request-claim-replay")
	binding, _ := revocationTestBindingWithIntermediateClaim(
		t, authorization, queryTestItem(document), claim,
	)
	authorizer := &queryTestAuthorizer{}
	loader := &queryTestLoader{load: func(handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
		if len(handles) != 1 || handles[0] != document {
			return nil, fmt.Errorf("loader received authorization-only path resources: %#v", handles)
		}
		return []protocol.EvidenceItem{queryTestItem(document)}, nil
	}}
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: loader,
		RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	report, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
	if err != nil || !report.Allowed() || report.ResourceCount != 2 {
		t.Fatalf("intermediate Claim replay authorization = %#v, %v", report, err)
	}
	if len(loader.calls) != 1 || len(loader.calls[0]) != 1 || loader.calls[0][0] != document {
		t.Fatalf("intermediate Claim reached the evidence loader: %#v", loader.calls)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("live authorization calls = %d, want pre-load and post-load checks", len(authorizer.calls))
	}
	for _, call := range authorizer.calls {
		if call.Consistency != authz.ConsistencyHigherConsistency || len(call.Checks) != 2 ||
			!revocationTestChecksObject(call, document.AuthorizationID) ||
			!revocationTestChecksObject(call, claim.AuthorizationID) {
			t.Fatalf("live authorization did not cover every protected binding resource: %#v", call)
		}
	}
}

func TestIntermediateClaimRevocationFailsClosedAndTombstonesCache(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	claim := revocationTestClaim(t, "revoked-intermediate-claim")
	authorization := queryTestAuthorization("alice", "request-revoked-claim")
	binding, evidence := revocationTestBindingWithIntermediateClaim(
		t, authorization, queryTestItem(document), claim,
	)

	t.Run("live deny", func(t *testing.T) {
		authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
				return check.Object != claim.AuthorizationID
			}), nil
		}}
		loader := &queryTestLoader{load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
			return nil, errors.New("authorization-only Claim denial should precede loading")
		}}
		service, err := New(Options{
			KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: loader,
			RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}

		report, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
		if !errors.Is(err, ErrProtectedContentUnavailable) || err.Error() != ErrProtectedContentUnavailable.Error() ||
			report.ResourceCount != 2 || report.AllowedCount != 1 || report.DeniedCount != 1 {
			t.Fatalf("denied intermediate Claim replay = %#v, %v", report, err)
		}
		if len(loader.calls) != 0 {
			t.Fatalf("denied intermediate Claim reached loader: %#v", loader.calls)
		}
	})

	t.Run("tombstone", func(t *testing.T) {
		cacheNow := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
		cache, err := newQueryCache(4, func() time.Time { return cacheNow })
		if err != nil {
			t.Fatal(err)
		}
		authorizer := &queryTestAuthorizer{}
		loader := &queryTestLoader{load: func(handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
			if len(handles) != 1 || handles[0] != document {
				return nil, fmt.Errorf("loader received authorization-only path resources: %#v", handles)
			}
			return []protocol.EvidenceItem{queryTestItem(document)}, nil
		}}
		service, err := New(Options{
			KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: loader, Cache: cache,
			RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
			RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := NewRevocationCoordinator(service)
		if err != nil {
			t.Fatal(err)
		}
		key := cacheTestKey(
			protocol.QueryRequest{Question: "claim cache", Authorization: authorization},
			"retriever-v1", "prompt-v1",
		)
		cached := QueryResult{Evidence: evidence}
		if !cache.put(key, cached) {
			t.Fatal("cache entry with an intermediate Claim was rejected before revocation")
		}

		report, err := coordinator.Apply(context.Background(), RevocationRequest{
			Authorization: authorization,
			Binding:       binding,
			ResourceIDs:   []protocol.ResourceID{claim.ResourceID},
			RevokedAt:     cacheNow.Add(-time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.InvalidatedResourceCount != 1 || report.RemovedEntryCount != 1 ||
			report.ProtectedResourceCount != 2 || report.AllowedCount != 2 {
			t.Fatalf("intermediate Claim revocation report = %#v", report)
		}
		if _, ok := cache.get(key); ok {
			t.Fatal("intermediate Claim tombstone did not evict the bound cache entry")
		}
		if cache.put(key, cached) {
			t.Fatal("intermediate Claim tombstone allowed an in-flight cache put")
		}
		if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) ||
			err.Error() != ErrProtectedContentUnavailable.Error() {
			t.Fatalf("tombstoned intermediate Claim replay error = %v", err)
		}
		if len(loader.calls) != 0 {
			t.Fatalf("tombstoned intermediate Claim reached loader: %#v", loader.calls)
		}
	})
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
	binding := revocationTestBindingForItem(t, authorization, queryTestChunkItem(chunk, parent))
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

func TestAuthorizeProtectedContentValidatesSelectedDerivedEvidenceProvenance(t *testing.T) {
	authorization := queryTestAuthorization("alice", "request-derived-replay")
	artifact := queryTestDocument(queryTestModelID, "derived content", "projection-v1")
	artifact.Type = protocol.ResourceDerivedArtifact
	artifact.AuthorizationID = "derived_artifact:" + string(artifact.ResourceID)
	source := queryTestDocument(queryTestOtherID, "source content", "projection-v1")
	item := protocol.EvidenceItem{
		Resource: artifact, Content: "derived content", Derivation: protocol.DerivationAllRequired,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-source", Resource: source,
			Evidence: []protocol.ResourceHandle{source}, Complete: false,
		}},
		Citation: protocol.Citation{Handle: "citation-derived", Resource: artifact},
	}
	binding := revocationTestBindingForItem(t, authorization, item)
	loader := &queryTestLoader{load: func(handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
		if len(handles) != 1 || handles[0] != artifact {
			return nil, fmt.Errorf("strict loader received non-root handles: %#v", handles)
		}
		return []protocol.EvidenceItem{item}, nil
	}}
	service := revocationTestServiceWithLoader(t, loader)

	report, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
	if err != nil || !report.Allowed() {
		t.Fatalf("derived evidence authorization = %#v, %v", report, err)
	}
	if report.ResourceCount != 2 || report.AllowedCount != 2 {
		t.Fatalf("derived evidence authorization decisions = %#v", report)
	}
	if len(loader.calls) != 1 || len(loader.calls[0]) != 1 || loader.calls[0][0] != artifact {
		t.Fatalf("derived evidence loader calls = %#v", loader.calls)
	}
}

func TestAuthorizeProtectedContentRejectsDerivedEvidenceMetadataDrift(t *testing.T) {
	authorization := queryTestAuthorization("alice", "request-derived-drift")
	artifact := queryTestDocument(queryTestModelID, "derived content", "projection-v1")
	artifact.Type = protocol.ResourceDerivedArtifact
	artifact.AuthorizationID = "derived_artifact:" + string(artifact.ResourceID)
	parent := queryTestDocument(queryTestOtherID, "parent", "projection-v1")
	chunkID, err := protocol.NewStableResourceID("tenant-1", "kb-1", protocol.ResourceChunk, "derived-support")
	if err != nil {
		t.Fatal(err)
	}
	chunk := queryTestChunk(chunkID, parent, "chunk")
	original := protocol.EvidenceItem{
		Resource: artifact, Content: "derived content", Derivation: protocol.DerivationAllRequired,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-chunk", Resource: chunk,
			Evidence: []protocol.ResourceHandle{parent}, Complete: false,
		}},
		Citation: protocol.Citation{Handle: "citation-derived", Resource: artifact},
	}
	binding := revocationTestBindingForItem(t, authorization, original)

	for _, test := range []struct {
		name   string
		mutate func(protocol.EvidenceItem) protocol.EvidenceItem
	}{
		{
			name: "selected handle",
			mutate: func(item protocol.EvidenceItem) protocol.EvidenceItem {
				item.Resource.Versions.Content = "content-v2"
				item.Citation.Resource = item.Resource
				return item
			},
		},
		{
			name: "provenance handle",
			mutate: func(item protocol.EvidenceItem) protocol.EvidenceItem {
				item.Supports[0].Resource.Versions.Content = "content-v2"
				return item
			},
		},
		{
			name: "authorization boundary",
			mutate: func(item protocol.EvidenceItem) protocol.EvidenceItem {
				item.Supports[0].Evidence[0].Versions.Content = "content-v2"
				return item
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			loaded := original
			loaded.Supports = append([]protocol.ProvenanceSupport(nil), original.Supports...)
			loaded.Supports[0].Evidence = append([]protocol.ResourceHandle(nil), original.Supports[0].Evidence...)
			loaded = test.mutate(loaded)
			loader := &queryTestLoader{load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
				return []protocol.EvidenceItem{loaded}, nil
			}}
			service := revocationTestServiceWithLoader(t, loader)

			if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) {
				t.Fatalf("derived evidence %s drift remained replayable: %v", test.name, err)
			}
		})
	}
}

func TestAuthorizeProtectedContentWithoutCacheRejectsExactHandleAndBoundaryDrift(t *testing.T) {
	authorization := queryTestAuthorization("alice", "request-nil-cache-drift")
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	changedDocument := document
	changedDocument.Versions.Content = "content-v2"
	parent := queryTestDocument(queryTestModelID, "parent", "projection-v1")
	chunk := queryTestChunk(queryTestOtherID, parent, "chunk")
	changedParent := parent
	changedParent.Versions.Content = "content-v2"

	for _, test := range []struct {
		name     string
		original protocol.EvidenceItem
		loaded   protocol.EvidenceItem
	}{
		{name: "exact handle", original: queryTestItem(document), loaded: queryTestItem(changedDocument)},
		{name: "authorization boundary", original: queryTestChunkItem(chunk, parent), loaded: queryTestChunkItem(chunk, changedParent)},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := revocationTestBindingForItem(t, authorization, test.original)
			authorizer := &queryTestAuthorizer{}
			loader := &queryTestLoader{items: map[protocol.ResourceID]protocol.EvidenceItem{
				test.original.Resource.ResourceID: test.loaded,
			}}
			service, err := New(Options{
				KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: loader,
				RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
			})
			if err != nil {
				t.Fatal(err)
			}

			if _, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding); !errors.Is(err, ErrProtectedContentUnavailable) {
				t.Fatalf("nil-cache %s drift remained replayable: %v", test.name, err)
			}
			if len(loader.calls) != 1 || len(authorizer.calls) != 1 {
				t.Fatalf("nil-cache %s checks: authz=%d load=%d", test.name, len(authorizer.calls), len(loader.calls))
			}
		})
	}
}

func TestAuthorizeProtectedContentRechecksLiveAuthorizationAfterExactReload(t *testing.T) {
	document := queryTestDocument(queryTestModelID, "content", "projection-v1")
	authorization := queryTestAuthorization("alice", "request-revoked-during-load")
	binding := revocationTestBinding(t, authorization, document)
	events := []string{}
	revoked := false
	authorizer := &queryTestAuthorizer{
		events: &events,
		decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
			return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return !revoked }), nil
		},
	}
	loader := &queryTestLoader{
		events: &events,
		load: func([]protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
			revoked = true
			return []protocol.EvidenceItem{queryTestItem(document)}, nil
		},
	}
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: loader,
		RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	report, err := service.AuthorizeProtectedContent(context.Background(), authorization, binding)
	if !errors.Is(err, ErrProtectedContentUnavailable) || report.AllowedCount != 0 || report.DeniedCount != 1 {
		t.Fatalf("authorization revoked during exact reload = %#v, %v", report, err)
	}
	if got := strings.Join(events, ","); got != "authz,load,authz" {
		t.Fatalf("revocation check order = %q", got)
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

func (b *blockingGenerateKAG) Discover(context.Context, kag.DiscoverRequest) (kag.DiscoverResult, error) {
	return kag.DiscoverResult{
		Mode: "fake", Resources: []protocol.ResourceHandle{b.document}, Complete: true,
	}, nil
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
	binding, err := protocol.NewProtectedContentBindingFromResourcesForAuthorization(
		authorization,
		[]protocol.ProtectedResourceBinding{{Resource: resource, AuthorizationResource: resource}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func revocationTestBindingForItem(
	t *testing.T,
	authorization protocol.AuthorizationContext,
	item protocol.EvidenceItem,
) protocol.ProtectedContentBinding {
	t.Helper()
	handles, boundaries, _, err := collectEvidenceHandles(authorization, []protocol.EvidenceItem{item})
	if err != nil {
		t.Fatal(err)
	}
	objects := make(map[string]objectCheck, len(handles))
	for index, handle := range handles {
		if _, ok := objects[handle.AuthorizationID]; !ok {
			objects[handle.AuthorizationID] = objectCheck{
				correlationID: fmt.Sprintf("binding-root-%d", index), allowed: true,
			}
		}
	}
	evidence, err := buildEvidencePackage(
		authorization,
		[]protocol.EvidenceItem{item},
		checkedEvidence{handles: handles, boundaries: boundaries, projection: handles[0].Versions.Projection, objects: objects},
		time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func revocationTestBindingWithIntermediateClaim(
	t *testing.T,
	authorization protocol.AuthorizationContext,
	item protocol.EvidenceItem,
	claim protocol.ResourceHandle,
) (protocol.ProtectedContentBinding, protocol.EvidencePackage) {
	t.Helper()
	handles, boundaries, projection, err := collectEvidenceHandles(
		authorization, []protocol.EvidenceItem{item},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.ValidateFor(authorization); err != nil {
		t.Fatal(err)
	}
	if claim.Type != protocol.ResourceClaim || claim.Versions.Projection != projection {
		t.Fatal("intermediate Claim must match the evidence projection")
	}
	handles = append(handles, claim)
	boundaries[claim.ResourceID] = claim
	objects := make(map[string]objectCheck, len(handles))
	for index, handle := range handles {
		objects[handle.AuthorizationID] = objectCheck{
			correlationID: fmt.Sprintf("binding-resource-%d", index), allowed: true,
		}
	}
	evidence, err := buildEvidencePackage(
		authorization,
		[]protocol.EvidenceItem{item},
		checkedEvidence{handles: handles, boundaries: boundaries, projection: projection, objects: objects},
		time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return binding, evidence
}

func revocationTestClaim(t *testing.T, sourceKey string) protocol.ResourceHandle {
	t.Helper()
	resourceID, err := protocol.NewStableResourceID(
		"tenant-1", "kb-1", protocol.ResourceClaim, sourceKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	claim := queryTestDocument(resourceID, "claim", "projection-v1")
	claim.Type = protocol.ResourceClaim
	claim.AuthorizationID = "claim:" + string(resourceID)
	return claim
}

func revocationTestChecksObject(request authz.BatchCheckRequest, object string) bool {
	for _, check := range request.Checks {
		if check.Object == object {
			return true
		}
	}
	return false
}

func revocationTestServiceWithLoader(t *testing.T, loader EvidenceLoader) *Service {
	t.Helper()
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: &queryTestAuthorizer{}, Loader: loader,
		RetrieveLimit: 10, EvidenceLimit: 2, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func revocationTestService(
	t *testing.T,
	authorizer authz.BatchChecker,
	cache *QueryCache,
	now func() time.Time,
	loaded ...protocol.EvidenceItem,
) *Service {
	t.Helper()
	items := make(map[protocol.ResourceID]protocol.EvidenceItem, len(loaded))
	for _, item := range loaded {
		items[item.Resource.ResourceID] = item
	}
	service, err := New(Options{
		KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: &queryTestLoader{items: items}, Cache: cache,
		RetrieverVersion: "retriever-v1", PromptVersion: "prompt-v1",
		RetrieveLimit: 10, EvidenceLimit: 2, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func revocationTestItem(resource protocol.ResourceHandle, content string) protocol.EvidenceItem {
	return protocol.EvidenceItem{
		Resource: resource, Content: content, Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support-" + string(resource.ResourceID), Resource: resource,
			Evidence: []protocol.ResourceHandle{resource}, Complete: true,
		}},
		Citation: protocol.Citation{Handle: "citation-" + string(resource.ResourceID), Resource: resource},
	}
}
