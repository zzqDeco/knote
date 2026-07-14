package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestGraphAllowlistsAreExplicitStableAndDefensive(t *testing.T) {
	wantPredicates := []ClaimPredicateSourceKey{
		ClaimPredicateContradicts,
		ClaimPredicateCreatedBy,
		ClaimPredicateDependsOn,
		ClaimPredicateDerivedFrom,
		ClaimPredicateLocatedIn,
		ClaimPredicateMemberOf,
		ClaimPredicateOwnedBy,
		ClaimPredicatePartOf,
		ClaimPredicateRelatedTo,
		ClaimPredicateSupports,
	}
	gotPredicates := SupportedClaimPredicateSourceKeys()
	if !reflect.DeepEqual(gotPredicates, wantPredicates) {
		t.Fatalf("supported predicates = %v, want %v", gotPredicates, wantPredicates)
	}
	for _, sourceKey := range gotPredicates {
		predicateKey, err := NewClaimPredicateKey(string(sourceKey))
		if err != nil {
			t.Fatalf("declared predicate %q: %v", sourceKey, err)
		}
		if err := predicateKey.Validate(); err != nil {
			t.Fatalf("declared predicate key %q: %v", predicateKey, err)
		}
	}
	locatedIn, err := NewClaimPredicateKey(string(ClaimPredicateLocatedIn))
	if err != nil {
		t.Fatal(err)
	}
	if locatedIn != "pred_a3b0b7f1948c58d586d3af99fee4704e" {
		t.Fatalf("located_in predicate key changed: %s", locatedIn)
	}
	gotPredicates[0] = "mutated"
	if SupportedClaimPredicateSourceKeys()[0] != ClaimPredicateContradicts {
		t.Fatal("supported predicate list exposed mutable registry state")
	}
	if _, err := NewClaimPredicateKey("undeclared_private_relation"); err == nil {
		t.Fatal("undeclared predicate source was accepted")
	}
	if err := ClaimPredicateKey("pred_ffffffffffffffffffffffffffffffff").Validate(); err == nil {
		t.Fatal("undeclared opaque predicate key was accepted")
	}

	wantKinds := []GraphResourceKind{
		GraphResourceChunk,
		GraphResourceClaim,
		GraphResourceDerivedArtifact,
		GraphResourceDocument,
		GraphResourceEntity,
	}
	gotKinds := SupportedGraphResourceKinds()
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Fatalf("supported resource kinds = %v, want %v", gotKinds, wantKinds)
	}
	gotKinds[0] = "mutated"
	if SupportedGraphResourceKinds()[0] != GraphResourceChunk {
		t.Fatal("supported resource kind list exposed mutable registry state")
	}
}

func TestCompileGraphQueryProducesDeterministicTemplateOwnedDescriptor(t *testing.T) {
	query := validGraphQueryFixture()
	query.StartResourceIDs = []ResourceID{graphQueryResourceID(2), graphQueryResourceID(1), graphQueryResourceID(2)}
	query.PredicateSources = []ClaimPredicateSourceKey{
		ClaimPredicatePartOf,
		ClaimPredicateLocatedIn,
		ClaimPredicatePartOf,
	}
	query.ResourceKinds = []GraphResourceKind{GraphResourceEntity, GraphResourceClaim, GraphResourceEntity}
	query.Fields = []GraphField{GraphFieldResourceKind, GraphFieldClaimID, GraphFieldResourceKind}
	query.Filters = []GraphFilter{
		{
			Kind:        GraphFilterDerivationIn,
			Derivations: []DerivationMode{DerivationAnySupport, DerivationAllRequired},
		},
		{
			Kind:        GraphFilterObjectIDIn,
			ResourceIDs: []ResourceID{graphQueryResourceID(4), graphQueryResourceID(3), graphQueryResourceID(4)},
		},
	}
	query.Order = []GraphOrder{
		{Key: GraphSortSubjectID, Direction: GraphSortDescending, Priority: 0},
		{Key: GraphSortObjectID, Direction: GraphSortAscending, Priority: 1},
	}

	permuted := validGraphQueryFixture()
	permuted.StartResourceIDs = []ResourceID{graphQueryResourceID(1), graphQueryResourceID(2)}
	permuted.PredicateSources = []ClaimPredicateSourceKey{ClaimPredicateLocatedIn, ClaimPredicatePartOf}
	permuted.ResourceKinds = []GraphResourceKind{GraphResourceClaim, GraphResourceEntity}
	permuted.Fields = []GraphField{GraphFieldResourceKind}
	permuted.Filters = []GraphFilter{
		{
			Kind:        GraphFilterObjectIDIn,
			ResourceIDs: []ResourceID{graphQueryResourceID(3), graphQueryResourceID(4)},
		},
		{
			Kind:        GraphFilterDerivationIn,
			Derivations: []DerivationMode{DerivationAllRequired, DerivationAnySupport},
		},
	}
	permuted.Order = []GraphOrder{
		{Key: GraphSortObjectID, Direction: GraphSortAscending, Priority: 1},
		{Key: GraphSortSubjectID, Direction: GraphSortDescending, Priority: 0},
	}

	first, err := CompileGraphQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileGraphQuery(permuted)
	if err != nil {
		t.Fatal(err)
	}
	if first.Template != GraphOperationTemplateClaimTraversalV1 {
		t.Fatalf("template = %q", first.Template)
	}
	if first.Parameters.PredicateAllowlistVersion != ClaimPredicateAllowlistVersion ||
		first.Parameters.ResourceKindAllowlistVersion != GraphResourceKindAllowlistVersion {
		t.Fatalf("allowlist versions missing from plan: %+v", first.Parameters)
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("equivalent queries compiled differently:\n%s\n%s", firstJSON, secondJSON)
	}
	if bytes.Contains(firstJSON, []byte(ClaimPredicateLocatedIn)) || bytes.Contains(firstJSON, []byte(ClaimPredicatePartOf)) {
		t.Fatalf("predicate source labels escaped into descriptor: %s", firstJSON)
	}
	if !sort.SliceIsSorted(first.Parameters.PredicateKeys, func(i, j int) bool {
		return first.Parameters.PredicateKeys[i] < first.Parameters.PredicateKeys[j]
	}) {
		t.Fatalf("predicate keys were not normalized: %v", first.Parameters.PredicateKeys)
	}
	assertDescriptorJSONSchemaCanary(t, firstJSON)
}

func TestGraphQueryRejectsUnknownAndUnboundedInputs(t *testing.T) {
	tests := []struct {
		name   string
		canary string
		mutate func(*GraphQuery)
	}{
		{name: "operation", canary: "raw_cypher", mutate: func(query *GraphQuery) { query.Operation = "raw_cypher" }},
		{name: "identity version", mutate: func(query *GraphQuery) { query.IdentityVersion++ }},
		{name: "predicate", canary: "MATCH (n:ProtectedLabel) RETURN n", mutate: func(query *GraphQuery) {
			query.PredicateSources = []ClaimPredicateSourceKey{"MATCH (n:ProtectedLabel) RETURN n"}
		}},
		{name: "kind", canary: "ProtectedLabel", mutate: func(query *GraphQuery) {
			query.ResourceKinds = []GraphResourceKind{"ProtectedLabel"}
		}},
		{name: "direction", canary: "sideways", mutate: func(query *GraphQuery) { query.Direction = "sideways" }},
		{name: "field", canary: "private_property", mutate: func(query *GraphQuery) {
			query.Fields = []GraphField{"private_property"}
		}},
		{name: "filter", canary: "property_equals", mutate: func(query *GraphQuery) {
			query.Filters = []GraphFilter{{Kind: "property_equals", ResourceIDs: []ResourceID{graphQueryResourceID(3)}}}
		}},
		{name: "sort key", canary: "private_sort", mutate: func(query *GraphQuery) {
			query.Order = []GraphOrder{{Key: "private_sort", Direction: GraphSortAscending}}
		}},
		{name: "sort direction", canary: "random", mutate: func(query *GraphQuery) {
			query.Order = []GraphOrder{{Key: GraphSortClaimID, Direction: "random"}}
		}},
		{name: "unbounded depth", mutate: func(query *GraphQuery) { query.Limits.MaxDepth = MaxGraphTraversalDepth + 1 }},
		{name: "missing frontier bound", mutate: func(query *GraphQuery) { query.Limits.MaxFrontierWidth = 0 }},
		{name: "unbounded timeout", mutate: func(query *GraphQuery) {
			query.Limits.MaxWallClockMillis = MaxGraphWallClockMilliseconds + 1
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := validGraphQueryFixture()
			test.mutate(&query)
			descriptor, err := CompileGraphQuery(query)
			if err == nil {
				t.Fatalf("invalid query produced descriptor: %+v", descriptor)
			}
			assertGenericInvalidPlanError(t, err, test.canary)
		})
	}
}

func TestGraphQueryStrictJSONRejectsRawQueriesLabelsAndProperties(t *testing.T) {
	valid, err := json.Marshal(validGraphQueryFixture())
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(valid, &base); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "raw cypher", mutate: func(value map[string]any) { value["cypher"] = "MATCH (n) RETURN n" }},
		{name: "raw gql", mutate: func(value map[string]any) { value["gql"] = "MATCH (n) RETURN n" }},
		{name: "generic raw query", mutate: func(value map[string]any) { value["query"] = "MATCH (n) RETURN n" }},
		{name: "backend label", mutate: func(value map[string]any) { value["label"] = "ProtectedLabel" }},
		{name: "backend property", mutate: func(value map[string]any) {
			value["filters"] = []any{map[string]any{
				"kind":         string(GraphFilterObjectIDIn),
				"resource_ids": []any{string(graphQueryResourceID(3))},
				"property":     "private_property",
			}}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneJSONMap(t, base)
			test.mutate(candidate)
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var query GraphQuery
			err = json.Unmarshal(encoded, &query)
			if err == nil {
				t.Fatalf("unsafe JSON was accepted: %s", encoded)
			}
			assertGenericInvalidPlanError(t, err, "ProtectedLabel", "private_property", "MATCH")
		})
	}

	trailing := append(append([]byte(nil), valid...), []byte(` {"query":"MATCH"}`)...)
	var query GraphQuery
	if err := json.Unmarshal(trailing, &query); err == nil {
		t.Fatal("trailing raw query JSON was accepted")
	}
}

func TestTraversalPlanAndDescriptorRejectForgedFragments(t *testing.T) {
	descriptor, err := CompileGraphQuery(validGraphQueryFixture())
	if err != nil {
		t.Fatal(err)
	}

	forgedPredicate := descriptor
	forgedPredicate.Parameters.PredicateKeys = []ClaimPredicateKey{"pred_ffffffffffffffffffffffffffffffff"}
	assertGenericInvalidPlanError(t, forgedPredicate.Validate(), "ffffffff")

	forgedTemplate := descriptor
	forgedTemplate.Template = "raw_cypher"
	assertGenericInvalidPlanError(t, forgedTemplate.Validate(), "raw_cypher")

	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["query"] = "MATCH (n:ProtectedLabel) RETURN n.private_property"
	unsafeJSON, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var forged GraphOperationDescriptor
	if err := json.Unmarshal(unsafeJSON, &forged); err == nil {
		t.Fatal("descriptor accepted executable query text")
	} else {
		assertGenericInvalidPlanError(t, err, "ProtectedLabel", "private_property", "MATCH")
	}
}

func TestGraphPlanErrorsExposeOnlyStableCategoryAndSafeVersions(t *testing.T) {
	query := validGraphQueryFixture()
	query.ProjectionVersion = "MATCH (n:ProtectedLabel)"
	_, err := CompileGraphQuery(query)
	assertGenericInvalidPlanError(t, err, "ProtectedLabel", "MATCH")

	var planError *GraphPlanError
	if !errors.As(err, &planError) {
		t.Fatalf("error type = %T", err)
	}
	if planError.Category != GraphPlanErrorInvalidPlan {
		t.Fatalf("category = %q", planError.Category)
	}
	if planError.Versions.ProjectionVersion != "" || planError.Versions.IdentityVersion != query.IdentityVersion {
		t.Fatalf("unsafe or missing version metadata: %+v", planError.Versions)
	}
	if planError.Versions.ContractVersion != GraphQueryContractVersion ||
		planError.Versions.PredicateAllowlistVersion != ClaimPredicateAllowlistVersion ||
		planError.Versions.ResourceKindAllowlistVersion != GraphResourceKindAllowlistVersion {
		t.Fatalf("stable version metadata missing: %+v", planError.Versions)
	}

	notFound := NewGraphPlanNotFoundError("prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", GraphBindingContractVersion)
	if !errors.Is(notFound, ErrGraphPlanNotFound) || notFound.Category != GraphPlanErrorNotFound {
		t.Fatalf("not-found category is not stable: %+v", notFound)
	}
	if notFound.Versions.ProjectionVersion != "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ||
		notFound.Versions.IdentityVersion != GraphBindingContractVersion {
		t.Fatalf("not-found version metadata = %+v", notFound.Versions)
	}
}

func validGraphQueryFixture() GraphQuery {
	return GraphQuery{
		Version:           GraphQueryContractVersion,
		Operation:         GraphOperationTraverseClaims,
		ProjectionVersion: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IdentityVersion:   GraphBindingContractVersion,
		StartResourceIDs:  []ResourceID{graphQueryResourceID(1)},
		PredicateSources:  []ClaimPredicateSourceKey{ClaimPredicateLocatedIn},
		ResourceKinds:     []GraphResourceKind{GraphResourceEntity},
		Direction:         TraversalOutbound,
		Limits: TraversalLimits{
			MaxDepth: 2, MaxFrontierWidth: 32, MaxCandidatesPerHop: 64,
			MaxTotalResources: 128, MaxBatchChecks: 16, MaxWallClockMillis: 5_000,
		},
	}
}

func graphQueryResourceID(value int) ResourceID {
	return ResourceID("res_" + strings.Repeat("0", 31) + string(rune('0'+value)))
}

func assertGenericInvalidPlanError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected invalid plan error")
	}
	if !errors.Is(err, ErrInvalidGraphPlan) {
		t.Fatalf("error category = %T %v", err, err)
	}
	if err.Error() != ErrInvalidGraphPlan.Error() {
		t.Fatalf("public error is not generic: %q", err)
	}
	for _, canary := range forbidden {
		if canary != "" && strings.Contains(err.Error(), canary) {
			t.Fatalf("public error exposed protected canary %q: %v", canary, err)
		}
	}
}

func assertDescriptorJSONSchemaCanary(t *testing.T, encoded []byte) {
	t.Helper()
	allowedKeys := map[string]struct{}{
		"version": {}, "template": {}, "parameters": {},
		"predicate_allowlist_version": {}, "resource_kind_allowlist_version": {},
		"projection_version": {}, "identity_version": {}, "start_resource_ids": {},
		"predicate_keys": {}, "resource_kinds": {}, "direction": {}, "fields": {},
		"filters": {}, "order": {}, "limits": {}, "kind": {}, "resource_ids": {},
		"derivations": {}, "key": {}, "priority": {}, "max_depth": {}, "max_frontier_width": {},
		"max_candidates_per_hop": {}, "max_total_resources": {}, "max_batch_checks": {},
		"max_wall_clock_millis": {},
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, nested := range typed {
				if _, ok := allowedKeys[key]; !ok {
					t.Fatalf("descriptor emitted undeclared key %q in %s", key, encoded)
				}
				walk(nested)
			}
		case []any:
			for _, nested := range typed {
				walk(nested)
			}
		}
	}
	walk(value)
	for _, forbidden := range []string{"query", "cypher", "gql", "label", "property"} {
		if _, ok := allowedKeys[forbidden]; ok {
			t.Fatalf("unsafe descriptor key %q was allowlisted by the test", forbidden)
		}
	}
}

func cloneJSONMap(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
