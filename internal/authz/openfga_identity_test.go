package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zzqDeco/knote/internal/identity"
)

const (
	testIdentityWatermark = "identity_00000000000000000001_00000000000000000000000000000000"
	testProjectionDigest  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

func TestOpenFGAIdentityInspectionUsesHigherConsistencyAndCompletePagination(t *testing.T) {
	var calls atomic.Int32
	publishedFence := identity.MembershipPublicationFence{
		State: identity.MembershipPublicationFencePublished, IdentityWatermark: testIdentityWatermark,
		ProjectionDigest: testProjectionDigest,
	}
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stores/"+openFGATestStoreID+"/read" {
			t.Errorf("path = %q", request.URL.Path)
		}
		var body struct {
			TupleKey struct {
				Relation string `json:"relation"`
				Object   string `json:"object"`
			} `json:"tuple_key"`
			PageSize          int32  `json:"page_size"`
			ContinuationToken string `json:"continuation_token"`
			Consistency       string `json:"consistency"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode read request: %v", err)
		}
		if body.PageSize != openFGAIdentityPageSize || body.Consistency != "HIGHER_CONSISTENCY" {
			t.Errorf("read options = page_size:%d consistency:%q", body.PageSize, body.Consistency)
		}
		calls.Add(1)
		switch {
		case body.TupleKey.Object == identityControlObject && body.ContinuationToken == "":
			writeJSON(t, writer, tupleReadResponse(
				[]Tuple{{User: identityClaimUser, Relation: identityClaimRelation, Object: identityControlObject}}, "control-next",
			))
		case body.TupleKey.Object == identityControlObject && body.ContinuationToken == "control-next":
			writeJSON(t, writer, tupleReadResponse([]Tuple{
				{User: "identity_tenant:tenant-http", Relation: identityTenantRelation, Object: identityControlObject},
				identityFenceTuple(publishedFence),
			}, ""))
		case body.TupleKey.Relation == RelationMember && body.ContinuationToken == "":
			writeJSON(t, writer, tupleReadResponse([]Tuple{
				{User: "group:policy#member", Relation: RelationMember, Object: "organization:acme"},
				{User: "user:bob", Relation: RelationMember, Object: "group:engineering"},
			}, "member-next"))
		case body.TupleKey.Relation == RelationMember && body.ContinuationToken == "member-next":
			writeJSON(t, writer, tupleReadResponse(
				[]Tuple{{User: "user:alice", Relation: RelationMember, Object: "group:engineering"}}, "",
			))
		default:
			t.Errorf("unexpected read request: %+v", body)
			writeJSON(t, writer, `{"tuples":[],"continuation_token":""}`)
		}
	}))
	target := identity.MembershipPublicationTarget{
		TenantID: "tenant-http", StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID,
	}
	state, err := authorizer.InspectMembershipState(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	want := []identity.Membership{
		{TenantID: target.TenantID, PrincipalID: "alice", GroupID: "engineering"},
		{TenantID: target.TenantID, PrincipalID: "bob", GroupID: "engineering"},
	}
	if !state.Claimed || len(state.TenantIDs) != 1 || state.TenantIDs[0] != target.TenantID ||
		state.PublicationFence == nil || *state.PublicationFence != publishedFence ||
		!identityMembershipSlicesEqual(state.Members, want) || calls.Load() != 4 {
		t.Fatalf("remote state = %+v calls=%d", state, calls.Load())
	}
}

func TestOpenFGAIdentityClaimIsAtomicAndMembershipWritesRemainBounded(t *testing.T) {
	var claimCalls atomic.Int32
	var publicationCalls atomic.Int32
	activeFence := identity.MembershipPublicationFence{
		State: identity.MembershipPublicationFenceActive, IdentityWatermark: testIdentityWatermark,
		ProjectionDigest: testProjectionDigest, Attempt: 1,
	}
	expectedFence := activeFence
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stores/"+openFGATestStoreID+"/write" {
			t.Errorf("path = %q", request.URL.Path)
		}
		var body struct {
			AuthorizationModelID string `json:"authorization_model_id"`
			Writes               struct {
				OnDuplicate string  `json:"on_duplicate"`
				TupleKeys   []Tuple `json:"tuple_keys"`
			} `json:"writes"`
			Deletes struct {
				OnMissing string  `json:"on_missing"`
				TupleKeys []Tuple `json:"tuple_keys"`
			} `json:"deletes"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode write request: %v", err)
		}
		if body.AuthorizationModelID != openFGATestModelID {
			t.Errorf("authorization_model_id = %q", body.AuthorizationModelID)
		}
		if len(body.Writes.TupleKeys) == 3 && len(body.Deletes.TupleKeys) == 0 &&
			body.Writes.TupleKeys[0].User == identityClaimUser {
			claimCalls.Add(1)
			if body.Writes.OnDuplicate != "error" || body.Writes.TupleKeys[0] != (Tuple{
				User: identityClaimUser, Relation: identityClaimRelation, Object: identityControlObject,
			}) || body.Writes.TupleKeys[1] != (Tuple{
				User: "identity_tenant:tenant-http", Relation: identityTenantRelation, Object: identityControlObject,
			}) || identityFenceTuple(activeFence) != body.Writes.TupleKeys[2] {
				t.Errorf("claim transaction = %+v", body.Writes)
			}
		} else {
			publicationCalls.Add(1)
			operations := len(body.Writes.TupleKeys) + len(body.Deletes.TupleKeys)
			if operations == 0 || operations > MaxTupleOperationsPerWrite ||
				body.Writes.OnDuplicate != "error" || body.Deletes.OnMissing != "error" ||
				countIdentityFenceTuples(body.Writes.TupleKeys) != 1 ||
				countIdentityFenceTuples(body.Deletes.TupleKeys) != 1 {
				t.Errorf("publication transaction = writes:%d deletes:%d conflicts:%q/%q",
					len(body.Writes.TupleKeys), len(body.Deletes.TupleKeys), body.Writes.OnDuplicate, body.Deletes.OnMissing)
			}
			deleted, deleteErr := publicationFenceFromTuples(body.Deletes.TupleKeys)
			next, nextErr := publicationFenceFromTuples(body.Writes.TupleKeys)
			if deleteErr != nil || nextErr != nil || deleted != expectedFence {
				t.Errorf("publication fence transition = %v -> %v, want %v: %v / %v", deleted, next, expectedFence, deleteErr, nextErr)
			} else {
				if next.State == identity.MembershipPublicationFenceActive && next.Attempt != expectedFence.Attempt+1 {
					t.Errorf("active publication attempt = %d, want %d", next.Attempt, expectedFence.Attempt+1)
				}
				if next.IdentityWatermark != testIdentityWatermark || next.ProjectionDigest != testProjectionDigest {
					t.Errorf("publication fence payload = %+v", next)
				}
				expectedFence = next
			}
		}
		writeJSON(t, writer, `{}`)
	}))
	target := identity.MembershipPublicationTarget{
		TenantID: "tenant-http", StoreID: openFGATestStoreID, AuthorizationModelID: openFGATestModelID,
	}
	if err := authorizer.ClaimMembershipStore(context.Background(), target, activeFence); err != nil {
		t.Fatal(err)
	}
	members := make([]identity.Membership, 205)
	for index := range members {
		members[index] = identity.Membership{
			TenantID: target.TenantID, PrincipalID: fmt.Sprintf("principal-%03d", index), GroupID: "engineering",
		}
	}
	if err := authorizer.ApplyMembershipChanges(context.Background(), identity.MembershipWriteRequest{
		Target: target, IdentityWatermark: testIdentityWatermark, ProjectionDigest: testProjectionDigest,
		ExpectedFence: activeFence, Writes: members,
	}); err != nil {
		t.Fatal(err)
	}
	if claimCalls.Load() != 1 || publicationCalls.Load() != 4 ||
		expectedFence.State != identity.MembershipPublicationFencePublished {
		t.Fatalf("claim calls=%d publication calls=%d final fence=%+v", claimCalls.Load(), publicationCalls.Load(), expectedFence)
	}
}

func TestIdentityPublicationFenceTupleRoundTrips(t *testing.T) {
	for _, fence := range []identity.MembershipPublicationFence{
		{
			State: identity.MembershipPublicationFenceActive, IdentityWatermark: testIdentityWatermark,
			ProjectionDigest: testProjectionDigest, Attempt: 42,
		},
		{
			State: identity.MembershipPublicationFencePublished, IdentityWatermark: testIdentityWatermark,
			ProjectionDigest: testProjectionDigest,
		},
	} {
		parsed, err := parseIdentityPublicationFence(identityFenceTuple(fence).User)
		if err != nil || parsed != fence {
			t.Fatalf("publication fence round trip = %+v, %v; want %+v", parsed, err, fence)
		}
	}
	for _, malformed := range []string{
		identityFenceUserPrefix + "a_00000000000000000000_00000000000000000001_00000000000000000000000000000000_0000000000000000000000000000000000000000000000000000000000000000",
		identityFenceUserPrefix + "p_00000000000000000001_00000000000000000001_00000000000000000000000000000000_0000000000000000000000000000000000000000000000000000000000000000",
		identityFenceUserPrefix + "unknown",
	} {
		if _, err := parseIdentityPublicationFence(malformed); err == nil {
			t.Fatalf("malformed publication fence accepted: %q", malformed)
		}
	}
}

func TestOpenFGAApplyMembershipChangesEmptyDiffPublishesActiveFence(t *testing.T) {
	var calls atomic.Int32
	authorizer := newTestOpenFGA(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	err := authorizer.ApplyMembershipChanges(context.Background(), identity.MembershipWriteRequest{
		Target: identity.MembershipPublicationTarget{
			TenantID: "tenant-http", StoreID: openFGATestStoreID,
			AuthorizationModelID: openFGATestModelID,
		},
		IdentityWatermark: testIdentityWatermark, ProjectionDigest: testProjectionDigest,
		ExpectedFence: identity.MembershipPublicationFence{
			State: identity.MembershipPublicationFenceActive, IdentityWatermark: testIdentityWatermark,
			ProjectionDigest: testProjectionDigest, Attempt: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("empty membership diff issued %d HTTP calls, want one fence commit", calls.Load())
	}
}

func countIdentityFenceTuples(tuples []Tuple) int {
	count := 0
	for _, tuple := range tuples {
		if tuple.Object == identityControlObject && tuple.Relation == identityClaimRelation &&
			strings.HasPrefix(tuple.User, identityFenceUserPrefix) {
			count++
		}
	}
	return count
}

func publicationFenceFromTuples(tuples []Tuple) (identity.MembershipPublicationFence, error) {
	for _, tuple := range tuples {
		if tuple.Object == identityControlObject && tuple.Relation == identityClaimRelation &&
			strings.HasPrefix(tuple.User, identityFenceUserPrefix) {
			return parseIdentityPublicationFence(tuple.User)
		}
	}
	return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication fence tuple is missing")
}

func tupleReadResponse(tuples []Tuple, continuation string) string {
	sort.Slice(tuples, func(i, j int) bool { return tupleLess(tuples[i], tuples[j]) })
	type responseTuple struct {
		Key       Tuple  `json:"key"`
		Timestamp string `json:"timestamp"`
	}
	response := struct {
		Tuples            []responseTuple `json:"tuples"`
		ContinuationToken string          `json:"continuation_token"`
	}{ContinuationToken: continuation}
	for _, tuple := range tuples {
		response.Tuples = append(response.Tuples, responseTuple{
			Key: tuple, Timestamp: "2026-07-17T00:00:00Z",
		})
	}
	data, _ := json.Marshal(response)
	return string(data)
}

func identityMembershipSlicesEqual(left, right []identity.Membership) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
