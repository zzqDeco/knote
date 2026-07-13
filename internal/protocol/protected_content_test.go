package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProtectedContentBindingIsStableSortedAndMetadataOnly(t *testing.T) {
	auth := testAuthorizationContext()
	firstID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/a.md")
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/b.md")
	if err != nil {
		t.Fatal(err)
	}
	firstPackage := testEvidencePackage(t, auth, testResourceHandle(t, firstID))
	secondPackage := testEvidencePackage(t, auth, testResourceHandle(t, secondID))

	forward, err := NewProtectedContentBinding(auth, firstPackage, secondPackage)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NewProtectedContentBinding(auth, secondPackage, firstPackage)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("binding depends on evidence order:\nforward=%#v\nreverse=%#v", forward, reverse)
	}
	if len(forward.Resources) != 2 || protectedResourceSortKey(forward.Resources[0]) >= protectedResourceSortKey(forward.Resources[1]) {
		t.Fatalf("protected resources are not sorted: %#v", forward.Resources)
	}
	if forward.Version != ProtectedContentBindingVersion || len(forward.EvidenceRoots) != 2 ||
		protectedEvidenceRootSortKey(forward.EvidenceRoots[0]) >= protectedEvidenceRootSortKey(forward.EvidenceRoots[1]) {
		t.Fatalf("protected evidence roots are not versioned and sorted: %#v", forward)
	}
	if err := forward.ValidateFor(auth); err != nil {
		t.Fatalf("validate protected binding: %v", err)
	}

	encoded, err := json.Marshal(forward)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"authorized content", "sources/a.md", "answer canary", "question canary"} {
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("protected metadata leaked %q: %s", canary, encoded)
		}
	}
}

func TestProtectedContentBindingPersistsOnlyTopLevelEvidenceRoots(t *testing.T) {
	auth := testAuthorizationContext()
	rootID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/root.md")
	if err != nil {
		t.Fatal(err)
	}
	supportID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/support.md")
	if err != nil {
		t.Fatal(err)
	}
	root := testResourceHandle(t, rootID)
	support := testResourceHandle(t, supportID)
	evidence := testEvidencePackage(t, auth, root)
	evidence.Items[0].Supports = []ProvenanceSupport{{
		SupportID: "support-source", Resource: support,
		Evidence: []ResourceHandle{support}, Complete: true,
	}}
	supportDecision := testDecision(t, supportID)
	supportDecision.CorrelationID = "decision-support"
	evidence.Decisions = append(evidence.Decisions, supportDecision)
	if err := evidence.ValidateFor(auth); err != nil {
		t.Fatal(err)
	}

	binding, err := NewProtectedContentBinding(auth, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(binding.Resources) != 2 {
		t.Fatalf("protected decision resources = %#v", binding.Resources)
	}
	if !reflect.DeepEqual(binding.EvidenceRoots, []ResourceHandle{root}) {
		t.Fatalf("protected evidence roots = %#v", binding.EvidenceRoots)
	}
	if err := binding.ValidateFor(auth); err != nil {
		t.Fatal(err)
	}
	tamperedRoots := binding
	tamperedRoots.EvidenceRoots = []ResourceHandle{support}
	if err := tamperedRoots.Validate(); err == nil {
		t.Fatal("evidence-root tampering did not invalidate block_id")
	}
}

func TestProtectedContentBindingSurvivesEventRoundTrip(t *testing.T) {
	auth := testAuthorizationContext()
	resourceID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewProtectedContentBinding(auth, testEvidencePackage(t, auth, testResourceHandle(t, resourceID)))
	if err != nil {
		t.Fatal(err)
	}
	event := NewEvent(EventAssistantDone, auth.SessionID, "authorized answer", nil)
	event.ProtectedContent = &binding
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ProtectedContent == nil || !reflect.DeepEqual(*decoded.ProtectedContent, binding) {
		t.Fatalf("protected event round trip = %#v", decoded.ProtectedContent)
	}
}

func TestProtectedContentBindingRejectsTamperingAndConflicts(t *testing.T) {
	auth := testAuthorizationContext()
	resourceID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	resource := testResourceHandle(t, resourceID)
	binding, err := NewProtectedContentBinding(auth, testEvidencePackage(t, auth, resource))
	if err != nil {
		t.Fatal(err)
	}

	tampered := binding
	tampered.BlockID = "block_00000000000000000000000000000000"
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered block id succeeded")
	}

	current := auth
	current.RequestID = "request-replay"
	if err := binding.ValidateFor(current); err != nil {
		t.Fatalf("a fresh replay request should validate: %v", err)
	}
	crossTenant := current
	crossTenant.TenantID = "other-tenant"
	if err := binding.ValidateFor(crossTenant); err == nil {
		t.Fatal("cross-tenant replay binding succeeded")
	}

	changed := resource
	changed.Versions.Content = "content-v2"
	_, err = NewProtectedContentBindingFromResources(auth.SessionID, auth.RequestID, []ProtectedResourceBinding{
		{Resource: resource, AuthorizationResource: resource},
		{Resource: changed, AuthorizationResource: changed},
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting exact handles") {
		t.Fatalf("conflicting exact handles error = %v", err)
	}
}

func TestProtectedContentBindingRejectsNonCanonicalPersistedMetadata(t *testing.T) {
	auth := testAuthorizationContext()
	resourceID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/intro.md")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewProtectedContentBinding(auth, testEvidencePackage(t, auth, testResourceHandle(t, resourceID)))
	if err != nil {
		t.Fatal(err)
	}

	duplicate := binding
	duplicate.Resources = append(duplicate.Resources, duplicate.Resources[0])
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate protected resource succeeded")
	}
	duplicateRoot := binding
	duplicateRoot.EvidenceRoots = append(duplicateRoot.EvidenceRoots, duplicateRoot.EvidenceRoots[0])
	duplicateRoot.BlockID = protectedContentBlockID(duplicateRoot)
	if err := duplicateRoot.Validate(); err == nil {
		t.Fatal("duplicate protected evidence root succeeded")
	}
	missingRoot := binding
	missingRoot.EvidenceRoots = nil
	missingRoot.BlockID = protectedContentBlockID(missingRoot)
	if err := missingRoot.Validate(); err == nil {
		t.Fatal("missing protected evidence root succeeded")
	}

	secondID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/second.md")
	if err != nil {
		t.Fatal(err)
	}
	second := ProtectedResourceBinding{
		Resource:              testResourceHandle(t, secondID),
		AuthorizationResource: testResourceHandle(t, secondID),
	}
	sorted, err := NewProtectedContentBindingFromResources(auth.SessionID, auth.RequestID, []ProtectedResourceBinding{
		binding.Resources[0], second,
	})
	if err != nil {
		t.Fatal(err)
	}
	unsorted := sorted
	unsorted.Resources = append([]ProtectedResourceBinding(nil), sorted.Resources...)
	unsorted.Resources[0], unsorted.Resources[1] = unsorted.Resources[1], unsorted.Resources[0]
	if err := unsorted.Validate(); err == nil {
		t.Fatal("unsorted protected resources succeeded")
	}
	unsortedRoots := sorted
	unsortedRoots.EvidenceRoots = append([]ResourceHandle(nil), sorted.EvidenceRoots...)
	unsortedRoots.EvidenceRoots[0], unsortedRoots.EvidenceRoots[1] = unsortedRoots.EvidenceRoots[1], unsortedRoots.EvidenceRoots[0]
	unsortedRoots.BlockID = protectedContentBlockID(unsortedRoots)
	if err := unsortedRoots.Validate(); err == nil {
		t.Fatal("unsorted protected evidence roots succeeded")
	}
	unboundRoot := binding
	unboundRoot.EvidenceRoots = []ResourceHandle{second.Resource}
	unboundRoot.BlockID = protectedContentBlockID(unboundRoot)
	if err := unboundRoot.Validate(); err == nil {
		t.Fatal("unbound protected evidence root succeeded")
	}
	staleRoot := binding
	staleRoot.EvidenceRoots = append([]ResourceHandle(nil), binding.EvidenceRoots...)
	staleRoot.EvidenceRoots[0].Versions.Content = "content-v2"
	staleRoot.BlockID = protectedContentBlockID(staleRoot)
	if err := staleRoot.Validate(); err == nil {
		t.Fatal("stale protected evidence root succeeded")
	}

	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := strings.Replace(string(encoded), `"version":`, `"title":"TITLE_CANARY","version":`, 1)
	var decoded ProtectedContentBinding
	if err := json.Unmarshal([]byte(withUnknown), &decoded); err == nil {
		t.Fatal("unknown persisted field succeeded")
	}
	if err := json.Unmarshal(append(encoded, []byte(` {}`)...), &decoded); err == nil {
		t.Fatal("trailing persisted JSON succeeded")
	}
}

func TestProtectedContentBindingContainsNoContentBearingFields(t *testing.T) {
	auth := testAuthorizationContext()
	resourceID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "BODY_CANARY")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewProtectedContentBinding(auth, testEvidencePackage(t, auth, testResourceHandle(t, resourceID)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"title":`, `"body":`, `"question":`, `"answer":`, "BODY_CANARY",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("protected binding contains content-bearing value %q: %s", forbidden, encoded)
		}
	}
}

func TestProtectedContentBindingPersistsExactChunkAuthorizationBoundary(t *testing.T) {
	auth := testAuthorizationContext()
	parentID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/parent.md")
	if err != nil {
		t.Fatal(err)
	}
	chunkID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceChunk, "sources/parent.md#chunk-1")
	if err != nil {
		t.Fatal(err)
	}
	parent := testResourceHandle(t, parentID)
	chunk := testResourceHandle(t, chunkID)
	chunk.Type = ResourceChunk
	chunk.AuthorizationID = parent.AuthorizationID
	chunk.AuthorizationResourceID = parent.ResourceID
	if err := chunk.Validate(); err != nil {
		t.Fatal(err)
	}

	binding, err := NewProtectedContentBindingFromResources(auth.SessionID, auth.RequestID, []ProtectedResourceBinding{{
		Resource: chunk, AuthorizationResource: parent,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Resources[0].Resource != chunk || binding.Resources[0].AuthorizationResource != parent {
		t.Fatalf("chunk binding lost its exact authorization boundary: %#v", binding.Resources[0])
	}
	if err := binding.ValidateFor(auth); err != nil {
		t.Fatal(err)
	}

	otherID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, ResourceDocument, "sources/other.md")
	if err != nil {
		t.Fatal(err)
	}
	tampered := binding
	tampered.Resources = append([]ProtectedResourceBinding(nil), binding.Resources...)
	tampered.Resources[0].AuthorizationResource = testResourceHandle(t, otherID)
	if err := tampered.Validate(); err == nil {
		t.Fatal("chunk binding with a different authorization boundary succeeded")
	}
}
