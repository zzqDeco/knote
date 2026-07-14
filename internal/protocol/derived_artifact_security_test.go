package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDerivedArtifactKindsDefaultToAllRequired(t *testing.T) {
	for _, kind := range []string{"summary", "outline", "table", "future-kind"} {
		t.Run(kind, func(t *testing.T) {
			artifact, supports, auth := derivedArtifactSecurityFixture(t, "projection-v1")
			record, err := NewDerivedArtifactSecurityRecord(kind, "", artifact, supports, "repo:knote", auth)
			if err != nil {
				t.Fatal(err)
			}
			if record.DerivationMode != DerivationAllRequired {
				t.Fatalf("kind %q defaulted to %q", kind, record.DerivationMode)
			}
		})
	}
}

func TestDerivedArtifactSecurityRecordIsCanonicalAndJSONStable(t *testing.T) {
	artifact, supports, auth := derivedArtifactSecurityFixture(t, "projection-v1")
	supports[0], supports[1] = supports[1], supports[0]
	supports[0].Resources[0], supports[0].Resources[1] = supports[0].Resources[1], supports[0].Resources[0]
	record, err := NewDerivedArtifactSecurityRecord(
		"summary", DerivationAnySupport, artifact, supports, "repo:knote", auth,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{record.Supports[0].SupportID, record.Supports[1].SupportID}; !reflect.DeepEqual(got, []string{"support-a", "support-b"}) {
		t.Fatalf("support groups are not sorted: %v", got)
	}
	if record.Supports[0].Resources[0].ResourceID > record.Supports[0].Resources[1].ResourceID {
		t.Fatal("support resources are not sorted")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DerivedArtifactSecurityRecord
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(reencoded) {
		t.Fatalf("security record JSON is not stable:\n%s\n%s", encoded, reencoded)
	}
	expected, err := NewVisibilityFingerprint(auth, record.ProjectionWatermark)
	if err != nil {
		t.Fatal(err)
	}
	if record.VisibilityFingerprint != expected {
		t.Fatalf("visibility fingerprint = %q, want %q", record.VisibilityFingerprint, expected)
	}
}

func TestDerivedArtifactSecurityRecordRejectsDuplicatesIncompleteGroupsAndDrift(t *testing.T) {
	artifact, supports, auth := derivedArtifactSecurityFixture(t, "projection-v1")
	valid, err := NewDerivedArtifactSecurityRecord(
		"table", DerivationAnySupport, artifact, supports, "repo:knote", auth,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*DerivedArtifactSecurityRecord)
	}{
		{name: "duplicate support", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.Supports[1].SupportID = record.Supports[0].SupportID
		}},
		{name: "duplicate resource", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.Supports[0].Resources[1] = record.Supports[0].Resources[0]
		}},
		{name: "incomplete group", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.Supports[0].Complete = false
		}},
		{name: "support projection drift", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.Supports[0].Resources[0].Versions.Projection = "projection-v2"
		}},
		{name: "artifact projection drift", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.Artifact.Versions.Projection = "projection-v2"
		}},
		{name: "model watermark drift", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.AuthorizationModelID = "model-v2"
		}},
		{name: "identity watermark drift", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.IdentityWatermark = "identity-v2"
		}},
		{name: "acl watermark drift", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.ACLWatermark = "acl-watermark-v2"
		}},
		{name: "projection watermark drift", mutate: func(record *DerivedArtifactSecurityRecord) {
			record.ProjectionWatermark = "projection-v2"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Supports = append([]DerivedArtifactSupportGroup(nil), valid.Supports...)
			for i := range candidate.Supports {
				candidate.Supports[i].Resources = append(
					[]DerivedArtifactResourceIdentity(nil), valid.Supports[i].Resources...,
				)
			}
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid security record was accepted")
			}
		})
	}
}

func TestDerivedArtifactAnySupportRequiresCompleteIndependentGroups(t *testing.T) {
	artifact, supports, auth := derivedArtifactSecurityFixture(t, "projection-v1")
	if _, err := NewDerivedArtifactSecurityRecord(
		"outline", DerivationAnySupport, artifact, supports, "repo:knote", auth,
	); err != nil {
		t.Fatalf("complete any_support groups were rejected: %v", err)
	}
	supports[1].Complete = false
	if _, err := NewDerivedArtifactSecurityRecord(
		"outline", DerivationAnySupport, artifact, supports, "repo:knote", auth,
	); err == nil {
		t.Fatal("any_support accepted an incomplete alternative")
	}
}

func TestDerivedArtifactAllRequiredAllowsIncompleteGroups(t *testing.T) {
	artifact, supports, auth := derivedArtifactSecurityFixture(t, "projection-v1")
	supports[0].Complete = false
	record, err := NewDerivedArtifactSecurityRecord(
		"summary", DerivationAllRequired, artifact, supports, "repo:knote", auth,
	)
	if err != nil {
		t.Fatalf("all_required rejected a collectively required incomplete group: %v", err)
	}
	incomplete := 0
	for _, support := range record.Supports {
		if !support.Complete {
			incomplete++
		}
	}
	if incomplete != 1 {
		t.Fatalf("incomplete support count = %d, want 1", incomplete)
	}
}

func TestDerivedArtifactSecurityRecordInvalidatesAuthorizationWatermarkDrift(t *testing.T) {
	artifact, supports, auth := derivedArtifactSecurityFixture(t, "projection-v1")
	record, err := NewDerivedArtifactSecurityRecord(
		"summary", DerivationAllRequired, artifact, supports, "repo:knote", auth,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.ValidateFor(auth, "repo:knote", "projection-v1"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AuthorizationContext){
		func(candidate *AuthorizationContext) { candidate.AuthorizationModelID = "model-v2" },
		func(candidate *AuthorizationContext) { candidate.IdentityWatermark = "identity-v2" },
		func(candidate *AuthorizationContext) { candidate.ACLWatermark = "acl-watermark-v2" },
	} {
		candidate := auth
		mutate(&candidate)
		if err := record.ValidateFor(candidate, "repo:knote", "projection-v1"); err == nil {
			t.Fatal("authorization watermark drift did not invalidate the record")
		}
	}
	if err := record.ValidateFor(auth, "repo:other", "projection-v1"); err == nil {
		t.Fatal("security-domain drift did not invalidate the record")
	}
	if err := record.ValidateFor(auth, "repo:knote", "projection-v2"); err == nil {
		t.Fatal("projection watermark drift did not invalidate the record")
	}
}

func derivedArtifactSecurityFixture(
	t *testing.T,
	projection string,
) (DerivedArtifactResourceIdentity, []DerivedArtifactSupportGroup, AuthorizationContext) {
	t.Helper()
	auth := AuthorizationContext{
		Version: SecurityContractVersion, TenantID: "tenant-local", KnowledgeBaseID: "kb-default",
		PrincipalID: "user:alice", SessionID: "session-1", RequestID: "request-1",
		AuthorizationModelID: "model-v1", IdentityWatermark: "identity-v1",
		ACLWatermark: "acl-watermark-v1", AgentID: "agent-1", TaskID: "task-1",
		Consistency: ConsistencyHigherConsistency,
	}
	identity := func(resourceType ResourceType, sourceKey string) DerivedArtifactResourceIdentity {
		resourceID, err := NewStableResourceID(auth.TenantID, auth.KnowledgeBaseID, resourceType, sourceKey)
		if err != nil {
			t.Fatal(err)
		}
		return DerivedArtifactResourceIdentity{
			ResourceID: resourceID, Type: resourceType, AuthorizationID: string(resourceType) + ":" + sourceKey,
			AuthorizationResourceID: resourceID, ContentDigest: NewContentDigest(sourceKey),
			Versions: ResourceVersions{
				Source: "source-v1", Content: "content-" + sourceKey, ACL: "acl-v1",
				Index: "index-v1", Graph: "graph-v1", Projection: projection,
			},
		}
	}
	artifact := identity(ResourceDerivedArtifact, "artifact:summary")
	first := identity(ResourceDocument, "sources/a.md")
	second := identity(ResourceClaim, "claim:a")
	third := identity(ResourceDocument, "sources/b.md")
	return artifact, []DerivedArtifactSupportGroup{
		{SupportID: "support-b", Resources: []DerivedArtifactResourceIdentity{third}, Complete: true},
		{SupportID: "support-a", Resources: []DerivedArtifactResourceIdentity{second, first}, Complete: true},
	}, auth
}
