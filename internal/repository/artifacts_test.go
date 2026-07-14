package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
)

func TestCanonicalArtifactFilesRejectsGraphBindingsOutsideManifestVersions(t *testing.T) {
	resourceID := protocol.ResourceID("res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	handle := protocol.ResourceHandle{
		ResourceID:              resourceID,
		Type:                    protocol.ResourceDocument,
		TenantID:                "tenant",
		KnowledgeBaseID:         "knowledge-base",
		AuthorizationID:         "document:" + string(resourceID),
		AuthorizationResourceID: resourceID,
		ContentDigest:           protocol.NewContentDigest("body"),
		Versions: protocol.ResourceVersions{
			Source: "source-stale", Content: "content-stale", ACL: "acl-stale",
			Index:      "index_prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Graph:      "graph_prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Projection: "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		ServingState: protocol.ServingActive,
	}
	binding, err := protocol.NewGraphResourceBinding(handle)
	if err != nil {
		t.Fatal(err)
	}
	base := ArtifactSet{
		BundleManifest: protocol.ArtifactBundleManifest{
			ProjectionVersion:           handle.Versions.Projection,
			AuthorizationVersion:        handle.Versions.ACL,
			GraphBindingContractVersion: protocol.GraphBindingContractVersion,
			SourceSnapshot:              protocol.ArtifactSourceSnapshot{Version: handle.Versions.Source},
		},
		GraphBindings: []protocol.GraphResourceBinding{binding},
	}
	tests := []struct {
		name   string
		mutate func(*protocol.ArtifactBundleManifest)
	}{
		{name: "source", mutate: func(value *protocol.ArtifactBundleManifest) { value.SourceSnapshot.Version = "source-current" }},
		{name: "ACL", mutate: func(value *protocol.ArtifactBundleManifest) { value.AuthorizationVersion = "acl-current" }},
		{name: "projection", mutate: func(value *protocol.ArtifactBundleManifest) {
			value.ProjectionVersion = "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := base
			test.mutate(&set.BundleManifest)
			if _, err := CanonicalArtifactFiles(set); err == nil {
				t.Fatalf("artifact files accepted graph bindings with a mismatched manifest %s version", test.name)
			}
		})
	}
}

func TestCanonicalArtifactFilesRejectsEmptyGraphProjection(t *testing.T) {
	set := ArtifactSet{BundleManifest: protocol.ArtifactBundleManifest{
		GraphBindingContractVersion: protocol.GraphBindingContractVersion,
	}}
	if _, err := CanonicalArtifactFiles(set); !errors.Is(err, ErrArtifactProjectionMismatch) {
		t.Fatalf("empty graph projection error = %v, want generic projection mismatch", err)
	}
}

func TestCanonicalArtifactFilesEmitExactSourceBackedClaimBindingsWithoutRawGraphInput(t *testing.T) {
	set := sourceBackedArtifactSet(t)
	payloads, err := CanonicalArtifactFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	var claimBindingData []byte
	for _, payload := range payloads {
		if payload.Descriptor.Path == protocol.ClaimBindingsArtifactPath {
			claimBindingData = payload.Data
		}
	}
	if len(claimBindingData) == 0 {
		t.Fatal("source-backed Claim did not emit claim_bindings.jsonl")
	}
	for _, required := range []string{
		"subject_resource_id", "predicate_key", "object_resource_id",
		"source_document_resource_id", "source_version", "provenance_resource_ids", "derivation",
	} {
		if !bytes.Contains(claimBindingData, []byte(`"`+required+`"`)) {
			t.Fatalf("extended Claim binding omitted %q: %s", required, claimBindingData)
		}
	}
	for _, forbidden := range []string{"located_in", "PrivateLabel", "secret_property", "MATCH (n"} {
		if bytes.Contains(claimBindingData, []byte(forbidden)) {
			t.Fatalf("Claim artifact exposed raw graph input %q: %s", forbidden, claimBindingData)
		}
	}

	mismatched := set
	mismatched.ClaimBindings = append([]protocol.ClaimTripleBinding(nil), set.ClaimBindings...)
	mismatched.ClaimBindings[0].SubjectResourceID = mismatched.ClaimBindings[0].ObjectResourceID
	if _, err := CanonicalArtifactFiles(mismatched); !errors.Is(err, ErrArtifactProjectionMismatch) {
		t.Fatalf("stable identity mismatch error = %v, want generic projection mismatch", err)
	}

	const rawQuery = "MATCH (n:PrivateLabel) RETURN n.secret_property"
	unsafe := set
	unsafe.ClaimBindings = append([]protocol.ClaimTripleBinding(nil), set.ClaimBindings...)
	unsafe.ClaimBindings[0].PredicateKey = protocol.ClaimPredicateKey(rawQuery)
	_, err = CanonicalArtifactFiles(unsafe)
	if !errors.Is(err, ErrArtifactProjectionMismatch) || strings.Contains(err.Error(), rawQuery) ||
		strings.Contains(err.Error(), "PrivateLabel") || strings.Contains(err.Error(), "secret_property") {
		t.Fatalf("unsafe graph input error was not generic: %v", err)
	}
}

func TestValidateGraphArtifactPayloadsPreservesLegacyV2WithoutGraphContract(t *testing.T) {
	manifest := protocol.ArtifactBundleManifest{GraphBindingContractVersion: 0}
	files := map[string][]byte{
		"projection.json":                  []byte("legacy projection bytes"),
		protocol.GraphBindingsArtifactPath: []byte("legacy optional data"),
	}
	if err := ValidateGraphArtifactPayloads(manifest, files); err != nil {
		t.Fatalf("legacy v2 bundle without a graph contract was reinterpreted: %v", err)
	}
}

func TestValidateGraphArtifactPayloadsUpgradesV1ClaimBindings(t *testing.T) {
	set := sourceBackedArtifactSet(t)
	payloads, err := CanonicalArtifactFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(payloads))
	for _, payload := range payloads {
		files[payload.Descriptor.Path] = payload.Data
	}

	v1GraphIDs := make(map[protocol.GraphObjectID]protocol.GraphObjectID, len(set.GraphBindings))
	v1Resources := append([]protocol.GraphResourceBinding(nil), set.GraphBindings...)
	for index := range v1Resources {
		v1Resources[index].Version = protocol.GraphBindingContractVersionV1
		identity := fmt.Sprintf(
			"%d\x00%s\x00%s",
			protocol.GraphBindingContractVersionV1,
			v1Resources[index].Resource.Versions.Projection,
			v1Resources[index].Resource.ResourceID,
		)
		digest := sha256.Sum256([]byte(identity))
		v1Resources[index].GraphObjectID = protocol.GraphObjectID(fmt.Sprintf("kg_%x", digest[:16]))
		v1GraphIDs[set.GraphBindings[index].GraphObjectID] = v1Resources[index].GraphObjectID
	}
	protocol.SortGraphResourceBindings(v1Resources)
	v1Claims := append([]protocol.ClaimTripleBinding(nil), set.ClaimBindings...)
	for index := range v1Claims {
		v1Claims[index].Provenance = append([]protocol.GraphObjectID(nil), v1Claims[index].Provenance...)
		v1Claims[index].Version = protocol.GraphBindingContractVersionV1
		v1Claims[index].Claim = v1GraphIDs[v1Claims[index].Claim]
		v1Claims[index].Subject = v1GraphIDs[v1Claims[index].Subject]
		v1Claims[index].Object = v1GraphIDs[v1Claims[index].Object]
		v1Claims[index].SourceDocument = v1GraphIDs[v1Claims[index].SourceDocument]
		for provenanceIndex, graphObjectID := range v1Claims[index].Provenance {
			v1Claims[index].Provenance[provenanceIndex] = v1GraphIDs[graphObjectID]
		}
		sort.Slice(v1Claims[index].Provenance, func(left, right int) bool {
			return v1Claims[index].Provenance[left] < v1Claims[index].Provenance[right]
		})
		v1Claims[index].Supports = nil
		v1Claims[index].SubjectResourceID = ""
		v1Claims[index].ObjectResourceID = ""
		v1Claims[index].SourceDocumentResourceID = ""
		v1Claims[index].SourceVersion = ""
		v1Claims[index].ProvenanceResourceIDs = nil
	}
	protocol.SortClaimTripleBindings(v1Claims)
	v1Manifest := set.BundleManifest
	v1Manifest.GraphBindingContractVersion = protocol.GraphBindingContractVersionV1
	files["projection.json"] = set.ProjectionJSON
	files[protocol.GraphBindingsArtifactPath], err = marshalJSONL(v1Resources)
	if err != nil {
		t.Fatal(err)
	}
	files[protocol.ClaimBindingsArtifactPath], err = marshalJSONL(v1Claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, v2Field := range [][]byte{
		[]byte(`"subject_resource_id"`), []byte(`"object_resource_id"`),
		[]byte(`"source_document_resource_id"`), []byte(`"source_version"`),
		[]byte(`"provenance_resource_ids"`), []byte(`"supports"`),
	} {
		if bytes.Contains(files[protocol.ClaimBindingsArtifactPath], v2Field) {
			t.Fatalf("v1 compatibility fixture contains v2 field %s", v2Field)
		}
	}
	if err := ValidateGraphArtifactPayloads(v1Manifest, files); err != nil {
		t.Fatalf("valid v1 graph payload was rejected: %v", err)
	}
}

func TestValidateGraphArtifactPayloadsRejectsEmptyLegacyGraphProjection(t *testing.T) {
	projectionVersion := "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifest := protocol.ArtifactBundleManifest{
		ProjectionVersion:           projectionVersion,
		AuthorizationVersion:        "acl-v1",
		GraphBindingContractVersion: protocol.GraphBindingContractVersion,
		SourceSnapshot:              protocol.ArtifactSourceSnapshot{Version: "source-v1"},
	}
	files := map[string][]byte{
		"projection.json":                  []byte(`{"version":"` + projectionVersion + `"}`),
		"claims.jsonl":                     nil,
		protocol.GraphBindingsArtifactPath: nil,
		protocol.ClaimBindingsArtifactPath: nil,
	}
	if err := ValidateGraphArtifactPayloads(manifest, files); !errors.Is(err, ErrArtifactProjectionMismatch) {
		t.Fatalf("empty legacy graph projection error = %v, want generic projection mismatch", err)
	}
}

func sourceBackedArtifactSet(t *testing.T) ArtifactSet {
	t.Helper()
	scope := catalog.Scope{TenantID: "tenant", KnowledgeBaseID: "knowledge-base"}
	projectionVersion := "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	versions := protocol.ResourceVersions{
		Source: "source-v1", Content: "content-v1", ACL: "acl-v1",
		Index: "index_" + projectionVersion, Graph: "graph_" + projectionVersion,
		Projection: projectionVersion,
	}
	newMetadata := func(resourceType protocol.ResourceType, sourceKey string, parent protocol.ResourceID) catalog.ResourceMetadata {
		resourceID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, resourceType, sourceKey)
		if err != nil {
			t.Fatal(err)
		}
		authorizationObject := string(resourceType) + ":" + string(resourceID)
		if parent != "" {
			authorizationObject = "document:" + string(parent)
		}
		metadata, err := catalog.NewResourceMetadata(
			scope, resourceType, sourceKey, authorizationObject, parent,
			protocol.NewContentDigest(sourceKey), versions, catalog.SensitivityInternal, "local",
		)
		if err != nil {
			t.Fatal(err)
		}
		metadata.ServingState = catalog.StatePublished
		metadata.ProjectionStatus = catalog.SucceededProjectionStatus()
		return metadata
	}
	document := newMetadata(protocol.ResourceDocument, "sources/a.md", "")
	chunk := newMetadata(protocol.ResourceChunk, "sources/a.md#chunk:0", document.ResourceID)
	chunk.Dependencies = []protocol.ResourceID{document.ResourceID}
	subject := newMetadata(protocol.ResourceEntity, "entity:subject", "")
	subject.Dependencies = []protocol.ResourceID{chunk.ResourceID}
	object := newMetadata(protocol.ResourceEntity, "entity:object", "")
	object.Dependencies = []protocol.ResourceID{chunk.ResourceID}
	claim := newMetadata(protocol.ResourceClaim, "claim:semantic", "")
	documentRef := catalog.DocumentVersionRef{
		ResourceID: document.ResourceID, SourceVersion: versions.Source,
		ContentVersion: versions.Content, ACLVersion: versions.ACL, ProjectionVersion: versions.Projection,
	}
	predicate, err := protocol.NewClaimPredicateKey(string(protocol.ClaimPredicateLocatedIn))
	if err != nil {
		t.Fatal(err)
	}
	claim.ClaimRecord = &catalog.ClaimProjectionRecord{
		BindingState:      catalog.ClaimBindingSourceBacked,
		SubjectResourceID: subject.ResourceID, PredicateKey: predicate, ObjectResourceID: object.ResourceID,
		SourceDocument: documentRef,
		Provenance: catalog.Provenance{DerivationMode: protocol.DerivationAllRequired, Supports: []catalog.Support{{
			SupportID: "support-span", Complete: true,
			Evidence: []catalog.EvidenceRef{{
				ResourceID: chunk.ResourceID, Type: protocol.ResourceChunk,
				Versions: versions, Document: documentRef,
			}},
		}}},
	}
	claim.Dependencies = []protocol.ResourceID{document.ResourceID, chunk.ResourceID, subject.ResourceID, object.ResourceID}
	sort.Slice(claim.Dependencies, func(i, j int) bool { return claim.Dependencies[i] < claim.Dependencies[j] })
	snapshot := catalog.SourceSnapshotRef{
		Scope: scope, SourceID: "workspace", Version: versions.Source, SecurityDomain: "local",
		Digest: protocol.NewContentDigest("snapshot"), DocumentCount: 1,
	}
	projection, err := catalog.NewProjection(
		scope, projectionVersion, snapshot, catalog.StatePublished,
		[]catalog.ResourceMetadata{document, chunk, subject, object, claim},
	)
	if err != nil {
		t.Fatal(err)
	}
	graphBindings, claimBindings, err := catalog.ProjectionGraphBindings(projection)
	if err != nil {
		t.Fatal(err)
	}
	projectionJSON, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	return ArtifactSet{
		Manifest: protocol.ArtifactManifest{Version: 1, ClaimCount: 1},
		BundleManifest: protocol.ArtifactBundleManifest{
			ProjectionVersion: projectionVersion, AuthorizationVersion: versions.ACL,
			GraphBindingContractVersion: protocol.GraphBindingContractVersion,
			SourceSnapshot:              protocol.ArtifactSourceSnapshot{Version: versions.Source, DocumentCount: 1},
			Compatibility:               protocol.ArtifactManifest{Version: 1, ClaimCount: 1},
		},
		ProjectionJSON: projectionJSON, ProjectionResourceCount: len(projection.Resources),
		Claims: []protocol.Claim{{
			ClaimID: string(claim.ResourceID), Text: "semantic claim", Confidence: "high",
			EvidenceChunkIDs: []string{string(chunk.ResourceID)},
		}},
		GraphBindings: graphBindings, ClaimBindings: claimBindings,
	}
}
