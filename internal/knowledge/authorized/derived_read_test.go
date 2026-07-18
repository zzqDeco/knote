package authorized

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestServiceReadDerivedArtifactAuthorizesSourcesWithoutArtifactTuple(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	reader := newTrackingSelectedReader(fixture.snapshot)
	artifactChecked := false
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		for _, check := range request.Checks {
			if strings.HasPrefix(check.Object, "artifact:") {
				artifactChecked = true
				return nil, fmt.Errorf("derived artifact is not an OpenFGA type")
			}
		}
		return queryTestDecisions(request, func(authz.BatchCheckItem) bool { return true }), nil
	}}
	service, _ := newDerivedReadService(t, reader, authorizer)

	item, err := service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	if err != nil {
		t.Fatal(err)
	}
	if artifactChecked {
		t.Fatal("derived artifact handle was sent to BatchCheck")
	}
	if item.Content != fixture.summaryText || item.Resource != fixture.handle ||
		protocol.NewContentDigest(item.Content) != fixture.handle.ContentDigest {
		t.Fatalf("derived evidence does not match the exact summary: %#v", item)
	}
	if err := validateLoadedItem(fixture.authorization, item); err != nil {
		t.Fatalf("derived evidence item: %v", err)
	}
	if _, _, _, err := collectEvidenceHandles(fixture.authorization, []protocol.EvidenceItem{item}); err != nil {
		t.Fatalf("derived evidence boundaries: %v", err)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("source authorization calls = %d, want pre-load and post-load checks", len(authorizer.calls))
	}
	for _, object := range fixture.sourceAuthorizationIDs {
		for call, request := range authorizer.calls {
			if !batchCheckContainsObject(request, object) {
				t.Fatalf("authorization call %d omitted source boundary %s", call, object)
			}
		}
	}
	metadataReads, bundleReads := reader.stats()
	if metadataReads != 2 || bundleReads != 1 {
		t.Fatalf("selected reads = metadata:%d bundle:%d, want metadata:2 bundle:1", metadataReads, bundleReads)
	}
}

func TestServiceReadDerivedArtifactDeniesBeforeBundleBodyRead(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	reader := newTrackingSelectedReader(fixture.snapshot)
	deniedObject := fixture.sourceAuthorizationIDs[0]
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != deniedObject
		}), nil
	}}
	service, _ := newDerivedReadService(t, reader, authorizer)

	_, err := service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	requireProtectedContentUnavailable(t, err)
	_, bundleReads := reader.stats()
	if bundleReads != 0 {
		t.Fatalf("denied derived read loaded %d full bundle(s)", bundleReads)
	}
}

func TestServiceReadDerivedArtifactAnySupportRequiresEverySourceAuthorization(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	snapshot := rewriteDerivedProjection(t, fixture.snapshot, func(metadata *catalog.ResourceMetadata) {
		reissueDerivedAnySupport(t, metadata)
	})
	deniedObject := fixture.sourceAuthorizationIDs[0]
	reader := newTrackingSelectedReader(snapshot)
	authorizer := &queryTestAuthorizer{decide: func(_ int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return check.Object != deniedObject
		}), nil
	}}
	service, _ := newDerivedReadService(t, reader, authorizer)

	_, err := service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	requireProtectedContentUnavailable(t, err)
	for _, request := range authorizer.calls {
		if !batchCheckContainsObject(request, deniedObject) {
			t.Fatal("any_support authorization omitted the denied alternative")
		}
	}
	_, bundleReads := reader.stats()
	if bundleReads != 0 {
		t.Fatalf("denied any_support source loaded %d full bundle(s)", bundleReads)
	}
}

func TestServiceReadDerivedArtifactRejectsSourceRevokedAfterBundleRead(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	reader := newTrackingSelectedReader(fixture.snapshot)
	deniedObject := fixture.sourceAuthorizationIDs[0]
	authorizer := &queryTestAuthorizer{decide: func(call int, request authz.BatchCheckRequest) ([]authz.Decision, error) {
		return queryTestDecisions(request, func(check authz.BatchCheckItem) bool {
			return call == 0 || check.Object != deniedObject
		}), nil
	}}
	service, _ := newDerivedReadService(t, reader, authorizer)

	_, err := service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	requireProtectedContentUnavailable(t, err)
	if len(authorizer.calls) != 2 {
		t.Fatalf("source authorization calls = %d, want pre-load and post-load checks", len(authorizer.calls))
	}
	_, bundleReads := reader.stats()
	if bundleReads != 1 {
		t.Fatalf("post-load revocation bundle reads = %d, want 1", bundleReads)
	}
}

func TestServiceReadDerivedArtifactUsesHigherConsistencyForBothSourceChecks(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	snapshot := rewriteDerivedProjection(t, fixture.snapshot, func(metadata *catalog.ResourceMetadata) {
		reissueDerivedSecurity(t, metadata, string(protocol.DerivedArtifactSummary), func(auth *protocol.AuthorizationContext) {
			auth.Consistency = protocol.ConsistencyMinimizeLatency
		})
	})
	authorization := fixture.authorization
	authorization.Consistency = protocol.ConsistencyMinimizeLatency
	reader := newTrackingSelectedReader(snapshot)
	authorizer := &queryTestAuthorizer{}
	service, _ := newDerivedReadService(t, reader, authorizer)

	if _, err := service.ReadDerivedArtifact(context.Background(), authorization, fixture.handle); err != nil {
		t.Fatal(err)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("source authorization calls = %d, want 2", len(authorizer.calls))
	}
	for index, request := range authorizer.calls {
		if request.Consistency != authz.ConsistencyHigherConsistency {
			t.Fatalf("authorization call %d consistency = %q, want %q", index, request.Consistency, authz.ConsistencyHigherConsistency)
		}
	}
}

func TestServiceReadDerivedArtifactContextAndHandleDriftAreIndistinguishable(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	tests := []struct {
		name       string
		mutateAuth func(*protocol.AuthorizationContext)
		mutate     func(*protocol.ResourceHandle)
	}{
		{name: "principal", mutateAuth: func(auth *protocol.AuthorizationContext) { auth.PrincipalID = "other-principal" }},
		{name: "model", mutateAuth: func(auth *protocol.AuthorizationContext) { auth.AuthorizationModelID = "other-model" }},
		{name: "identity", mutateAuth: func(auth *protocol.AuthorizationContext) { auth.IdentityWatermark = "other-identity" }},
		{name: "ACL", mutateAuth: func(auth *protocol.AuthorizationContext) { auth.ACLWatermark = "acl-other" }},
		{name: "projection", mutate: func(handle *protocol.ResourceHandle) { handle.Versions.Projection = "projection-stale" }},
		{name: "authorization identity", mutate: func(handle *protocol.ResourceHandle) { handle.AuthorizationID = "artifact:stale" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newTrackingSelectedReader(fixture.snapshot)
			service, _ := newDerivedReadService(t, reader, &queryTestAuthorizer{})
			authorization := fixture.authorization
			handle := fixture.handle
			if test.mutateAuth != nil {
				test.mutateAuth(&authorization)
			}
			if test.mutate != nil {
				test.mutate(&handle)
			}
			_, err := service.ReadDerivedArtifact(context.Background(), authorization, handle)
			requireProtectedContentUnavailable(t, err)
			_, bundleReads := reader.stats()
			if bundleReads != 0 {
				t.Fatalf("%s drift loaded %d full bundle(s)", test.name, bundleReads)
			}
		})
	}
}

func TestServiceReadDerivedArtifactRejectsMissingStaleOrMismatchedSecurity(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	tests := []struct {
		name   string
		mutate func(*catalog.ResourceMetadata)
	}{
		{name: "missing record", mutate: func(metadata *catalog.ResourceMetadata) {
			metadata.DerivedArtifactSecurity = nil
		}},
		{name: "stale ACL record", mutate: func(metadata *catalog.ResourceMetadata) {
			reissueDerivedSecurity(t, metadata, string(protocol.DerivedArtifactSummary), func(auth *protocol.AuthorizationContext) {
				auth.ACLWatermark = "acl-stale"
			})
		}},
		{name: "stale principal record", mutate: func(metadata *catalog.ResourceMetadata) {
			reissueDerivedSecurity(t, metadata, string(protocol.DerivedArtifactSummary), func(auth *protocol.AuthorizationContext) {
				auth.PrincipalID = "retired-principal"
			})
		}},
		{name: "support identity mismatch", mutate: func(metadata *catalog.ResourceMetadata) {
			record := *metadata.DerivedArtifactSecurity
			record.Supports = append([]protocol.DerivedArtifactSupportGroup(nil), record.Supports...)
			record.Supports[0].Resources = append([]protocol.DerivedArtifactResourceIdentity(nil), record.Supports[0].Resources...)
			record.Supports[0].Resources[0].ContentDigest = protocol.NewContentDigest("stale support")
			metadata.DerivedArtifactSecurity = &record
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := rewriteDerivedProjection(t, fixture.snapshot, test.mutate)
			reader := newTrackingSelectedReader(snapshot)
			service, _ := newDerivedReadService(t, reader, &queryTestAuthorizer{})
			_, err := service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
			requireProtectedContentUnavailable(t, err)
			_, bundleReads := reader.stats()
			if bundleReads != 0 {
				t.Fatalf("invalid security loaded %d full bundle(s)", bundleReads)
			}
		})
	}
}

func TestServiceReadDerivedArtifactRejectsSummaryDigestMismatch(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	snapshot := fixture.snapshot.Clone()
	summary := decodeOnlySummary(t, snapshot.Files["summaries.jsonl"])
	summary.Text += " tampered"
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	replaceSelectedFile(t, &snapshot, "summaries.jsonl", data)
	reader := newTrackingSelectedReader(snapshot)
	service, _ := newDerivedReadService(t, reader, &queryTestAuthorizer{})

	_, err = service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	requireProtectedContentUnavailable(t, err)
	_, bundleReads := reader.stats()
	if bundleReads != 1 {
		t.Fatalf("digest mismatch bundle reads = %d, want 1", bundleReads)
	}
}

func TestServiceReadDerivedArtifactRejectsSummaryEvidenceMismatch(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	snapshot := fixture.snapshot.Clone()
	summary := decodeOnlySummary(t, snapshot.Files["summaries.jsonl"])
	if len(summary.EvidenceChunkIDs) < 2 {
		t.Fatalf("fixture summary has insufficient evidence: %#v", summary)
	}
	summary.EvidenceChunkIDs = summary.EvidenceChunkIDs[1:]
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	replaceSelectedFile(t, &snapshot, "summaries.jsonl", data)
	reader := newTrackingSelectedReader(snapshot)
	service, _ := newDerivedReadService(t, reader, &queryTestAuthorizer{})

	_, err = service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	requireProtectedContentUnavailable(t, err)
	_, bundleReads := reader.stats()
	if bundleReads != 1 {
		t.Fatalf("evidence mismatch bundle reads = %d, want 1", bundleReads)
	}
}

func TestServiceReadDerivedArtifactRejectsSummaryIDMismatch(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	snapshot := fixture.snapshot.Clone()
	summary := decodeOnlySummary(t, snapshot.Files["summaries.jsonl"])
	summary.SummaryID = string(queryTestOtherID)
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	replaceSelectedFile(t, &snapshot, "summaries.jsonl", data)
	reader := newTrackingSelectedReader(snapshot)
	service, _ := newDerivedReadService(t, reader, &queryTestAuthorizer{})

	_, err = service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle)
	requireProtectedContentUnavailable(t, err)
	_, bundleReads := reader.stats()
	if bundleReads != 1 {
		t.Fatalf("summary ID mismatch bundle reads = %d, want 1", bundleReads)
	}
}

func TestServiceReadDerivedArtifactRejectsMetadataPointerChange(t *testing.T) {
	first := newDerivedReadFixture(t, "alpha body", "beta body")
	second := newDerivedReadFixture(t, "alpha body changed", "beta body")
	reader := newTrackingSelectedReader(first.snapshot)
	reader.metadata = []repository.SelectedArtifactMetadata{
		selectedMetadata(first.snapshot), selectedMetadata(second.snapshot),
	}
	service, _ := newDerivedReadService(t, reader, &queryTestAuthorizer{})

	_, err := service.ReadDerivedArtifact(context.Background(), first.authorization, first.handle)
	requireProtectedContentUnavailable(t, err)
	metadataReads, bundleReads := reader.stats()
	if metadataReads != 2 || bundleReads != 1 {
		t.Fatalf("pointer-change reads = metadata:%d bundle:%d, want metadata:2 bundle:1", metadataReads, bundleReads)
	}
}

func TestDerivedArtifactOutlineAndTableWithoutBodiesFailClosed(t *testing.T) {
	fixture := newDerivedReadFixture(t, "alpha body", "beta body")
	for _, kind := range []protocol.DerivedArtifactKind{
		protocol.DerivedArtifactOutline,
		protocol.DerivedArtifactTable,
	} {
		t.Run(string(kind), func(t *testing.T) {
			snapshot := rewriteDerivedProjection(t, fixture.snapshot, func(metadata *catalog.ResourceMetadata) {
				reissueDerivedSecurity(t, metadata, string(kind), nil)
			})
			reader := newTrackingSelectedReader(snapshot)
			service, loader := newDerivedReadService(t, reader, &queryTestAuthorizer{})
			metadata, err := loader.DiscoverDerivedArtifact(context.Background(), fixture.handle.ResourceID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loader.LoadDerivedArtifact(context.Background(), metadata); err != nil {
				requireProtectedContentUnavailable(t, err)
			} else {
				t.Fatal("body loader accepted an unsupported derived artifact kind")
			}
			if _, err := service.ReadDerivedArtifact(context.Background(), fixture.authorization, fixture.handle); err != nil {
				requireProtectedContentUnavailable(t, err)
			} else {
				t.Fatal("service accepted an unsupported derived artifact kind")
			}
			_, bundleReads := reader.stats()
			if bundleReads != 0 {
				t.Fatalf("unsupported %s loaded %d full bundle(s)", kind, bundleReads)
			}
		})
	}
}

type derivedReadFixture struct {
	snapshot               repository.SelectedArtifactBundle
	handle                 protocol.ResourceHandle
	authorization          protocol.AuthorizationContext
	summaryText            string
	sourceAuthorizationIDs []string
}

func newDerivedReadFixture(t *testing.T, contents ...string) derivedReadFixture {
	t.Helper()
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	for index, content := range contents {
		path := filepath.Join(workspace, "sources", fmt.Sprintf("source-%d.md", index))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store := local.New(workspace)
	service := versioned.New(versioned.Options{
		Workspace: workspace, Repo: store, Backend: derivedReadBuildBackend{}, Mode: versioned.ModeFake,
	})
	if _, err := service.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	localSnapshot, err := store.ReadCurrentArtifactBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	localProjection := decodeSelectedProjection(t, localSnapshot)
	materializationAuthorization := protocol.AuthorizationContext{
		Version:  protocol.SecurityContractVersion,
		TenantID: localProjection.Scope.TenantID, KnowledgeBaseID: localProjection.Scope.KnowledgeBaseID,
		PrincipalID: "derived-reader", SessionID: "derived-materialization", RequestID: "derived-materialization-request",
		AuthorizationModelID: queryTestAuthModel, IdentityWatermark: "derived-identity-v1",
		ACLWatermark: localSnapshot.Manifest.AuthorizationVersion,
		Consistency:  protocol.ConsistencyHigherConsistency,
	}
	permissionedContext, err := protocol.WithAuthorizationContext(context.Background(), materializationAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Build(permissionedContext); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadCurrentArtifactBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	projection := decodeSelectedProjection(t, snapshot)
	handles := make(map[protocol.ResourceID]protocol.ResourceHandle, len(projection.Resources))
	var derived catalog.ResourceMetadata
	for _, metadata := range projection.Resources {
		if metadata.IsServing() {
			handle, err := metadata.ServingHandle()
			if err != nil {
				t.Fatal(err)
			}
			handles[metadata.ResourceID] = handle
		}
		if metadata.Type == protocol.ResourceDerivedArtifact {
			derived = metadata
		}
	}
	if derived.DerivedArtifactSecurity == nil {
		t.Fatal("fixture projection has no derived security record")
	}
	handle := handles[derived.ResourceID]
	record := derived.DerivedArtifactSecurity
	authorization := authorizationForDerivedRecord(*record)
	sourceObjects := make(map[string]struct{})
	for _, support := range record.Supports {
		for _, identity := range support.Resources {
			sourceObjects[handles[identity.ResourceID].AuthorizationID] = struct{}{}
		}
	}
	sourceAuthorizationIDs := make([]string, 0, len(sourceObjects))
	for object := range sourceObjects {
		sourceAuthorizationIDs = append(sourceAuthorizationIDs, object)
	}
	sort.Strings(sourceAuthorizationIDs)
	return derivedReadFixture{
		snapshot: snapshot, handle: handle, authorization: authorization,
		summaryText:            decodeOnlySummary(t, snapshot.Files["summaries.jsonl"]).Text,
		sourceAuthorizationIDs: sourceAuthorizationIDs,
	}
}

func newDerivedReadService(
	t *testing.T,
	reader repository.SelectedArtifactReader,
	authorizer authz.BatchChecker,
) (*Service, *BundleEvidenceLoader) {
	t.Helper()
	loader, err := NewBundleEvidenceLoader(reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{KAG: &queryTestKAG{}, Authorizer: authorizer, Loader: loader})
	if err != nil {
		t.Fatal(err)
	}
	return service, loader
}

type trackingSelectedReader struct {
	mu            sync.Mutex
	bundle        repository.SelectedArtifactBundle
	metadata      []repository.SelectedArtifactMetadata
	metadataReads int
	bundleReads   int
}

func newTrackingSelectedReader(snapshot repository.SelectedArtifactBundle) *trackingSelectedReader {
	return &trackingSelectedReader{
		bundle: snapshot.Clone(), metadata: []repository.SelectedArtifactMetadata{selectedMetadata(snapshot)},
	}
}

func (r *trackingSelectedReader) ReadCurrentArtifactMetadata(context.Context) (repository.SelectedArtifactMetadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.metadataReads
	r.metadataReads++
	if index >= len(r.metadata) {
		index = len(r.metadata) - 1
	}
	return r.metadata[index].Clone(), nil
}

func (r *trackingSelectedReader) ReadCurrentArtifactBundle(context.Context) (repository.SelectedArtifactBundle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bundleReads++
	return r.bundle.Clone(), nil
}

func (r *trackingSelectedReader) stats() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.metadataReads, r.bundleReads
}

func rewriteDerivedProjection(
	t *testing.T,
	snapshot repository.SelectedArtifactBundle,
	mutate func(*catalog.ResourceMetadata),
) repository.SelectedArtifactBundle {
	t.Helper()
	snapshot = snapshot.Clone()
	projection := decodeSelectedProjection(t, snapshot)
	found := false
	for index := range projection.Resources {
		if projection.Resources[index].Type != protocol.ResourceDerivedArtifact {
			continue
		}
		mutate(&projection.Resources[index])
		found = true
		break
	}
	if !found {
		t.Fatal("projection has no derived artifact")
	}
	data, err := json.MarshalIndent(projection, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	replaceSelectedFile(t, &snapshot, "projection.json", data)
	return snapshot
}

func reissueDerivedSecurity(
	t *testing.T,
	metadata *catalog.ResourceMetadata,
	kind string,
	mutate func(*protocol.AuthorizationContext),
) {
	t.Helper()
	if metadata.DerivedArtifactSecurity == nil {
		t.Fatal("derived security record is missing")
	}
	current := *metadata.DerivedArtifactSecurity
	authorization := authorizationForDerivedRecord(current)
	if mutate != nil {
		mutate(&authorization)
	}
	record, err := protocol.NewDerivedArtifactSecurityRecord(
		kind, current.DerivationMode, current.Artifact, current.Supports,
		current.SecurityDomain, authorization,
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata.DerivedArtifactSecurity = &record
}

func reissueDerivedAnySupport(t *testing.T, metadata *catalog.ResourceMetadata) {
	t.Helper()
	if metadata.DerivedArtifactSecurity == nil {
		t.Fatal("derived security record is missing")
	}
	current := *metadata.DerivedArtifactSecurity
	byAuthorizationObject := make(map[string][]protocol.DerivedArtifactResourceIdentity)
	for _, support := range current.Supports {
		for _, resource := range support.Resources {
			byAuthorizationObject[resource.AuthorizationID] = append(byAuthorizationObject[resource.AuthorizationID], resource)
		}
	}
	objects := make([]string, 0, len(byAuthorizationObject))
	for object := range byAuthorizationObject {
		objects = append(objects, object)
	}
	sort.Strings(objects)
	supports := make([]protocol.DerivedArtifactSupportGroup, len(objects))
	for index, object := range objects {
		supports[index] = protocol.DerivedArtifactSupportGroup{
			SupportID: fmt.Sprintf("support-%03d", index),
			Resources: byAuthorizationObject[object], Complete: true,
		}
	}
	record, err := protocol.NewDerivedArtifactSecurityRecord(
		current.Kind, protocol.DerivationAnySupport, current.Artifact,
		supports, current.SecurityDomain, authorizationForDerivedRecord(current),
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata.DerivedArtifactSecurity = &record
}

func authorizationForDerivedRecord(record protocol.DerivedArtifactSecurityRecord) protocol.AuthorizationContext {
	return protocol.AuthorizationContext{
		Version:  protocol.SecurityContractVersion,
		TenantID: record.TenantID, KnowledgeBaseID: record.KnowledgeBaseID,
		PrincipalID: record.PrincipalID, SessionID: "derived-read-session", RequestID: "derived-read-request",
		AgentID: record.AgentID, TaskID: record.TaskID,
		DelegationWatermark:       record.DelegationWatermark,
		AgentTaskScopeFingerprint: record.AgentTaskScopeFingerprint,
		AuthorizationModelID:      record.AuthorizationModelID, IdentityWatermark: record.IdentityWatermark,
		ACLWatermark: record.ACLWatermark, Consistency: record.Consistency,
	}
}

func replaceSelectedFile(
	t *testing.T,
	snapshot *repository.SelectedArtifactBundle,
	path string,
	data []byte,
) {
	t.Helper()
	snapshot.Files[path] = append([]byte(nil), data...)
	sum := sha256.Sum256(data)
	for index := range snapshot.Manifest.Files {
		if snapshot.Manifest.Files[index].Path != path {
			continue
		}
		snapshot.Manifest.Files[index].SHA256 = hex.EncodeToString(sum[:])
		snapshot.Manifest.Files[index].SizeBytes = int64(len(data))
		return
	}
	t.Fatalf("manifest has no descriptor for %s", path)
}

func selectedMetadata(snapshot repository.SelectedArtifactBundle) repository.SelectedArtifactMetadata {
	return repository.SelectedArtifactMetadata{
		Manifest: snapshot.Manifest, ProjectionJSON: append([]byte(nil), snapshot.Files["projection.json"]...),
	}.Clone()
}

func decodeSelectedProjection(t *testing.T, snapshot repository.SelectedArtifactBundle) catalog.Projection {
	t.Helper()
	var projection catalog.Projection
	if err := json.Unmarshal(snapshot.Files["projection.json"], &projection); err != nil {
		t.Fatal(err)
	}
	return projection
}

func decodeOnlySummary(t *testing.T, data []byte) protocol.Summary {
	t.Helper()
	var summary protocol.Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	return summary
}

func batchCheckContainsObject(request authz.BatchCheckRequest, object string) bool {
	for _, check := range request.Checks {
		if check.Object == object {
			return true
		}
	}
	return false
}

func requireProtectedContentUnavailable(t *testing.T, err error) {
	t.Helper()
	if err != ErrProtectedContentUnavailable || !errors.Is(err, ErrProtectedContentUnavailable) ||
		err.Error() != ErrProtectedContentUnavailable.Error() {
		t.Fatalf("error = %v, want exact %v", err, ErrProtectedContentUnavailable)
	}
}

type derivedReadBuildBackend struct{}

func (derivedReadBuildBackend) Build(context.Context) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"mode": "fake"}}, nil
}

func (derivedReadBuildBackend) Query(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "fake", "mode": "fake"}}, nil
}

func (derivedReadBuildBackend) Explain(context.Context, string) (kag.Response, error) {
	return kag.Response{Data: map[string]any{"answer": "fake", "mode": "fake"}}, nil
}

func (b derivedReadBuildBackend) BuildInNamespace(ctx context.Context, _, _ string) (kag.Response, error) {
	return b.Build(ctx)
}

func (b derivedReadBuildBackend) BuildInNamespaceWithCorpus(
	ctx context.Context,
	_, _ string,
	_ []kag.CorpusRecord,
) (kag.Response, error) {
	return b.Build(ctx)
}

func (b derivedReadBuildBackend) QueryInNamespace(
	ctx context.Context,
	_ string,
	query string,
) (kag.Response, error) {
	return b.Query(ctx, query)
}

func (b derivedReadBuildBackend) ExplainInNamespace(
	ctx context.Context,
	_ string,
	query string,
) (kag.Response, error) {
	return b.Explain(ctx, query)
}
