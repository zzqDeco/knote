package versioned

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

const (
	localTenantID       = "local"
	localSecurityDomain = "local"
	projectionSchema    = "artifact-bundle-v2"
)

type loadedSource struct {
	source repository.Source
	data   []byte
	digest protocol.ContentDigest
}

type projectionBuild struct {
	store   *catalog.ProjectionStore
	current catalog.Projection
	plan    catalog.ProjectionPlan
	noop    bool
}

type artifactPublisher interface {
	StageArtifacts(context.Context, repository.ArtifactSet) error
	PublishArtifacts(context.Context, protocol.ArtifactBundleManifest) error
}

type currentProjectionReader interface {
	ReadCurrentProjection(context.Context) ([]byte, error)
}

type projectionRootProvider interface {
	ProjectionStoreRoot() string
}

func (s service) prepareArtifactProjection(ctx context.Context) (repository.ArtifactSet, projectionBuild, error) {
	sources, err := s.repo.ListSources(ctx)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	if len(sources) == 0 {
		return repository.ArtifactSet{}, projectionBuild{}, fmt.Errorf("sources directory not found or contains no .md/.txt files")
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	cfg, err := s.repo.Config(ctx)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	loaded := make([]loadedSource, 0, len(sources))
	for _, source := range sources {
		data, err := s.repo.ReadSource(ctx, source.Path)
		if err != nil {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		loaded = append(loaded, loadedSource{source: source, data: data, digest: protocol.NewContentDigest(string(data))})
	}

	namespaceBase := canonicalNamespace(firstNonEmpty(cfg.KAG.Namespace, "KnoteKB"))
	scope := catalog.Scope{TenantID: localTenantID, KnowledgeBaseID: namespaceBase}
	snapshotVersion, err := sourceSnapshotVersion(scope, loaded)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	aclVersion := canonicalACLVersion(scope)
	snapshotDocuments := make([]catalog.SourceDocumentSnapshot, 0, len(loaded))
	documentIDs := make(map[string]protocol.ResourceID, len(loaded))
	for _, item := range loaded {
		documentID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceDocument, item.source.Path)
		if err != nil {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		documentIDs[item.source.Path] = documentID
		snapshotDocuments = append(snapshotDocuments, catalog.SourceDocumentSnapshot{
			SourceKey: item.source.Path, SourceVersion: snapshotVersion, ContentDigest: item.digest,
			ACLVersion: aclVersion, AuthorizationObject: "document:" + string(documentID),
			Sensitivity: catalog.SensitivityInternal, SecurityDomain: localSecurityDomain,
		})
	}
	snapshot, err := catalog.NewSourceSnapshot(scope, "workspace", snapshotVersion, localSecurityDomain, snapshotDocuments)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	projectionVersion, err := canonicalProjectionVersion(scope, snapshot.Ref(), aclVersion)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	versions := func(content string) protocol.ResourceVersions {
		return protocol.ResourceVersions{
			Source: snapshotVersion, Content: content, ACL: aclVersion,
			Index: "index_" + projectionVersion, Graph: "graph_" + projectionVersion,
			Projection: projectionVersion,
		}
	}

	var set repository.ArtifactSet
	resources := make([]catalog.ResourceMetadata, 0)
	allDocumentIDs := make([]protocol.ResourceID, 0, len(loaded))
	for _, source := range loaded {
		documentID := documentIDs[source.source.Path]
		documentMetadata, err := catalog.NewResourceMetadata(
			scope, protocol.ResourceDocument, source.source.Path, "document:"+string(documentID), documentID,
			source.digest, versions("content_"+strings.TrimPrefix(string(source.digest), "sha256:")[:24]),
			catalog.SensitivityInternal, localSecurityDomain,
		)
		if err != nil {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		resources = append(resources, documentMetadata)
		allDocumentIDs = append(allDocumentIDs, documentID)
		doc := protocol.Document{
			DocumentID: string(documentID), Path: source.source.Path,
			ContentHash: strings.TrimPrefix(string(source.digest), "sha256:")[:16],
			Title:       titleFromContent(string(source.data)), Mtime: time.Unix(0, 0).UTC(),
		}
		set.Documents = append(set.Documents, doc)
		chunks := splitChunks(string(source.data), 1000)
		evidenceChunkIDs := make([]string, 0, len(chunks))
		entityDependencies := make([]protocol.ResourceID, 0, len(chunks))
		for ordinal, chunk := range chunks {
			chunkKey := fmt.Sprintf("%s#chunk:%d", source.source.Path, ordinal)
			chunkID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceChunk, chunkKey)
			if err != nil {
				return repository.ArtifactSet{}, projectionBuild{}, err
			}
			chunkDigest := protocol.NewContentDigest(chunk.text)
			chunkMetadata, err := catalog.NewResourceMetadata(
				scope, protocol.ResourceChunk, chunkKey, documentMetadata.AuthorizationObject, documentID,
				chunkDigest, versions("content_"+strings.TrimPrefix(string(chunkDigest), "sha256:")[:24]),
				catalog.SensitivityInternal, localSecurityDomain,
			)
			if err != nil {
				return repository.ArtifactSet{}, projectionBuild{}, err
			}
			chunkMetadata.Dependencies = []protocol.ResourceID{documentID}
			resources = append(resources, chunkMetadata)
			entityDependencies = append(entityDependencies, chunkID)
			item := protocol.Chunk{
				ChunkID: string(chunkID), DocumentID: string(documentID), Span: chunk.span,
				Text: chunk.text, Hash: strings.TrimPrefix(string(chunkDigest), "sha256:")[:16],
			}
			set.Chunks = append(set.Chunks, item)
			evidenceChunkIDs = append(evidenceChunkIDs, item.ChunkID)

			claimKey := chunkKey + "#claim"
			claimID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceClaim, claimKey)
			if err != nil {
				return repository.ArtifactSet{}, projectionBuild{}, err
			}
			claimText := compactClaim(item.Text)
			claimMetadata, err := catalog.NewResourceMetadata(
				scope, protocol.ResourceClaim, claimKey, "claim:"+string(claimID), claimID,
				protocol.NewContentDigest(claimText), versions("content_"+fullHash([]byte(claimText))[:24]),
				catalog.SensitivityInternal, localSecurityDomain,
			)
			if err != nil {
				return repository.ArtifactSet{}, projectionBuild{}, err
			}
			claimMetadata.Dependencies = []protocol.ResourceID{chunkID}
			resources = append(resources, claimMetadata)
			set.Claims = append(set.Claims, protocol.Claim{
				ClaimID: string(claimID), Text: claimText, Confidence: "medium",
				EvidenceChunkIDs: []string{item.ChunkID},
			})
		}
		sort.Strings(evidenceChunkIDs)
		sort.Slice(entityDependencies, func(i, j int) bool { return entityDependencies[i] < entityDependencies[j] })
		if len(entityDependencies) == 0 {
			entityDependencies = []protocol.ResourceID{documentID}
		}
		entityID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceEntity, source.source.Path+"#entity:document")
		if err != nil {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		entityMetadata, err := catalog.NewResourceMetadata(
			scope, protocol.ResourceEntity, source.source.Path+"#entity:document", "entity:"+string(entityID), entityID,
			protocol.NewContentDigest(firstNonEmpty(doc.Title, doc.Path)), versions("content_"+fullHash([]byte(firstNonEmpty(doc.Title, doc.Path)))[:24]),
			catalog.SensitivityInternal, localSecurityDomain,
		)
		if err != nil {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		entityMetadata.Dependencies = entityDependencies
		resources = append(resources, entityMetadata)
		set.Entities = append(set.Entities, protocol.Entity{
			EntityID: string(entityID), Name: firstNonEmpty(doc.Title, doc.Path), Type: "Document",
			Aliases: []string{doc.Path}, EvidenceChunkIDs: evidenceChunkIDs,
		})
	}
	sort.Slice(allDocumentIDs, func(i, j int) bool { return allDocumentIDs[i] < allDocumentIDs[j] })
	artifactID, err := protocol.NewStableResourceID(scope.TenantID, scope.KnowledgeBaseID, protocol.ResourceDerivedArtifact, "artifacts/bundle")
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	artifactMetadata, err := catalog.NewResourceMetadata(
		scope, protocol.ResourceDerivedArtifact, "artifacts/bundle", "artifact:"+string(artifactID), artifactID,
		protocol.NewContentDigest(projectionVersion), versions("content_"+projectionVersion),
		catalog.SensitivityInternal, localSecurityDomain,
	)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	artifactMetadata.Dependencies = allDocumentIDs
	resources = append(resources, artifactMetadata)
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })

	set.Summaries = []protocol.Summary{{
		SummaryID:        string(artifactID),
		Text:             fmt.Sprintf("Built %d documents and %d chunks.", len(set.Documents), len(set.Chunks)),
		EvidenceChunkIDs: chunkIDs(set.Chunks),
	}}
	generatedAt := time.Unix(0, 0).UTC()
	set.Manifest = protocol.ArtifactManifest{
		Version: 1, Workspace: scope.KnowledgeBaseID, GeneratedAt: generatedAt,
		SourceCount: len(sources), DocumentCount: len(set.Documents), ChunkCount: len(set.Chunks),
		EntityCount: len(set.Entities), RelationCount: len(set.Relations), ClaimCount: len(set.Claims),
		SummaryCount: len(set.Summaries),
	}
	set.SchemaYAML = defaultSchemaYAML
	set.BuildReport = renderBuildReport(set.Manifest)
	publishedResources := make([]catalog.ResourceMetadata, len(resources))
	for i, resource := range resources {
		resource.ServingState = catalog.StatePublished
		resource.ProjectionStatus = catalog.SucceededProjectionStatus()
		publishedResources[i] = resource
	}
	publicProjection, err := catalog.NewProjection(scope, projectionVersion, snapshot.Ref(), catalog.StatePublished, publishedResources)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	projectionJSON, err := json.MarshalIndent(publicProjection, "", "  ")
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	set.ProjectionJSON = append(projectionJSON, '\n')
	set.ProjectionResourceCount = len(publicProjection.Resources)
	set.BundleManifest = protocol.ArtifactBundleManifest{
		Version: protocol.ArtifactBundleManifestVersion, ProjectionID: projectionVersion,
		ProjectionVersion: projectionVersion, Namespace: namespaceBase + "__" + projectionVersion,
		AuthorizationObject:  "knowledge-base:" + scope.KnowledgeBaseID,
		AuthorizationVersion: aclVersion,
		SourceSnapshot: protocol.ArtifactSourceSnapshot{
			Version: snapshot.Ref().Version, Digest: strings.TrimPrefix(string(snapshot.Ref().Digest), "sha256:"),
			DocumentCount: snapshot.Ref().DocumentCount,
		},
		GeneratedAt: generatedAt, Compatibility: set.Manifest,
	}
	payloads, err := repository.CanonicalArtifactFiles(set)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	set.BundleManifest.Files = repository.ArtifactFileDescriptors(payloads)
	if err := set.BundleManifest.Validate(); err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}

	current, err := s.selectedBaseProjection(ctx, scope)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	if current.Version == projectionVersion {
		return set, projectionBuild{current: current, noop: true}, nil
	}
	projectionRoot := filepath.Join(s.workspace, ".knote", "projections")
	if provider, ok := s.repo.(projectionRootProvider); ok {
		projectionRoot = provider.ProjectionStoreRoot()
	}
	storeRoot := filepath.Join(projectionRoot, "by-base", current.Version)
	store, err := catalog.NewProjectionStore(storeRoot)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	if err := store.InitializeServing(current); err != nil {
		if !errors.Is(err, catalog.ErrJournalConflict) {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		serving, servingErr := store.ServingProjection()
		if servingErr != nil || serving.Version != projectionVersion {
			return repository.ArtifactSet{}, projectionBuild{}, err
		}
		return set, projectionBuild{store: store, current: serving, noop: true}, nil
	}
	build := projectionBuild{store: store, current: current}
	run := catalog.SyncRun{
		RunID: "run-" + projectionVersion, Scope: scope, SourceSnapshot: snapshot.Ref(),
		BaseProjectionVersion: current.Version, ProjectionVersion: projectionVersion,
		IdempotencyKey: "sync-" + projectionVersion, Reconciliation: catalog.ReconciliationFull,
		State: catalog.RunStaged,
	}
	build.plan, err = catalog.PlanResources(run, current, resources)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	return set, build, nil
}

func (s service) selectedBaseProjection(ctx context.Context, scope catalog.Scope) (catalog.Projection, error) {
	if reader, ok := s.repo.(currentProjectionReader); ok {
		data, err := reader.ReadCurrentProjection(ctx)
		if err == nil {
			var projection catalog.Projection
			if err := json.Unmarshal(data, &projection); err != nil {
				return catalog.Projection{}, fmt.Errorf("decode selected artifact projection: %w", err)
			}
			if err := projection.Validate(); err != nil {
				return catalog.Projection{}, fmt.Errorf("validate selected artifact projection: %w", err)
			}
			if projection.Scope != scope {
				return catalog.Projection{}, fmt.Errorf("selected artifact projection scope does not match workspace")
			}
			return projection, nil
		}
		if !errors.Is(err, repository.ErrArtifactCurrentNotFound) {
			return catalog.Projection{}, err
		}
	}
	emptySnapshot, err := catalog.NewSourceSnapshot(scope, "workspace", "source-empty", localSecurityDomain, nil)
	if err != nil {
		return catalog.Projection{}, err
	}
	return catalog.NewProjection(scope, "projection-empty", emptySnapshot.Ref(), catalog.StatePublished, nil)
}

func sourceSnapshotVersion(scope catalog.Scope, sources []loadedSource) (string, error) {
	payload := struct {
		Scope          catalog.Scope `json:"scope"`
		SecurityDomain string        `json:"security_domain"`
		Sources        []struct {
			Path   string                 `json:"path"`
			Digest protocol.ContentDigest `json:"digest"`
		} `json:"sources"`
	}{Scope: scope, SecurityDomain: localSecurityDomain}
	for _, source := range sources {
		payload.Sources = append(payload.Sources, struct {
			Path   string                 `json:"path"`
			Digest protocol.ContentDigest `json:"digest"`
		}{Path: source.source.Path, Digest: source.digest})
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "source-" + fullHash(data)[:24], nil
}

func canonicalProjectionVersion(scope catalog.Scope, snapshot catalog.SourceSnapshotRef, aclVersion string) (string, error) {
	payload := struct {
		Schema   string                    `json:"schema"`
		Scope    catalog.Scope             `json:"scope"`
		Snapshot catalog.SourceSnapshotRef `json:"source_snapshot"`
		ACL      string                    `json:"acl_version"`
		Index    string                    `json:"index_version"`
		Graph    string                    `json:"graph_version"`
	}{
		Schema: projectionSchema, Scope: scope, Snapshot: snapshot, ACL: aclVersion,
		Index: "index-v1", Graph: "graph-v1",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "prj_" + fullHash(data)[:32], nil
}

func canonicalACLVersion(scope catalog.Scope) string {
	payload := strings.Join([]string{
		projectionSchema,
		scope.TenantID,
		scope.KnowledgeBaseID,
		localSecurityDomain,
		"document-boundary-v1",
	}, "\x00")
	return "acl_" + fullHash([]byte(payload))[:24]
}

func (s service) executeProjectionBuild(ctx context.Context, artifacts repository.ArtifactSet, build projectionBuild) (map[string]any, error) {
	publisher, ok := s.repo.(artifactPublisher)
	if !ok {
		return nil, fmt.Errorf("v2 artifact repository does not support staged publication")
	}
	if build.noop {
		if err := publisher.StageArtifacts(ctx, artifacts); err != nil {
			return nil, err
		}
		if err := publisher.PublishArtifacts(ctx, artifacts.BundleManifest); err != nil {
			return nil, err
		}
		return map[string]any{"projection_version": artifacts.BundleManifest.ProjectionVersion, "idempotent_noop": true}, nil
	}
	backend, ok := s.backend.(namespacedBackend)
	if !ok {
		return nil, fmt.Errorf("v2 build requires a backend that implements BuildInNamespace")
	}
	var buildData map[string]any
	var operationErr error
	kagBuilt := false
	artifactsStaged := false
	executor := catalog.OperationExecutorFunc(func(ctx context.Context, operation catalog.ProjectionOperation) (catalog.OperationResult, error) {
		succeed := func() (catalog.OperationResult, error) {
			return catalog.OperationResult{OperationID: operation.OperationID, Outcome: catalog.OperationSucceeded}, nil
		}
		switch operation.Kind {
		case catalog.OperationProjectIndex:
			if !kagBuilt {
				response, err := backend.BuildInNamespace(ctx, artifacts.BundleManifest.Namespace)
				if err != nil {
					operationErr = fmt.Errorf("KAG build failed: %w", err)
					return catalog.OperationResult{}, operationErr
				}
				buildData = cloneMap(response.Data)
				kagBuilt = true
			}
		case catalog.OperationProjectArtifact:
			if !artifactsStaged {
				if err := publisher.StageArtifacts(ctx, artifacts); err != nil {
					operationErr = err
					return catalog.OperationResult{}, err
				}
				artifactsStaged = true
			}
		}
		return succeed()
	})
	execution, err := build.store.Execute(ctx, build.plan, build.current, executor)
	if err != nil {
		return nil, err
	}
	if execution.Report.RunState != catalog.RunSucceeded || execution.Projection.Version != artifacts.BundleManifest.ProjectionVersion {
		if operationErr != nil {
			return nil, operationErr
		}
		return nil, fmt.Errorf("projection build did not reach a successful serving state")
	}
	if err := publisher.PublishArtifacts(ctx, artifacts.BundleManifest); err != nil {
		return nil, fmt.Errorf("publish artifact serving pointer: %w", err)
	}
	return buildData, nil
}
