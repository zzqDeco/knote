package versioned

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

const (
	localTenantID       = "local"
	localSecurityDomain = "local"
	projectionSchema    = "artifact-bundle-v2"

	maxKAGResourceFiles     = 4_096
	maxKAGResourceFileBytes = 8 << 20
	maxKAGResourceBytes     = 64 << 20
)

type loadedSource struct {
	source repository.Source
	data   []byte
	digest protocol.ContentDigest
}

type projectionBuild struct {
	store   *catalog.ProjectionStore
	base    catalog.Projection
	current catalog.Projection
	plan    catalog.ProjectionPlan
	corpus  []kag.CorpusRecord
	noop    bool
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
	corpus := make([]kag.CorpusRecord, 0, len(loaded))
	for _, item := range loaded {
		content := string(item.data)
		corpus = append(corpus, kag.CorpusRecord{
			ID: item.source.Path, Name: titleFromContent(content), Content: content, SourcePath: item.source.Path,
		})
	}

	namespaceBase := canonicalNamespace(firstNonEmpty(cfg.KAG.Namespace, "KnoteKB"))
	scope := catalog.Scope{TenantID: localTenantID, KnowledgeBaseID: namespaceBase}
	snapshotVersion, err := sourceSnapshotVersion(scope, loaded)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	aclVersion := canonicalACLVersion(scope)
	buildConfigVersion, err := kagBuildConfigVersion(s.workspace, cfg)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
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
	projectionVersion, err := canonicalProjectionVersion(scope, snapshot.Ref(), aclVersion, buildConfigVersion)
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
		return set, projectionBuild{base: current, current: current, corpus: corpus, noop: true}, nil
	}
	projectionRoot := filepath.Join(s.workspace, ".knote", "projections")
	if provider, ok := s.repo.(projectionRootProvider); ok {
		projectionRoot = provider.ProjectionStoreRoot()
	}
	storeRoot := projectionJournalRoot(projectionRoot, current.Version, projectionVersion)
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
		return set, projectionBuild{
			store: store, base: current, current: serving, corpus: corpus, noop: true,
		}, nil
	}
	build := projectionBuild{store: store, base: current, current: current, corpus: corpus}
	runID, idempotencyKey, err := nextProjectionRunIdentity(store, projectionVersion)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	run := catalog.SyncRun{
		RunID: runID, Scope: scope, SourceSnapshot: snapshot.Ref(),
		BaseProjectionVersion: current.Version, ProjectionVersion: projectionVersion,
		IdempotencyKey: idempotencyKey, Reconciliation: catalog.ReconciliationFull,
		State: catalog.RunStaged,
	}
	build.plan, err = catalog.PlanResources(run, current, resources)
	if err != nil {
		return repository.ArtifactSet{}, projectionBuild{}, err
	}
	return set, build, nil
}

func projectionJournalRoot(root, baseVersion, projectionVersion string) string {
	return filepath.Join(root, "by-base", baseVersion, "successors", projectionVersion)
}

func (s service) selectedBaseProjection(ctx context.Context, scope catalog.Scope) (catalog.Projection, error) {
	data, err := s.repo.ReadCurrentProjection(ctx)
	if err == nil {
		var projection catalog.Projection
		if err := json.Unmarshal(data, &projection); err != nil {
			return catalog.Projection{}, fmt.Errorf("decode selected artifact projection: %w", err)
		}
		if err := projection.Validate(); err != nil {
			return catalog.Projection{}, fmt.Errorf("validate selected artifact projection: %w", err)
		}
		if projection.Scope == scope {
			return projection, nil
		}
	} else if !errors.Is(err, repository.ErrArtifactCurrentNotFound) {
		return catalog.Projection{}, err
	}
	return emptyBaseProjection(scope)
}

func emptyBaseProjection(scope catalog.Scope) (catalog.Projection, error) {
	emptySnapshot, err := catalog.NewSourceSnapshot(scope, "workspace", "source-empty", localSecurityDomain, nil)
	if err != nil {
		return catalog.Projection{}, err
	}
	emptyVersion := "projection-empty-" + fullHash([]byte(scope.TenantID + "\x00" + scope.KnowledgeBaseID))[:24]
	return catalog.NewProjection(scope, emptyVersion, emptySnapshot.Ref(), catalog.StatePublished, nil)
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

func canonicalProjectionVersion(
	scope catalog.Scope,
	snapshot catalog.SourceSnapshotRef,
	aclVersion string,
	buildConfigVersion string,
) (string, error) {
	payload := struct {
		Schema      string                    `json:"schema"`
		Scope       catalog.Scope             `json:"scope"`
		Snapshot    catalog.SourceSnapshotRef `json:"source_snapshot"`
		ACL         string                    `json:"acl_version"`
		BuildConfig string                    `json:"build_config_version"`
		Index       string                    `json:"index_version"`
		Graph       string                    `json:"graph_version"`
	}{
		Schema: projectionSchema, Scope: scope, Snapshot: snapshot, ACL: aclVersion,
		BuildConfig: buildConfigVersion, Index: "index-v1", Graph: "graph-v1",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "prj_" + fullHash(data)[:32], nil
}

func kagBuildConfigVersion(workspace string, cfg repository.Config) (string, error) {
	configDigest := "generated-config-v1"
	configIdentity := "generated"
	resourceDigest := "generated-resources-v1"
	var configPath string
	if strings.TrimSpace(cfg.KAG.ConfigPath) != "" {
		configPath = cfg.KAG.ConfigPath
		if !filepath.IsAbs(configPath) {
			configPath = filepath.Join(workspace, configPath)
		}
	} else {
		for _, candidate := range []string{
			filepath.Join(workspace, ".knote", "kag_config.yaml"),
			filepath.Join(workspace, "kag_config.yaml"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				configPath = candidate
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
	}
	if configPath != "" {
		data, err := readBoundedFile(configPath, maxKAGResourceFileBytes)
		if err != nil {
			return "", fmt.Errorf("read KAG build config: %w", err)
		}
		configDigest = fullHash(data)
		configIdentity, resourceDigest, err = kagConfigResourceDigest(workspace, configPath, cfg.KAG.RuntimeDir)
		if err != nil {
			return "", err
		}
	}
	payload := struct {
		Host           string                             `json:"host"`
		Fake           bool                               `json:"fake"`
		ProjectID      string                             `json:"project_id"`
		Namespace      string                             `json:"namespace"`
		Language       string                             `json:"language"`
		RuntimeDir     string                             `json:"runtime_dir"`
		ConfigIdentity string                             `json:"config_identity"`
		ConfigDigest   string                             `json:"config_digest"`
		ResourceDigest string                             `json:"resource_digest"`
		Models         map[string]repository.ModelProfile `json:"models"`
	}{
		Host: cfg.KAG.Host, Fake: cfg.KAG.Fake, ProjectID: cfg.KAG.ProjectID,
		Namespace: cfg.KAG.Namespace, Language: cfg.KAG.Language,
		RuntimeDir:     canonicalKAGRuntimeDir(workspace, cfg.KAG.RuntimeDir),
		ConfigIdentity: configIdentity, ConfigDigest: configDigest,
		ResourceDigest: resourceDigest, Models: cfg.Models,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "build_" + fullHash(data)[:24], nil
}

type kagResourceDigestEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

func kagConfigResourceDigest(workspace, configPath, runtimeDir string) (string, string, error) {
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve KAG config path: %w", err)
	}
	resourceRoot := filepath.Dir(configPath)
	identity := canonicalKAGConfigIdentity(workspace, configPath)
	excludedRoots, err := kagGeneratedResourceRoots(workspace, runtimeDir)
	if err != nil {
		return "", "", err
	}
	effectiveExclusions := make([]string, 0, len(excludedRoots))
	sourceRoot, err := filepath.Abs(filepath.Join(workspace, "sources"))
	if err != nil {
		return "", "", fmt.Errorf("resolve source root: %w", err)
	}
	for _, root := range excludedRoots {
		if pathWithin(root, configPath) {
			if filepath.Clean(root) == filepath.Clean(sourceRoot) {
				continue
			}
			return "", "", fmt.Errorf("KAG config must be outside generated/runtime directory %s", root)
		}
		if pathWithin(resourceRoot, root) {
			effectiveExclusions = append(effectiveExclusions, root)
		}
	}

	entries := make([]kagResourceDigestEntry, 0)
	var totalBytes int64
	err = filepath.WalkDir(resourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		for _, root := range effectiveExclusions {
			if pathWithin(root, path) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "__pycache__", ".pytest_cache", ".mypy_cache":
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("KAG config resource %s is a symlink", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("KAG config resource %s is not a regular file", path)
		}
		if len(entries) >= maxKAGResourceFiles {
			return fmt.Errorf("KAG config resources exceed %d files", maxKAGResourceFiles)
		}
		if info.Size() > maxKAGResourceFileBytes {
			return fmt.Errorf("KAG config resource %s exceeds %d bytes", path, maxKAGResourceFileBytes)
		}
		if totalBytes+info.Size() > maxKAGResourceBytes {
			return fmt.Errorf("KAG config resources exceed %d bytes", maxKAGResourceBytes)
		}
		data, err := readBoundedFile(path, maxKAGResourceFileBytes)
		if err != nil {
			return err
		}
		totalBytes += int64(len(data))
		if totalBytes > maxKAGResourceBytes {
			return fmt.Errorf("KAG config resources exceed %d bytes", maxKAGResourceBytes)
		}
		relative, err := filepath.Rel(resourceRoot, path)
		if err != nil {
			return err
		}
		entries = append(entries, kagResourceDigestEntry{
			Path: filepath.ToSlash(relative), Size: int64(len(data)), Digest: fullHash(data),
		})
		return nil
	})
	if err != nil {
		return "", "", fmt.Errorf("digest KAG config resources: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	payload, err := json.Marshal(struct {
		Schema  string                   `json:"schema"`
		Entries []kagResourceDigestEntry `json:"entries"`
	}{Schema: "kag-config-resources-v1", Entries: entries})
	if err != nil {
		return "", "", err
	}
	return identity, fullHash(payload), nil
}

func canonicalKAGConfigIdentity(workspace, configPath string) string {
	workspace, workspaceErr := filepath.Abs(workspace)
	configPath, configErr := filepath.Abs(configPath)
	if workspaceErr == nil && configErr == nil {
		if relative, err := filepath.Rel(workspace, configPath); err == nil &&
			relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(relative)
		}
	}
	return filepath.ToSlash(configPath)
}

func kagGeneratedResourceRoots(workspace, runtimeDir string) ([]string, error) {
	workspace, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace path: %w", err)
	}
	if strings.TrimSpace(runtimeDir) == "" {
		runtimeDir = filepath.Join(".knote", "kag-runtime")
	}
	if !filepath.IsAbs(runtimeDir) {
		runtimeDir = filepath.Join(workspace, runtimeDir)
	}
	runtimeDir, err = filepath.Abs(runtimeDir)
	if err != nil {
		return nil, fmt.Errorf("resolve KAG runtime path: %w", err)
	}
	roots := []string{
		filepath.Join(workspace, ".git"),
		filepath.Join(workspace, "sources"),
		filepath.Join(workspace, "artifacts"),
		filepath.Join(workspace, ".knote", "projections"),
		filepath.Join(workspace, ".knote", "sessions"),
		filepath.Join(workspace, ".knote", "cache"),
		filepath.Join(workspace, ".knote", "checkpoints"),
		filepath.Join(workspace, "evals", "report.md"),
		filepath.Join(workspace, "evals", "results.jsonl"),
		runtimeDir,
	}
	sort.Strings(roots)
	return roots, nil
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("KAG config resource %s exceeds %d bytes", path, limit)
	}
	return data, nil
}

func canonicalKAGRuntimeDir(workspace, runtimeDir string) string {
	runtimeDir = strings.TrimSpace(runtimeDir)
	if runtimeDir == "" {
		runtimeDir = filepath.Join(".knote", "kag-runtime")
	}
	runtimeDir = filepath.Clean(runtimeDir)
	if !filepath.IsAbs(runtimeDir) {
		return filepath.ToSlash(runtimeDir)
	}
	workspace = filepath.Clean(workspace)
	if filepath.IsAbs(workspace) {
		if relative, err := filepath.Rel(workspace, runtimeDir); err == nil &&
			relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(relative)
		}
	}
	return filepath.ToSlash(runtimeDir)
}

func nextProjectionRunIdentity(store *catalog.ProjectionStore, projectionVersion string) (string, string, error) {
	for attempt := 0; attempt < 10_000; attempt++ {
		suffix := ""
		if attempt > 0 {
			suffix = fmt.Sprintf("-retry-%d", attempt)
		}
		runID := "run-" + projectionVersion + suffix
		idempotencyKey := "sync-" + projectionVersion + suffix
		run, err := store.Run(runID)
		if errors.Is(err, os.ErrNotExist) {
			return runID, idempotencyKey, nil
		}
		if err != nil {
			return "", "", err
		}
		if run.State != catalog.RunFailed {
			return runID, idempotencyKey, nil
		}
	}
	return "", "", fmt.Errorf("projection %s exceeded retry limit", projectionVersion)
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

func projectionKAGBuildIdempotencyKey(projectionVersion string) string {
	return "kag-build-" + projectionVersion
}

func (s service) executeProjectionBuild(ctx context.Context, artifacts repository.ArtifactSet, build projectionBuild) (map[string]any, error) {
	if s.backend == nil {
		return nil, fmt.Errorf("KAG build failed: KAG backend is not configured")
	}
	if err := s.verifySelectedBaseProjection(ctx, build.base); err != nil {
		return nil, err
	}
	if build.noop {
		response, err := s.buildPreparedKAGCorpus(ctx, artifacts, build.corpus)
		if err != nil {
			return nil, err
		}
		if err := s.repo.StageArtifacts(ctx, artifacts); err != nil {
			return nil, err
		}
		if err := s.verifySelectedBaseProjection(ctx, build.base); err != nil {
			return nil, err
		}
		if err := s.repo.PublishArtifacts(ctx, artifacts.BundleManifest); err != nil {
			return nil, err
		}
		data := cloneMap(response.Data)
		if data == nil {
			data = make(map[string]any)
		}
		data["projection_version"] = artifacts.BundleManifest.ProjectionVersion
		data["idempotent_noop"] = true
		return data, nil
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
				response, err := s.buildPreparedKAGCorpus(ctx, artifacts, build.corpus)
				if err != nil {
					operationErr = err
					return catalog.OperationResult{}, operationErr
				}
				buildData = cloneMap(response.Data)
				kagBuilt = true
			}
		case catalog.OperationProjectArtifact:
			if !artifactsStaged {
				if err := s.repo.StageArtifacts(ctx, artifacts); err != nil {
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
	if err := s.verifySelectedBaseProjection(ctx, build.base); err != nil {
		return nil, err
	}
	if err := s.repo.PublishArtifacts(ctx, artifacts.BundleManifest); err != nil {
		return nil, fmt.Errorf("publish artifact serving pointer: %w", err)
	}
	return buildData, nil
}

func (s service) buildPreparedKAGCorpus(ctx context.Context, artifacts repository.ArtifactSet, corpus []kag.CorpusRecord) (kag.Response, error) {
	response, err := s.backend.BuildInNamespaceWithCorpus(
		ctx,
		artifacts.BundleManifest.Namespace,
		projectionKAGBuildIdempotencyKey(artifacts.BundleManifest.ProjectionVersion),
		corpus,
	)
	if err != nil {
		return kag.Response{}, fmt.Errorf("KAG build failed: %w", err)
	}
	return response, nil
}

func (s service) verifySelectedBaseProjection(ctx context.Context, expected catalog.Projection) error {
	selected, err := s.selectedBaseProjection(ctx, expected.Scope)
	if err != nil {
		return err
	}
	if selected.Scope != expected.Scope || selected.Version != expected.Version {
		return fmt.Errorf(
			"public projection base changed from %s to %s: %w",
			expected.Version, selected.Version, catalog.ErrStaleServingPointer,
		)
	}
	return nil
}
