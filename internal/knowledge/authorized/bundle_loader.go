package authorized

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

// ArtifactAuthorizationScope is the trusted authorization scope bound to the
// currently selected immutable artifact bundle.
type ArtifactAuthorizationScope struct {
	TenantID          string
	KnowledgeBaseID   string
	ACLWatermark      string
	ProjectionVersion string
}

// BundleEvidenceLoader materializes evidence only from a verified selected
// artifact bundle. It intentionally supports only resource kinds whose exact
// content is present in the bundle.
type BundleEvidenceLoader struct {
	reader repository.SelectedArtifactReader
}

func NewBundleEvidenceLoader(reader repository.SelectedArtifactReader) (*BundleEvidenceLoader, error) {
	if reader == nil {
		return nil, fmt.Errorf("selected artifact reader is required")
	}
	return &BundleEvidenceLoader{reader: reader}, nil
}

func (l *BundleEvidenceLoader) CurrentAuthorizationScope(ctx context.Context) (ArtifactAuthorizationScope, error) {
	if l == nil || l.reader == nil {
		return ArtifactAuthorizationScope{}, fmt.Errorf("bundle evidence loader is unavailable")
	}
	if ctx == nil {
		return ArtifactAuthorizationScope{}, fmt.Errorf("bundle authorization scope requires a context")
	}
	if err := ctx.Err(); err != nil {
		return ArtifactAuthorizationScope{}, err
	}
	metadata, err := l.reader.ReadCurrentArtifactMetadata(ctx)
	if err != nil {
		return ArtifactAuthorizationScope{}, fmt.Errorf("read selected artifact metadata: %w", err)
	}
	if err := metadata.Validate(); err != nil {
		return ArtifactAuthorizationScope{}, fmt.Errorf("validate selected artifact metadata: %w", err)
	}
	projection, err := selectedProjection(metadata.Manifest, metadata.ProjectionJSON)
	if err != nil {
		return ArtifactAuthorizationScope{}, err
	}
	return ArtifactAuthorizationScope{
		TenantID:          projection.Scope.TenantID,
		KnowledgeBaseID:   projection.Scope.KnowledgeBaseID,
		ACLWatermark:      metadata.Manifest.AuthorizationVersion,
		ProjectionVersion: projection.Version,
	}, nil
}

func (l *BundleEvidenceLoader) Load(ctx context.Context, handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
	if ctx == nil {
		return nil, fmt.Errorf("bundle evidence load requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, fmt.Errorf("bundle evidence load requires resources")
	}
	index, err := l.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]protocol.EvidenceItem, len(handles))
	for position, requested := range handles {
		selected, ok := index.handles[requested.ResourceID]
		if !ok || selected != requested {
			return nil, fmt.Errorf("resource %s does not match the selected artifact handle", requested.ResourceID)
		}
		item, err := index.evidenceItem(requested)
		if err != nil {
			return nil, err
		}
		if protocol.NewContentDigest(item.Content) != requested.ContentDigest {
			return nil, fmt.Errorf("resource %s content does not match the selected artifact handle", requested.ResourceID)
		}
		items[position] = item
	}
	return items, nil
}

type selectedBundleIndex struct {
	snapshot   repository.SelectedArtifactBundle
	projection catalog.Projection
	metadata   map[protocol.ResourceID]catalog.ResourceMetadata
	handles    map[protocol.ResourceID]protocol.ResourceHandle
	chunks     map[protocol.ResourceID]protocol.Chunk
	entities   map[protocol.ResourceID]protocol.Entity
	claims     map[protocol.ResourceID]protocol.Claim
}

func (l *BundleEvidenceLoader) loadIndex(ctx context.Context) (selectedBundleIndex, error) {
	if l == nil || l.reader == nil {
		return selectedBundleIndex{}, fmt.Errorf("bundle evidence loader is unavailable")
	}
	snapshot, err := l.reader.ReadCurrentArtifactBundle(ctx)
	if err != nil {
		return selectedBundleIndex{}, fmt.Errorf("read selected artifact bundle: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return selectedBundleIndex{}, fmt.Errorf("validate selected artifact bundle: %w", err)
	}
	projection, err := selectedProjection(snapshot.Manifest, snapshot.Files["projection.json"])
	if err != nil {
		return selectedBundleIndex{}, err
	}

	index := selectedBundleIndex{
		snapshot: snapshot, projection: projection,
		metadata: make(map[protocol.ResourceID]catalog.ResourceMetadata, len(projection.Resources)),
		handles:  make(map[protocol.ResourceID]protocol.ResourceHandle, len(projection.Resources)),
	}
	for _, metadata := range projection.Resources {
		if _, duplicate := index.metadata[metadata.ResourceID]; duplicate {
			return selectedBundleIndex{}, fmt.Errorf("selected artifact resource %s is duplicated", metadata.ResourceID)
		}
		index.metadata[metadata.ResourceID] = metadata
		if !metadata.IsServing() {
			continue
		}
		handle, err := metadata.ServingHandle()
		if err != nil {
			return selectedBundleIndex{}, fmt.Errorf("selected artifact resource %s: %w", metadata.ResourceID, err)
		}
		index.handles[metadata.ResourceID] = handle
	}
	if index.chunks, err = decodeResourceJSONL[protocol.Chunk](snapshot.Files["chunks.jsonl"], func(item protocol.Chunk) string { return item.ChunkID }); err != nil {
		return selectedBundleIndex{}, fmt.Errorf("decode selected artifact chunks: %w", err)
	}
	if index.entities, err = decodeResourceJSONL[protocol.Entity](snapshot.Files["entities.jsonl"], func(item protocol.Entity) string { return item.EntityID }); err != nil {
		return selectedBundleIndex{}, fmt.Errorf("decode selected artifact entities: %w", err)
	}
	if index.claims, err = decodeResourceJSONL[protocol.Claim](snapshot.Files["claims.jsonl"], func(item protocol.Claim) string { return item.ClaimID }); err != nil {
		return selectedBundleIndex{}, fmt.Errorf("decode selected artifact claims: %w", err)
	}
	return index, nil
}

func selectedProjection(
	manifest protocol.ArtifactBundleManifest,
	projectionJSON []byte,
) (catalog.Projection, error) {
	if manifest.GraphBindingContractVersion != protocol.GraphBindingContractVersion {
		return catalog.Projection{}, fmt.Errorf("selected artifact graph binding contract is not current")
	}
	var projection catalog.Projection
	if err := json.Unmarshal(projectionJSON, &projection); err != nil {
		return catalog.Projection{}, fmt.Errorf("decode selected artifact projection: %w", err)
	}
	if err := projection.Validate(); err != nil {
		return catalog.Projection{}, fmt.Errorf("validate selected artifact projection: %w", err)
	}
	if projection.Version != manifest.ProjectionVersion || projection.State != catalog.StatePublished {
		return catalog.Projection{}, fmt.Errorf("selected artifact projection does not match the serving manifest")
	}
	for _, metadata := range projection.Resources {
		if metadata.Scope != projection.Scope || metadata.Versions.Projection != projection.Version ||
			metadata.Versions.ACL != manifest.AuthorizationVersion {
			return catalog.Projection{}, fmt.Errorf("selected artifact resource %s crosses the serving revision", metadata.ResourceID)
		}
	}
	return projection, nil
}

func (i selectedBundleIndex) evidenceItem(resource protocol.ResourceHandle) (protocol.EvidenceItem, error) {
	metadata, ok := i.metadata[resource.ResourceID]
	if !ok {
		return protocol.EvidenceItem{}, fmt.Errorf("resource %s is absent from the selected artifact projection", resource.ResourceID)
	}
	var (
		content    string
		derivation = protocol.DerivationAnySupport
		supports   []protocol.ProvenanceSupport
		err        error
	)
	switch resource.Type {
	case protocol.ResourceChunk:
		chunk, ok := i.chunks[resource.ResourceID]
		if !ok {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s has no selected chunk content", resource.ResourceID)
		}
		if protocol.ResourceID(chunk.DocumentID) != metadata.AuthorizationResourceID ||
			!sameResourceIDs(metadata.Dependencies, []protocol.ResourceID{metadata.AuthorizationResourceID}) {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s chunk provenance differs from projection", resource.ResourceID)
		}
		content = chunk.Text
		supports, err = i.supportsFromIDs("chunk", []string{chunk.DocumentID})
	case protocol.ResourceEntity:
		entity, ok := i.entities[resource.ResourceID]
		if !ok {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s has no selected entity content", resource.ResourceID)
		}
		if !sameResourceIDs(metadata.Dependencies, stringResourceIDs(entity.EvidenceChunkIDs)) {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s entity provenance differs from projection", resource.ResourceID)
		}
		content = entity.Name
		supports, err = i.supportsFromIDs("entity", entity.EvidenceChunkIDs)
	case protocol.ResourceClaim:
		claim, ok := i.claims[resource.ResourceID]
		if !ok {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s has no selected claim content", resource.ResourceID)
		}
		if metadata.ClaimRecord == nil || !metadata.ClaimRecord.IsSourceBacked() {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s has no source-backed claim record", resource.ResourceID)
		}
		if !sameResourceIDs(stringResourceIDs(claim.EvidenceChunkIDs), claimEvidenceResourceIDs(*metadata.ClaimRecord)) {
			return protocol.EvidenceItem{}, fmt.Errorf("resource %s claim provenance differs from projection", resource.ResourceID)
		}
		content = claim.Text
		derivation = metadata.ClaimRecord.Provenance.DerivationMode
		supports, err = i.claimSupports(*metadata.ClaimRecord)
	default:
		return protocol.EvidenceItem{}, fmt.Errorf("resource %s has no loadable content in the selected artifact bundle", resource.ResourceID)
	}
	if err != nil {
		return protocol.EvidenceItem{}, fmt.Errorf("resource %s provenance: %w", resource.ResourceID, err)
	}
	item := protocol.EvidenceItem{
		Resource: resource, Content: content, Derivation: derivation, Supports: supports,
		Citation: protocol.Citation{Handle: "artifact-" + string(resource.ResourceID), Resource: resource},
	}
	if err := protocol.ValidateProvenance(item.Derivation, item.Supports); err != nil {
		return protocol.EvidenceItem{}, fmt.Errorf("resource %s provenance: %w", resource.ResourceID, err)
	}
	return item, nil
}

func (i selectedBundleIndex) supportsFromIDs(prefix string, ids []string) ([]protocol.ProvenanceSupport, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("evidence resources are required")
	}
	ordered := append([]string(nil), ids...)
	sort.Strings(ordered)
	supports := make([]protocol.ProvenanceSupport, len(ordered))
	for position, value := range ordered {
		if position > 0 && ordered[position-1] == value {
			return nil, fmt.Errorf("evidence resource %s is duplicated", value)
		}
		id := protocol.ResourceID(value)
		handle, ok := i.handles[id]
		if !ok {
			return nil, fmt.Errorf("evidence resource %s is not serving in the selected projection", value)
		}
		supports[position] = protocol.ProvenanceSupport{
			SupportID: prefix + "-" + value, Resource: handle,
			Evidence: []protocol.ResourceHandle{handle}, Complete: true,
		}
	}
	return supports, nil
}

func (i selectedBundleIndex) claimSupports(record catalog.ClaimProjectionRecord) ([]protocol.ProvenanceSupport, error) {
	document, ok := i.handles[record.SourceDocument.ResourceID]
	if !ok || document.Type != protocol.ResourceDocument {
		return nil, fmt.Errorf("claim source document is not serving")
	}
	supports := make([]protocol.ProvenanceSupport, len(record.Provenance.Supports))
	for position, support := range record.Provenance.Supports {
		evidence := make([]protocol.ResourceHandle, len(support.Evidence))
		for evidencePosition, ref := range support.Evidence {
			handle, ok := i.handles[ref.ResourceID]
			if !ok || handle.Type != ref.Type || handle.Versions != ref.Versions {
				return nil, fmt.Errorf("claim support %s does not match selected evidence", support.SupportID)
			}
			evidence[evidencePosition] = handle
		}
		supports[position] = protocol.ProvenanceSupport{
			SupportID: support.SupportID, Resource: document,
			Evidence: evidence, Complete: support.Complete,
		}
	}
	return supports, nil
}

func decodeResourceJSONL[T any](data []byte, key func(T) string) (map[protocol.ResourceID]T, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	items := make(map[protocol.ResourceID]T)
	for {
		var item T
		if err := decoder.Decode(&item); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		value := key(item)
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return nil, fmt.Errorf("resource id is invalid")
		}
		id := protocol.ResourceID(value)
		if err := id.Validate(); err != nil {
			return nil, err
		}
		if _, duplicate := items[id]; duplicate {
			return nil, fmt.Errorf("resource %s is duplicated", id)
		}
		items[id] = item
	}
	return items, nil
}

func stringResourceIDs(values []string) []protocol.ResourceID {
	ids := make([]protocol.ResourceID, len(values))
	for index, value := range values {
		ids[index] = protocol.ResourceID(value)
	}
	return ids
}

func claimEvidenceResourceIDs(record catalog.ClaimProjectionRecord) []protocol.ResourceID {
	set := make(map[protocol.ResourceID]struct{})
	for _, support := range record.Provenance.Supports {
		for _, evidence := range support.Evidence {
			set[evidence.ResourceID] = struct{}{}
		}
	}
	ids := make([]protocol.ResourceID, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func sameResourceIDs(left, right []protocol.ResourceID) bool {
	left = append([]protocol.ResourceID(nil), left...)
	right = append([]protocol.ResourceID(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i] < left[j] })
	sort.Slice(right, func(i, j int) bool { return right[i] < right[j] })
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] || (index > 0 && left[index-1] == left[index]) {
			return false
		}
	}
	return true
}
