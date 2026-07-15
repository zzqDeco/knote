package authorized

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

// DiscoverDerivedArtifact reads only selected manifest and projection bytes.
// Every failure is intentionally indistinguishable to callers.
func (l *BundleEvidenceLoader) DiscoverDerivedArtifact(
	ctx context.Context,
	resourceID protocol.ResourceID,
) (DerivedArtifactMetadata, error) {
	metadata, err := l.discoverDerivedArtifact(ctx, resourceID)
	if err != nil {
		return DerivedArtifactMetadata{}, ErrProtectedContentUnavailable
	}
	return metadata, nil
}

func (l *BundleEvidenceLoader) discoverDerivedArtifact(
	ctx context.Context,
	resourceID protocol.ResourceID,
) (DerivedArtifactMetadata, error) {
	if l == nil || l.reader == nil || ctx == nil {
		return DerivedArtifactMetadata{}, fmt.Errorf("derived artifact metadata loader is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return DerivedArtifactMetadata{}, err
	}
	if err := resourceID.Validate(); err != nil {
		return DerivedArtifactMetadata{}, err
	}
	selected, err := l.reader.ReadCurrentArtifactMetadata(ctx)
	if err != nil {
		return DerivedArtifactMetadata{}, err
	}
	return discoverDerivedArtifactFromSelected(selected, resourceID)
}

// LoadDerivedArtifact reads the full selected bundle only after its caller has
// authorized the exact discovery contract. Before returning content it repeats
// metadata discovery to detect a concurrent serving-pointer change.
func (l *BundleEvidenceLoader) LoadDerivedArtifact(
	ctx context.Context,
	metadata DerivedArtifactMetadata,
) (protocol.EvidenceItem, error) {
	item, err := l.loadDerivedArtifact(ctx, metadata)
	if err != nil {
		return protocol.EvidenceItem{}, ErrProtectedContentUnavailable
	}
	return item, nil
}

func (l *BundleEvidenceLoader) loadDerivedArtifact(
	ctx context.Context,
	metadata DerivedArtifactMetadata,
) (protocol.EvidenceItem, error) {
	if l == nil || l.reader == nil || ctx == nil {
		return protocol.EvidenceItem{}, fmt.Errorf("derived artifact body loader is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return protocol.EvidenceItem{}, err
	}
	if err := metadata.Validate(); err != nil {
		return protocol.EvidenceItem{}, err
	}
	if metadata.SecurityRecord.Kind != string(protocol.DerivedArtifactSummary) {
		return protocol.EvidenceItem{}, fmt.Errorf("selected bundle has no supported derived artifact body")
	}

	snapshot, err := l.reader.ReadCurrentArtifactBundle(ctx)
	if err != nil {
		return protocol.EvidenceItem{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return protocol.EvidenceItem{}, err
	}
	projectionJSON, ok := snapshot.Files["projection.json"]
	if !ok {
		return protocol.EvidenceItem{}, fmt.Errorf("selected bundle projection is missing")
	}
	bundleMetadata, err := discoverDerivedArtifactFromSelected(repository.SelectedArtifactMetadata{
		Manifest: snapshot.Manifest, ProjectionJSON: projectionJSON,
	}, metadata.Artifact.ResourceID)
	if err != nil || !reflect.DeepEqual(bundleMetadata, metadata) {
		return protocol.EvidenceItem{}, fmt.Errorf("selected bundle does not match authorized derived metadata")
	}

	summaries, err := decodeResourceJSONL[protocol.Summary](
		snapshot.Files["summaries.jsonl"],
		func(summary protocol.Summary) string { return summary.SummaryID },
	)
	if err != nil {
		return protocol.EvidenceItem{}, err
	}
	summary, ok := summaries[metadata.Artifact.ResourceID]
	if !ok || summary.SummaryID != string(metadata.Artifact.ResourceID) {
		return protocol.EvidenceItem{}, fmt.Errorf("selected bundle has no exact summary body")
	}
	if protocol.NewContentDigest(summary.Text) != metadata.Artifact.ContentDigest {
		return protocol.EvidenceItem{}, fmt.Errorf("selected summary body does not match its content digest")
	}
	if !equalDerivedStrings(summary.EvidenceChunkIDs, derivedSummaryChunkIDs(metadata)) {
		return protocol.EvidenceItem{}, fmt.Errorf("selected summary evidence does not match its support identities")
	}
	item := derivedArtifactEvidenceItem(metadata, summary.Text)
	if err := protocol.ValidateProvenance(item.Derivation, item.Supports); err != nil {
		return protocol.EvidenceItem{}, err
	}

	current, err := l.discoverDerivedArtifact(ctx, metadata.Artifact.ResourceID)
	if err != nil || !reflect.DeepEqual(current, metadata) {
		return protocol.EvidenceItem{}, fmt.Errorf("selected derived metadata changed while loading content")
	}
	return item, nil
}

func discoverDerivedArtifactFromSelected(
	selected repository.SelectedArtifactMetadata,
	resourceID protocol.ResourceID,
) (DerivedArtifactMetadata, error) {
	if err := selected.Validate(); err != nil {
		return DerivedArtifactMetadata{}, err
	}
	projection, err := selectedProjection(selected.Manifest, selected.ProjectionJSON)
	if err != nil {
		return DerivedArtifactMetadata{}, err
	}
	resources := make(map[protocol.ResourceID]catalog.ResourceMetadata, len(projection.Resources))
	handles := make(map[protocol.ResourceID]protocol.ResourceHandle, len(projection.Resources))
	for _, metadata := range projection.Resources {
		resources[metadata.ResourceID] = metadata
		if !metadata.IsServing() {
			continue
		}
		handle, err := metadata.ServingHandle()
		if err != nil {
			return DerivedArtifactMetadata{}, err
		}
		handles[metadata.ResourceID] = handle
	}
	resource, ok := resources[resourceID]
	if !ok || resource.Type != protocol.ResourceDerivedArtifact || !resource.IsServing() ||
		resource.DerivedArtifactSecurity == nil {
		return DerivedArtifactMetadata{}, fmt.Errorf("selected projection has no serving derived artifact metadata")
	}
	artifact, ok := handles[resourceID]
	if !ok {
		return DerivedArtifactMetadata{}, fmt.Errorf("selected derived artifact has no serving handle")
	}
	record, err := resource.DerivedArtifactSecurity.Canonical()
	if err != nil {
		return DerivedArtifactMetadata{}, err
	}
	supports := make([]DerivedArtifactSupportMetadata, len(record.Supports))
	for index, support := range record.Supports {
		supports[index] = DerivedArtifactSupportMetadata{
			SupportID: support.SupportID, Complete: support.Complete,
			Resources: make([]protocol.ResourceHandle, len(support.Resources)),
		}
		for resourceIndex, identity := range support.Resources {
			handle, ok := handles[identity.ResourceID]
			if !ok || derivedArtifactIdentity(handle) != identity {
				return DerivedArtifactMetadata{}, fmt.Errorf("derived support identity has no exact serving handle")
			}
			supports[index].Resources[resourceIndex] = handle
		}
	}
	selectionDigest, err := selectedArtifactMetadataDigest(selected)
	if err != nil {
		return DerivedArtifactMetadata{}, err
	}
	metadata := DerivedArtifactMetadata{
		Artifact: artifact, SecurityRecord: record,
		SecurityDomain: resource.SecurityDomain, ProjectionVersion: projection.Version,
		Dependencies: append([]protocol.ResourceID(nil), resource.Dependencies...),
		Supports:     supports, SelectionDigest: selectionDigest,
	}
	if err := metadata.Validate(); err != nil {
		return DerivedArtifactMetadata{}, err
	}
	return metadata, nil
}

func selectedArtifactMetadataDigest(selected repository.SelectedArtifactMetadata) (protocol.ContentDigest, error) {
	manifestJSON, err := json.Marshal(selected.Manifest)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, len(manifestJSON)+1+len(selected.ProjectionJSON))
	payload = append(payload, manifestJSON...)
	payload = append(payload, 0)
	payload = append(payload, selected.ProjectionJSON...)
	return protocol.NewContentDigest(string(payload)), nil
}

func derivedSummaryChunkIDs(metadata DerivedArtifactMetadata) []string {
	seen := make(map[protocol.ResourceID]struct{})
	ids := make([]string, 0)
	for _, support := range metadata.Supports {
		for _, resource := range support.Resources {
			if resource.Type != protocol.ResourceChunk {
				continue
			}
			if _, duplicate := seen[resource.ResourceID]; duplicate {
				continue
			}
			seen[resource.ResourceID] = struct{}{}
			ids = append(ids, string(resource.ResourceID))
		}
	}
	sort.Strings(ids)
	return ids
}
