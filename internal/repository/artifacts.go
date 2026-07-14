package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	ErrArtifactCurrentNotFound    = errors.New("artifact current pointer not found")
	ErrArtifactProjectionMismatch = errors.New("artifact projection mismatch")
)

type ArtifactFilePayload struct {
	Descriptor protocol.ArtifactBundleFile
	Data       []byte
}

// CanonicalArtifactFiles returns the exact bytes used by both immutable v2
// bundles and flat v1 compatibility exports.
func CanonicalArtifactFiles(set ArtifactSet) ([]ArtifactFilePayload, error) {
	documents := append([]protocol.Document(nil), set.Documents...)
	chunks := append([]protocol.Chunk(nil), set.Chunks...)
	entities := append([]protocol.Entity(nil), set.Entities...)
	relations := append([]protocol.Relation(nil), set.Relations...)
	claims := append([]protocol.Claim(nil), set.Claims...)
	graphBindings := append([]protocol.GraphResourceBinding(nil), set.GraphBindings...)
	claimBindings := append([]protocol.ClaimTripleBinding(nil), set.ClaimBindings...)
	summaries := append([]protocol.Summary(nil), set.Summaries...)
	sort.Slice(documents, func(i, j int) bool {
		if documents[i].DocumentID != documents[j].DocumentID {
			return documents[i].DocumentID < documents[j].DocumentID
		}
		return documents[i].Path < documents[j].Path
	})
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].ChunkID < chunks[j].ChunkID })
	sort.Slice(entities, func(i, j int) bool { return entities[i].EntityID < entities[j].EntityID })
	sort.Slice(relations, func(i, j int) bool { return relations[i].RelationID < relations[j].RelationID })
	sort.Slice(claims, func(i, j int) bool { return claims[i].ClaimID < claims[j].ClaimID })
	protocol.SortGraphResourceBindings(graphBindings)
	protocol.SortClaimTripleBindings(claimBindings)
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].SummaryID < summaries[j].SummaryID })
	if set.BundleManifest.GraphBindingContractVersion == 0 && (len(graphBindings) != 0 || len(claimBindings) != 0) {
		return nil, fmt.Errorf("graph bindings require a declared graph binding contract version")
	}
	if set.BundleManifest.GraphBindingContractVersion != 0 {
		if set.BundleManifest.GraphBindingContractVersion != protocol.GraphBindingContractVersion {
			return nil, fmt.Errorf(
				"unsupported graph binding contract version %d",
				set.BundleManifest.GraphBindingContractVersion,
			)
		}
		if len(graphBindings) == 0 {
			return nil, ErrArtifactProjectionMismatch
		}
		if err := protocol.ValidateGraphResourceBindings(graphBindings); err != nil {
			return nil, ErrArtifactProjectionMismatch
		}
		versions := graphBindings[0].Resource.Versions
		if versions.Source != set.BundleManifest.SourceSnapshot.Version {
			return nil, fmt.Errorf("graph binding source version does not match bundle manifest")
		}
		if versions.ACL != set.BundleManifest.AuthorizationVersion {
			return nil, fmt.Errorf("graph binding ACL version does not match bundle manifest")
		}
		if versions.Projection != set.BundleManifest.ProjectionVersion {
			return nil, fmt.Errorf("graph binding projection version does not match bundle manifest")
		}
		if err := protocol.ValidateClaimTripleBindings(graphBindings, claimBindings); err != nil {
			return nil, ErrArtifactProjectionMismatch
		}
		if err := validateGraphArtifactProjection(
			set.BundleManifest,
			set.ProjectionJSON,
			set.ProjectionResourceCount,
			claims,
			graphBindings,
			claimBindings,
		); err != nil {
			return nil, ErrArtifactProjectionMismatch
		}
	}

	type jsonlFile struct {
		name  string
		value any
		count int
	}
	jsonl := []jsonlFile{
		{name: "claims.jsonl", value: claims, count: len(claims)},
		{name: "chunks.jsonl", value: chunks, count: len(chunks)},
		{name: "documents.jsonl", value: documents, count: len(documents)},
		{name: "entities.jsonl", value: entities, count: len(entities)},
		{name: "relations.jsonl", value: relations, count: len(relations)},
		{name: "summaries.jsonl", value: summaries, count: len(summaries)},
	}
	if set.BundleManifest.GraphBindingContractVersion != 0 {
		jsonl = append(jsonl,
			jsonlFile{name: protocol.GraphBindingsArtifactPath, value: graphBindings, count: len(graphBindings)},
			jsonlFile{name: protocol.ClaimBindingsArtifactPath, value: claimBindings, count: len(claimBindings)},
		)
	}
	payloads := make([]ArtifactFilePayload, 0, len(jsonl)+2)
	for _, file := range jsonl {
		data, err := marshalJSONL(file.value)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", file.name, err)
		}
		payloads = append(payloads, artifactPayload(file.name, file.count, data))
	}
	defaultSchema := defaultArtifactSchemaYAML
	if set.BundleManifest.GraphBindingContractVersion != 0 {
		defaultSchema = defaultGraphArtifactSchemaYAML
	}
	schema := firstArtifactText(set.SchemaYAML, defaultSchema)
	payloads = append(payloads,
		artifactPayload("build_report.md", 1, []byte(set.BuildReport)),
		artifactPayload("schema.yaml", 1, []byte(schema)),
	)
	if set.BundleManifest.Version != 0 {
		payloads = append(payloads, artifactPayload("projection.json", set.ProjectionResourceCount, set.ProjectionJSON))
	}
	sort.Slice(payloads, func(i, j int) bool { return payloads[i].Descriptor.Path < payloads[j].Descriptor.Path })
	return payloads, nil
}

// ValidateGraphArtifactPayloads cross-validates the body-free graph files
// against projection.json after ordinary manifest digest validation succeeds.
// It intentionally returns one generic error class for all content failures.
func ValidateGraphArtifactPayloads(
	manifest protocol.ArtifactBundleManifest,
	files map[string][]byte,
) error {
	if manifest.GraphBindingContractVersion == 0 {
		return nil
	}
	if !protocol.IsSupportedGraphBindingContractVersion(manifest.GraphBindingContractVersion) {
		return ErrArtifactProjectionMismatch
	}
	claims, err := decodeJSONL[protocol.Claim](files["claims.jsonl"])
	if err != nil {
		return ErrArtifactProjectionMismatch
	}
	graphBindings, err := decodeJSONL[protocol.GraphResourceBinding](files[protocol.GraphBindingsArtifactPath])
	if err != nil {
		return ErrArtifactProjectionMismatch
	}
	if len(graphBindings) == 0 {
		return ErrArtifactProjectionMismatch
	}
	claimBindings, err := decodeJSONL[protocol.ClaimTripleBinding](files[protocol.ClaimBindingsArtifactPath])
	if err != nil {
		return ErrArtifactProjectionMismatch
	}
	graphBindingCount := len(graphBindings)
	claimBindingCount := len(claimBindings)
	if manifest.GraphBindingContractVersion == protocol.GraphBindingContractVersionV1 {
		graphBindings, claimBindings, err = protocol.UpgradeGraphBindingContract(graphBindings, claimBindings)
		if err != nil {
			return ErrArtifactProjectionMismatch
		}
	}
	projection, projectionErr := decodeProjection(files["projection.json"])
	projectionResourceCount := len(projection.Resources)
	if projectionErr != nil {
		projectionResourceCount = len(graphBindings)
		if err := validateLegacyGraphArtifactProjection(
			manifest, files["projection.json"], claims, graphBindings, claimBindings,
		); err != nil {
			return ErrArtifactProjectionMismatch
		}
	}
	counts := map[string]int{
		"projection.json":                  projectionResourceCount,
		"claims.jsonl":                     len(claims),
		protocol.GraphBindingsArtifactPath: graphBindingCount,
		protocol.ClaimBindingsArtifactPath: claimBindingCount,
	}
	for _, descriptor := range manifest.Files {
		if count, ok := counts[descriptor.Path]; ok && descriptor.Count != count {
			return ErrArtifactProjectionMismatch
		}
	}
	if projectionErr == nil {
		if err := validateDecodedGraphArtifactProjection(manifest, projection, claims, graphBindings, claimBindings); err != nil {
			return ErrArtifactProjectionMismatch
		}
	}
	return nil
}

func validateGraphArtifactProjection(
	manifest protocol.ArtifactBundleManifest,
	projectionData []byte,
	projectionResourceCount int,
	claims []protocol.Claim,
	graphBindings []protocol.GraphResourceBinding,
	claimBindings []protocol.ClaimTripleBinding,
) error {
	projection, err := decodeProjection(projectionData)
	if err != nil {
		if legacyErr := validateLegacyGraphArtifactProjection(
			manifest, projectionData, claims, graphBindings, claimBindings,
		); legacyErr != nil {
			return fmt.Errorf("decode projection: %w", err)
		}
		if len(graphBindings) != projectionResourceCount {
			return fmt.Errorf("legacy projection resource count differs")
		}
		return nil
	}
	if len(projection.Resources) != projectionResourceCount {
		return fmt.Errorf("projection resource count differs")
	}
	return validateDecodedGraphArtifactProjection(manifest, projection, claims, graphBindings, claimBindings)
}

func validateLegacyGraphArtifactProjection(
	manifest protocol.ArtifactBundleManifest,
	projectionData []byte,
	claims []protocol.Claim,
	graphBindings []protocol.GraphResourceBinding,
	claimBindings []protocol.ClaimTripleBinding,
) error {
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(projectionData))
	if err := decoder.Decode(&envelope); err != nil || len(envelope) != 1 {
		return ErrArtifactProjectionMismatch
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ErrArtifactProjectionMismatch
	}
	var version string
	if data, ok := envelope["version"]; !ok || json.Unmarshal(data, &version) != nil ||
		version != manifest.ProjectionVersion {
		return ErrArtifactProjectionMismatch
	}
	if manifest.GraphBindingContractVersion != protocol.GraphBindingContractVersionV1 {
		return ErrArtifactProjectionMismatch
	}
	if len(graphBindings) == 0 || len(claimBindings) != 0 ||
		protocol.ValidateGraphResourceBindings(graphBindings) != nil {
		return ErrArtifactProjectionMismatch
	}
	versions := graphBindings[0].Resource.Versions
	if versions.Source != manifest.SourceSnapshot.Version || versions.ACL != manifest.AuthorizationVersion ||
		versions.Projection != manifest.ProjectionVersion {
		return ErrArtifactProjectionMismatch
	}
	graphClaimIDs := make([]string, 0)
	for _, binding := range graphBindings {
		if binding.Resource.Type == protocol.ResourceClaim {
			graphClaimIDs = append(graphClaimIDs, string(binding.Resource.ResourceID))
		}
	}
	sort.Strings(graphClaimIDs)
	claimIDs := make([]string, len(claims))
	for index, claim := range claims {
		claimIDs[index] = claim.ClaimID
	}
	if !reflect.DeepEqual(claimIDs, graphClaimIDs) || manifest.Compatibility.ClaimCount != len(claims) {
		return ErrArtifactProjectionMismatch
	}
	return nil
}

func validateDecodedGraphArtifactProjection(
	manifest protocol.ArtifactBundleManifest,
	projection catalog.Projection,
	claims []protocol.Claim,
	graphBindings []protocol.GraphResourceBinding,
	claimBindings []protocol.ClaimTripleBinding,
) error {
	if projection.Version != manifest.ProjectionVersion ||
		projection.SourceSnapshot.Version != manifest.SourceSnapshot.Version ||
		projection.SourceSnapshot.Digest != protocol.ContentDigest("sha256:"+manifest.SourceSnapshot.Digest) ||
		graphBindings[0].Resource.Versions.ACL != manifest.AuthorizationVersion ||
		projection.SourceSnapshot.DocumentCount != manifest.SourceSnapshot.DocumentCount {
		return fmt.Errorf("projection identity differs from manifest")
	}
	var err error
	if manifest.GraphBindingContractVersion == protocol.GraphBindingContractVersionV1 {
		err = validateUpgradedV1ProjectionGraphBindings(projection, graphBindings, claimBindings)
	} else {
		err = catalog.ValidateProjectionGraphBindings(projection, graphBindings, claimBindings)
	}
	if err != nil {
		return fmt.Errorf("graph bindings: %w", err)
	}
	expectedClaimIDs := make([]string, 0)
	for _, resource := range projection.Resources {
		if resource.IsServing() && resource.Type == protocol.ResourceClaim {
			expectedClaimIDs = append(expectedClaimIDs, string(resource.ResourceID))
		}
	}
	sort.Strings(expectedClaimIDs)
	actualClaimIDs := make([]string, len(claims))
	for index, claim := range claims {
		actualClaimIDs[index] = claim.ClaimID
		if index > 0 && actualClaimIDs[index-1] >= actualClaimIDs[index] {
			return fmt.Errorf("claim artifacts are not sorted")
		}
	}
	if !reflect.DeepEqual(actualClaimIDs, expectedClaimIDs) ||
		manifest.Compatibility.ClaimCount != len(claims) {
		return fmt.Errorf("claim artifacts differ from projection")
	}
	return nil
}

func validateUpgradedV1ProjectionGraphBindings(
	projection catalog.Projection,
	graphBindings []protocol.GraphResourceBinding,
	claimBindings []protocol.ClaimTripleBinding,
) error {
	expectedGraph, err := legacyV1ProjectionGraphBindings(projection)
	if err != nil || !reflect.DeepEqual(expectedGraph, graphBindings) {
		return ErrArtifactProjectionMismatch
	}
	_, expectedClaims, err := catalog.ProjectionGraphBindings(projection)
	if err != nil {
		return ErrArtifactProjectionMismatch
	}
	if len(expectedClaims) != len(claimBindings) {
		return ErrArtifactProjectionMismatch
	}
	for index := range expectedClaims {
		expected := expectedClaims[index]
		actual := claimBindings[index]
		expected.Supports = nil
		actual.Supports = nil
		if !reflect.DeepEqual(expected, actual) {
			return ErrArtifactProjectionMismatch
		}
	}
	return nil
}

func legacyV1ProjectionGraphBindings(projection catalog.Projection) ([]protocol.GraphResourceBinding, error) {
	bindings := make([]protocol.GraphResourceBinding, 0, len(projection.Resources))
	for _, resource := range projection.Resources {
		if !resource.IsServing() {
			continue
		}
		handle, err := resource.ServingHandle()
		if err != nil {
			return nil, err
		}
		binding, err := protocol.NewGraphResourceBinding(handle)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	protocol.SortGraphResourceBindings(bindings)
	if err := protocol.ValidateGraphResourceBindings(bindings); err != nil {
		return nil, err
	}
	return bindings, nil
}

func decodeProjection(data []byte) (catalog.Projection, error) {
	var projection catalog.Projection
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return catalog.Projection{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return catalog.Projection{}, err
	}
	if err := projection.Validate(); err != nil {
		return catalog.Projection{}, err
	}
	return projection, nil
}

func decodeJSONL[T any](data []byte) ([]T, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	items := make([]T, 0)
	for {
		var item T
		if err := decoder.Decode(&item); errors.Is(err, io.EOF) {
			return items, nil
		} else if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("unexpected trailing JSON value")
}

func ArtifactFileDescriptors(payloads []ArtifactFilePayload) []protocol.ArtifactBundleFile {
	files := make([]protocol.ArtifactBundleFile, len(payloads))
	for i := range payloads {
		files[i] = payloads[i].Descriptor
	}
	return files
}

func artifactPayload(path string, count int, data []byte) ArtifactFilePayload {
	sum := sha256.Sum256(data)
	return ArtifactFilePayload{
		Descriptor: protocol.ArtifactBundleFile{
			Path: path, SHA256: hex.EncodeToString(sum[:]), Count: count, SizeBytes: int64(len(data)),
		},
		Data: data,
	}
}

func marshalJSONL(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	switch items := value.(type) {
	case []protocol.Document:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.Chunk:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.Entity:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.Relation:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.Claim:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.GraphResourceBinding:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.ClaimTripleBinding:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	case []protocol.Summary:
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported artifact jsonl type %T", value)
	}
	return buffer.Bytes(), nil
}

func firstArtifactText(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

const defaultArtifactSchemaYAML = `version: 1
artifacts:
  documents: documents.jsonl
  chunks: chunks.jsonl
  entities: entities.jsonl
  relations: relations.jsonl
  claims: claims.jsonl
  summaries: summaries.jsonl
`

const defaultGraphArtifactSchemaYAML = `version: 2
artifacts:
  documents: documents.jsonl
  chunks: chunks.jsonl
  entities: entities.jsonl
  relations: relations.jsonl
  claims: claims.jsonl
  graph_bindings: graph_bindings.jsonl
  claim_bindings: claim_bindings.jsonl
  summaries: summaries.jsonl
graph_binding_contract:
  version: 2
  graph_object_type: KnoteResource
  claim_edge_type: KnoteClaimEdge
`
