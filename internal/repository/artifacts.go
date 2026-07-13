package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

var ErrArtifactCurrentNotFound = errors.New("artifact current pointer not found")

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
		if err := protocol.ValidateGraphResourceBindings(graphBindings); err != nil {
			return nil, err
		}
		if err := protocol.ValidateClaimTripleBindings(graphBindings, claimBindings); err != nil {
			return nil, err
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
  version: 1
  graph_object_type: KnoteResource
  claim_edge_type: KnoteClaimEdge
`
