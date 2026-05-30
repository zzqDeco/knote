package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type Builder struct {
	Workspace string
}

type Result struct {
	Manifest  protocol.ArtifactManifest
	Documents []protocol.Document
	Chunks    []protocol.Chunk
	Entities  []protocol.Entity
	Relations []protocol.Relation
	Claims    []protocol.Claim
	Summaries []protocol.Summary
	Report    string
}

func (b Builder) Build() (Result, error) {
	sourcesDir := filepath.Join(b.Workspace, "sources")
	var files []string
	if err := filepath.WalkDir(sourcesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".md" || ext == ".txt" {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		if os.IsNotExist(err) {
			return Result{}, fmt.Errorf("sources directory not found: %s", sourcesDir)
		}
		return Result{}, err
	}
	sort.Strings(files)

	var result Result
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return Result{}, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return Result{}, err
		}
		rel, err := filepath.Rel(b.Workspace, path)
		if err != nil {
			return Result{}, err
		}
		contentHash := hashString(string(data))
		doc := protocol.Document{
			DocumentID:  hashString(rel + ":" + contentHash),
			Path:        filepath.ToSlash(rel),
			ContentHash: contentHash,
			Title:       titleFromContent(string(data)),
			Mtime:       info.ModTime().UTC(),
		}
		result.Documents = append(result.Documents, doc)
		chunks := splitChunks(string(data), 1000)
		for _, chunk := range chunks {
			chunkHash := hashString(chunk.text)
			item := protocol.Chunk{
				ChunkID:    hashString(doc.DocumentID + fmt.Sprint(chunk.span) + chunkHash),
				DocumentID: doc.DocumentID,
				Span:       chunk.span,
				Text:       chunk.text,
				Hash:       chunkHash,
			}
			result.Chunks = append(result.Chunks, item)
			result.Entities = append(result.Entities, protocol.Entity{
				EntityID:         hashString("document:" + doc.Title),
				Name:             firstNonEmpty(doc.Title, doc.Path),
				Type:             "Document",
				Aliases:          []string{doc.Path},
				EvidenceChunkIDs: []string{item.ChunkID},
			})
			result.Claims = append(result.Claims, protocol.Claim{
				ClaimID:          hashString("claim:" + item.ChunkID),
				Text:             compactClaim(item.Text),
				Confidence:       "medium",
				EvidenceChunkIDs: []string{item.ChunkID},
			})
		}
	}

	sort.Slice(result.Entities, func(i, j int) bool { return result.Entities[i].EntityID < result.Entities[j].EntityID })
	sort.Slice(result.Claims, func(i, j int) bool { return result.Claims[i].ClaimID < result.Claims[j].ClaimID })
	result.Summaries = []protocol.Summary{{
		SummaryID:        hashString("summary:" + b.Workspace),
		Text:             fmt.Sprintf("Built %d documents and %d chunks.", len(result.Documents), len(result.Chunks)),
		EvidenceChunkIDs: chunkIDs(result.Chunks),
	}}
	result.Manifest = protocol.ArtifactManifest{
		Version:       1,
		Workspace:     b.Workspace,
		GeneratedAt:   time.Now().UTC(),
		SourceCount:   len(files),
		DocumentCount: len(result.Documents),
		ChunkCount:    len(result.Chunks),
		EntityCount:   len(result.Entities),
		RelationCount: len(result.Relations),
		ClaimCount:    len(result.Claims),
		SummaryCount:  len(result.Summaries),
	}
	result.Report = renderReport(result.Manifest)
	return result, nil
}

func (r Result) Write(workspace string) error {
	dir := filepath.Join(workspace, "artifacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	writes := []struct {
		name string
		data any
	}{
		{"documents.jsonl", r.Documents},
		{"chunks.jsonl", r.Chunks},
		{"entities.jsonl", r.Entities},
		{"relations.jsonl", r.Relations},
		{"claims.jsonl", r.Claims},
		{"summaries.jsonl", r.Summaries},
	}
	for _, write := range writes {
		if err := writeJSONL(filepath.Join(dir, write.name), write.data); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), r.Manifest); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.yaml"), []byte(schemaYAML), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "build_report.md"), []byte(r.Report), 0o644)
}

func writeJSON(path string, value any) error {
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSONL(path string, value any) error {
	tmp := path + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	switch items := value.(type) {
	case []protocol.Document:
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				_ = file.Close()
				return err
			}
		}
	case []protocol.Chunk:
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				_ = file.Close()
				return err
			}
		}
	case []protocol.Entity:
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				_ = file.Close()
				return err
			}
		}
	case []protocol.Relation:
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				_ = file.Close()
				return err
			}
		}
	case []protocol.Claim:
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				_ = file.Close()
				return err
			}
		}
	case []protocol.Summary:
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				_ = file.Close()
				return err
			}
		}
	default:
		_ = file.Close()
		return fmt.Errorf("unsupported jsonl type %T", value)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type chunk struct {
	span [2]int
	text string
}

func splitChunks(text string, limit int) []chunk {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var chunks []chunk
	start := 0
	for start < len(text) {
		end := start + limit
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, chunk{span: [2]int{start, end}, text: strings.TrimSpace(text[start:end])})
		start = end
	}
	return chunks
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func titleFromContent(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if line != "" {
			return line
		}
	}
	return "Untitled"
}

func compactClaim(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 180 {
		return text[:180] + "..."
	}
	return text
}

func chunkIDs(chunks []protocol.Chunk) []string {
	ids := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		ids = append(ids, chunk.ChunkID)
	}
	sort.Strings(ids)
	return ids
}

func renderReport(m protocol.ArtifactManifest) string {
	return fmt.Sprintf(`# Build Report

- documents: %d
- chunks: %d
- entities: %d
- relations: %d
- claims: %d
- summaries: %d
`, m.DocumentCount, m.ChunkCount, m.EntityCount, m.RelationCount, m.ClaimCount, m.SummaryCount)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

const schemaYAML = `version: 1
artifacts:
  documents: documents.jsonl
  chunks: chunks.jsonl
  entities: entities.jsonl
  relations: relations.jsonl
  claims: claims.jsonl
  summaries: summaries.jsonl
`
