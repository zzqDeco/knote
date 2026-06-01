package local

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

type Store struct {
	workspace string
}

func New(workspace string) Store {
	return Store{workspace: workspace}
}

func (s Store) Config(ctx context.Context) (repository.Config, error) {
	if err := ctx.Err(); err != nil {
		return repository.Config{}, err
	}
	return loadConfigOrDefault(s.workspace)
}

func (s Store) SaveConfig(ctx context.Context, cfg repository.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ensureConfig(s.workspace, cfg)
}

func (s Store) ListSources(ctx context.Context) ([]repository.Source, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := filepath.Join(s.workspace, "sources")
	var sources []repository.Source
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".md" && ext != ".txt" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.workspace, path)
		if err != nil {
			return err
		}
		sources = append(sources, repository.Source{
			Path:    filepath.ToSlash(rel),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC(),
		})
		return nil
	}); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	return sources, nil
}

func (s Store) ReadSource(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fullPath, err := s.workspacePath(path)
	if err != nil {
		return nil, err
	}
	resolvedPath, err := s.resolveSourcePath(fullPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolvedPath)
}

func (s Store) WriteArtifacts(ctx context.Context, set repository.ArtifactSet) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Join(s.workspace, "artifacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	documents := append([]protocol.Document(nil), set.Documents...)
	chunks := append([]protocol.Chunk(nil), set.Chunks...)
	entities := append([]protocol.Entity(nil), set.Entities...)
	relations := append([]protocol.Relation(nil), set.Relations...)
	claims := append([]protocol.Claim(nil), set.Claims...)
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
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].SummaryID < summaries[j].SummaryID })

	writes := []struct {
		name  string
		value any
	}{
		{name: "documents.jsonl", value: documents},
		{name: "chunks.jsonl", value: chunks},
		{name: "entities.jsonl", value: entities},
		{name: "relations.jsonl", value: relations},
		{name: "claims.jsonl", value: claims},
		{name: "summaries.jsonl", value: summaries},
	}
	for _, write := range writes {
		if err := writeJSONL(filepath.Join(dir, write.name), write.value); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), set.Manifest); err != nil {
		return err
	}
	schema := firstNonEmpty(set.SchemaYAML, defaultSchemaYAML)
	if err := atomicWriteText(filepath.Join(dir, "schema.yaml"), schema); err != nil {
		return err
	}
	return atomicWriteText(filepath.Join(dir, "build_report.md"), set.BuildReport)
}

func (s Store) ReadManifest(ctx context.Context) (protocol.ArtifactManifest, error) {
	if err := ctx.Err(); err != nil {
		return protocol.ArtifactManifest{}, err
	}
	data, err := os.ReadFile(filepath.Join(s.workspace, "artifacts", "manifest.json"))
	if err != nil {
		return protocol.ArtifactManifest{}, err
	}
	var manifest protocol.ArtifactManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return protocol.ArtifactManifest{}, err
	}
	return manifest, nil
}

func (s Store) ReadSummaries(ctx context.Context) ([]protocol.Summary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var summaries []protocol.Summary
	if err := readJSONL(filepath.Join(s.workspace, "artifacts", "summaries.jsonl"), func(data []byte) error {
		var summary protocol.Summary
		if err := json.Unmarshal(data, &summary); err != nil {
			return err
		}
		summaries = append(summaries, summary)
		return nil
	}); err != nil {
		return nil, err
	}
	return summaries, nil
}

func (s Store) LoadQuestions(ctx context.Context) ([]repository.EvalQuestion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return loadEvalQuestions(s.workspace)
}

func (s Store) WriteEval(ctx context.Context, report repository.EvalReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	results := make([]repository.EvalResult, 0, len(report.Results))
	for _, result := range report.Results {
		results = append(results, repository.EvalResult{
			ID:            result.ID,
			Question:      result.Question,
			KnowledgeHash: result.KnowledgeHash,
			Answer:        result.Answer,
			Evidence:      append([]string(nil), result.Evidence...),
			Explanation:   result.Explanation,
			Uncertainty:   result.Uncertainty,
			Mode:          result.Mode,
			AdapterError:  result.AdapterError,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].ID != results[j].ID {
			return results[i].ID < results[j].ID
		}
		return results[i].Question < results[j].Question
	})
	currentKnowledgeHash := strings.TrimSpace(report.KnowledgeHash)
	if currentKnowledgeHash == "" {
		hash, err := knowledgeHash(s.workspace)
		if err != nil {
			return err
		}
		currentKnowledgeHash = hash
	}
	for i := range results {
		results[i].KnowledgeHash = currentKnowledgeHash
	}
	dir := filepath.Join(s.workspace, "evals")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeJSONL(filepath.Join(dir, "results.jsonl"), results); err != nil {
		return err
	}
	evalReport := repository.EvalReport{
		Results:       results,
		Total:         firstPositive(report.Total, len(results)),
		AdapterErrors: firstPositive(report.AdapterErrors, countAdapterErrors(results)),
		KnowledgeHash: currentKnowledgeHash,
	}
	markdown := renderEvalReport(evalReport)
	if strings.TrimSpace(report.ReportMarkdown) != "" && strings.TrimSpace(report.KnowledgeHash) == currentKnowledgeHash {
		markdown = report.ReportMarkdown
	}
	return atomicWriteText(filepath.Join(dir, "report.md"), markdown)
}

func (s Store) EvalGate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return evalGate(s.workspace)
}

func (s Store) KnowledgeHash(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return knowledgeHash(s.workspace)
}

func (s Store) Append(ctx context.Context, event protocol.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return appendSessionEvent(s.workspace, event)
}

func (s Store) Load(ctx context.Context, sessionID string) ([]protocol.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return loadSessionEvents(s.workspace, sessionID)
}

func (s Store) List(ctx context.Context, limit int) ([]repository.SessionSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return listSessions(s.workspace, limit)
}

func (s Store) Status(ctx context.Context) (repository.Status, error) {
	if err := ctx.Err(); err != nil {
		return repository.Status{}, err
	}
	store := gitClient{workspace: s.workspace}
	raw, err := store.Status(ctx)
	if err != nil {
		return repository.Status{}, err
	}
	return repository.Status{
		Branch: store.Branch(ctx),
		Dirty:  store.Dirty(ctx),
		Raw:    raw,
	}, nil
}

func (s Store) Diff(ctx context.Context, ref string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return (gitClient{workspace: s.workspace}).Diff(ctx, ref)
}

func (s Store) Versions(ctx context.Context, limit int) ([]repository.Version, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return (gitClient{workspace: s.workspace}).Versions(ctx, limit)
}

func (s Store) Commit(ctx context.Context, message string) (repository.CommitResult, error) {
	if err := ctx.Err(); err != nil {
		return repository.CommitResult{}, err
	}
	output, err := (gitClient{workspace: s.workspace}).Commit(ctx, message)
	if err != nil {
		return repository.CommitResult{}, err
	}
	result := repository.CommitResult{
		Summary: strings.TrimSpace(output),
		Output:  output,
	}
	if versions, err := s.Versions(ctx, 1); err == nil && len(versions) > 0 {
		result.Hash = versions[0].Hash
	}
	return result, nil
}

func (s Store) Tag(ctx context.Context, tag string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := (gitClient{workspace: s.workspace}).Tag(ctx, tag)
	return err
}

func (s Store) Checkout(ctx context.Context, ref string, opts repository.CheckoutOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := (gitClient{workspace: s.workspace}).Checkout(ctx, ref, opts.AllowDirty)
	return err
}

func (s Store) workspacePath(path string) (string, error) {
	path = filepath.Clean(filepath.FromSlash(strings.TrimSpace(path)))
	if path == "." || filepath.IsAbs(path) || strings.HasPrefix(path, ".."+string(filepath.Separator)) || path == ".." {
		return "", fmt.Errorf("path must stay inside workspace: %s", path)
	}
	slashed := filepath.ToSlash(path)
	if slashed != "sources" && !strings.HasPrefix(slashed, "sources/") {
		return "", fmt.Errorf("source path must be under sources/: %s", slashed)
	}
	return filepath.Join(s.workspace, path), nil
}

func (s Store) resolveSourcePath(path string) (string, error) {
	resolvedWorkspace, err := filepath.EvalSymlinks(s.workspace)
	if err != nil {
		return "", err
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedWorkspace, resolvedPath)
	if err != nil {
		return "", err
	}
	if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("source path resolves outside workspace: %s", path)
	}
	slashed := filepath.ToSlash(rel)
	if slashed != "sources" && !strings.HasPrefix(slashed, "sources/") {
		return "", fmt.Errorf("source path resolves outside sources/: %s", slashed)
	}
	return resolvedPath, nil
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
	case []repository.EvalResult:
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

func readJSONL(path string, handle func([]byte) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := handle([]byte(line)); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	return scanner.Err()
}

func atomicWriteText(path string, text string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func countAdapterErrors(results []repository.EvalResult) int {
	count := 0
	for _, result := range results {
		if strings.TrimSpace(result.AdapterError) != "" {
			count++
		}
	}
	return count
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

const defaultSchemaYAML = `version: 1
artifacts:
  documents: documents.jsonl
  chunks: chunks.jsonl
  entities: entities.jsonl
  relations: relations.jsonl
  claims: claims.jsonl
  summaries: summaries.jsonl
`
