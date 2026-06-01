package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

type Mode string

const (
	ModeFake Mode = "fake"
	ModeReal Mode = "real"
)

type Backend interface {
	Build(ctx context.Context) (kag.Response, error)
	Query(ctx context.Context, query string) (kag.Response, error)
	Explain(ctx context.Context, query string) (kag.Response, error)
}

type Service interface {
	Build(ctx context.Context) (BuildResult, error)
	Query(ctx context.Context, question string) (Answer, error)
	Explain(ctx context.Context, question string) (Explanation, error)
	Eval(ctx context.Context) (repository.EvalReport, error)
	Mode() Mode
}

type Options struct {
	Workspace string
	Repo      repository.Workspace
	Backend   Backend
	Mode      Mode
}

type BuildResult struct {
	Manifest     protocol.ArtifactManifest
	Report       string
	KAGData      map[string]any
	AdapterError string
}

type Answer struct {
	Answer       string
	Evidence     []string
	Uncertainty  string
	Mode         string
	Data         map[string]any
	AdapterError string
}

type Explanation = Answer

type service struct {
	workspace string
	repo      repository.Workspace
	backend   Backend
	mode      Mode
}

func New(opts Options) Service {
	mode := opts.Mode
	if mode == "" {
		mode = ModeReal
	}
	return service{
		workspace: opts.Workspace,
		repo:      opts.Repo,
		backend:   opts.Backend,
		mode:      mode,
	}
}

func (s service) Mode() Mode {
	return s.mode
}

func (s service) Build(ctx context.Context) (BuildResult, error) {
	var out BuildResult
	if s.backend != nil {
		resp, err := s.backend.Build(ctx)
		if err != nil {
			out.AdapterError = err.Error()
		} else {
			out.KAGData = cloneMap(resp.Data)
		}
	}

	artifacts, err := s.buildArtifacts(ctx)
	if err != nil {
		return out, err
	}
	if err := s.repo.WriteArtifacts(ctx, artifacts); err != nil {
		return out, err
	}
	out.Manifest = artifacts.Manifest
	out.Report = artifacts.BuildReport
	return out, nil
}

func (s service) Query(ctx context.Context, question string) (Answer, error) {
	if s.backend != nil {
		resp, err := s.backend.Query(ctx, question)
		if err == nil {
			answer := answerFromResponse(resp)
			if strings.TrimSpace(answer.Answer) != "" {
				return answer, nil
			}
		} else {
			answer, fallbackErr := s.fallbackAnswer(ctx)
			answer.AdapterError = err.Error()
			if fallbackErr != nil {
				return answer, fallbackErr
			}
			return answer, nil
		}
	}
	return s.fallbackAnswer(ctx)
}

func (s service) Explain(ctx context.Context, question string) (Explanation, error) {
	if s.backend == nil {
		return s.fallbackAnswer(ctx)
	}
	resp, err := s.backend.Explain(ctx, question)
	if err != nil {
		answer, fallbackErr := s.fallbackAnswer(ctx)
		answer.AdapterError = err.Error()
		if fallbackErr != nil {
			return answer, fallbackErr
		}
		return answer, nil
	}
	answer := answerFromResponse(resp)
	if strings.TrimSpace(answer.Answer) == "" {
		return s.fallbackAnswer(ctx)
	}
	return answer, nil
}

func (s service) Eval(ctx context.Context) (repository.EvalReport, error) {
	questions, err := s.repo.LoadQuestions(ctx)
	if err != nil {
		return repository.EvalReport{}, err
	}
	results := make([]repository.EvalResult, 0, len(questions))
	for _, question := range questions {
		result := repository.EvalResult{
			ID:       question.ID,
			Question: question.Question,
		}
		if s.backend == nil {
			result.AdapterError = "KAG backend is not configured"
			results = append(results, result)
			continue
		}
		resp, err := s.backend.Explain(ctx, question.Question)
		if err != nil {
			result.AdapterError = err.Error()
			results = append(results, result)
			continue
		}
		answer := answerFromResponse(resp)
		result.Answer = answer.Answer
		result.Evidence = append([]string(nil), answer.Evidence...)
		result.Explanation = stringFromMap(resp.Data, "explanation")
		result.Uncertainty = answer.Uncertainty
		result.Mode = answer.Mode
		results = append(results, result)
	}
	sortEvalResults(results)
	report := repository.EvalReport{
		Results:       results,
		Total:         len(results),
		AdapterErrors: countAdapterErrors(results),
	}
	if hasher, ok := s.repo.(interface {
		KnowledgeHash(context.Context) (string, error)
	}); ok {
		hash, err := hasher.KnowledgeHash(ctx)
		if err != nil {
			return repository.EvalReport{}, err
		}
		report.KnowledgeHash = hash
		for i := range report.Results {
			report.Results[i].KnowledgeHash = hash
		}
	}
	report.ReportMarkdown = RenderEvalReport(report)
	if err := s.repo.WriteEval(ctx, report); err != nil {
		return repository.EvalReport{}, err
	}
	return report, nil
}

func (s service) buildArtifacts(ctx context.Context) (repository.ArtifactSet, error) {
	sources, err := s.repo.ListSources(ctx)
	if err != nil {
		return repository.ArtifactSet{}, err
	}
	if len(sources) == 0 {
		return repository.ArtifactSet{}, fmt.Errorf("sources directory not found or contains no .md/.txt files")
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })

	var set repository.ArtifactSet
	for _, source := range sources {
		data, err := s.repo.ReadSource(ctx, source.Path)
		if err != nil {
			return repository.ArtifactSet{}, err
		}
		contentHash := hashString(string(data))
		doc := protocol.Document{
			DocumentID:  hashString(source.Path + ":" + contentHash),
			Path:        source.Path,
			ContentHash: contentHash,
			Title:       titleFromContent(string(data)),
			Mtime:       source.ModTime.UTC(),
		}
		set.Documents = append(set.Documents, doc)
		for _, chunk := range splitChunks(string(data), 1000) {
			chunkHash := hashString(chunk.text)
			item := protocol.Chunk{
				ChunkID:    hashString(doc.DocumentID + fmt.Sprint(chunk.span) + chunkHash),
				DocumentID: doc.DocumentID,
				Span:       chunk.span,
				Text:       chunk.text,
				Hash:       chunkHash,
			}
			set.Chunks = append(set.Chunks, item)
			set.Entities = append(set.Entities, protocol.Entity{
				EntityID:         hashString("document:" + doc.Title),
				Name:             firstNonEmpty(doc.Title, doc.Path),
				Type:             "Document",
				Aliases:          []string{doc.Path},
				EvidenceChunkIDs: []string{item.ChunkID},
			})
			set.Claims = append(set.Claims, protocol.Claim{
				ClaimID:          hashString("claim:" + item.ChunkID),
				Text:             compactClaim(item.Text),
				Confidence:       "medium",
				EvidenceChunkIDs: []string{item.ChunkID},
			})
		}
	}
	sort.Slice(set.Entities, func(i, j int) bool { return set.Entities[i].EntityID < set.Entities[j].EntityID })
	sort.Slice(set.Claims, func(i, j int) bool { return set.Claims[i].ClaimID < set.Claims[j].ClaimID })
	set.Summaries = []protocol.Summary{{
		SummaryID:        hashString("summary:" + s.workspace),
		Text:             fmt.Sprintf("Built %d documents and %d chunks.", len(set.Documents), len(set.Chunks)),
		EvidenceChunkIDs: chunkIDs(set.Chunks),
	}}
	set.Manifest = protocol.ArtifactManifest{
		Version:       1,
		Workspace:     s.workspace,
		GeneratedAt:   time.Now().UTC(),
		SourceCount:   len(sources),
		DocumentCount: len(set.Documents),
		ChunkCount:    len(set.Chunks),
		EntityCount:   len(set.Entities),
		RelationCount: len(set.Relations),
		ClaimCount:    len(set.Claims),
		SummaryCount:  len(set.Summaries),
	}
	set.SchemaYAML = defaultSchemaYAML
	set.BuildReport = renderBuildReport(set.Manifest)
	return set, nil
}

func (s service) fallbackAnswer(ctx context.Context) (Answer, error) {
	summaries, err := s.repo.ReadSummaries(ctx)
	if err != nil || len(summaries) == 0 {
		return Answer{
			Answer:      "当前知识版本中没有足够证据回答这个问题。请先运行 /build。",
			Uncertainty: "KAG unavailable; no local artifact summaries were available",
		}, nil
	}
	var b strings.Builder
	b.WriteString("结论\n")
	for _, summary := range summaries {
		b.WriteString("- ")
		b.WriteString(summary.Text)
		b.WriteByte('\n')
	}
	b.WriteString("\n依据\n本回答来自 knote artifacts fallback。\n\n不确定性\n真实 KAG 查询未返回可用结果。")
	return Answer{
		Answer:      strings.TrimSpace(b.String()),
		Uncertainty: "KAG unavailable; answered from local artifacts fallback",
		Mode:        "fallback",
	}, nil
}

func answerFromResponse(resp kag.Response) Answer {
	answer := Answer{
		Answer:      stringFromMap(resp.Data, "answer"),
		Evidence:    stringSliceFromMap(resp.Data, "evidence"),
		Uncertainty: stringFromMap(resp.Data, "uncertainty"),
		Mode:        stringFromMap(resp.Data, "mode"),
		Data:        cloneMap(resp.Data),
	}
	return answer
}

func RenderEvalReport(report repository.EvalReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# knote eval report\n\n")
	fmt.Fprintf(&b, "- total: %d\n", report.Total)
	fmt.Fprintf(&b, "- adapter_errors: %d\n", report.AdapterErrors)
	fmt.Fprintf(&b, "- knowledge_hash: %s\n", report.KnowledgeHash)
	status := "pass"
	if report.AdapterErrors > 0 || report.Total == 0 {
		status = "fail"
	}
	fmt.Fprintf(&b, "- status: %s\n\n", status)
	for i, result := range report.Results {
		fmt.Fprintf(&b, "## %d. %s\n\n", i+1, result.ID)
		fmt.Fprintf(&b, "question: %s\n\n", result.Question)
		if result.AdapterError != "" {
			fmt.Fprintf(&b, "adapter_error: %s\n\n", result.AdapterError)
			continue
		}
		fmt.Fprintf(&b, "answer: %s\n\n", firstNonEmpty(result.Answer, "(empty)"))
		if len(result.Evidence) > 0 {
			fmt.Fprintf(&b, "evidence:\n")
			for _, evidence := range result.Evidence {
				fmt.Fprintf(&b, "- %s\n", evidence)
			}
			b.WriteByte('\n')
		}
		if result.Explanation != "" {
			fmt.Fprintf(&b, "explanation: %s\n\n", result.Explanation)
		}
		if result.Uncertainty != "" {
			fmt.Fprintf(&b, "uncertainty: %s\n\n", result.Uncertainty)
		}
	}
	return b.String()
}

func renderBuildReport(m protocol.ArtifactManifest) string {
	return fmt.Sprintf(`# Build Report

- documents: %d
- chunks: %d
- entities: %d
- relations: %d
- claims: %d
- summaries: %d
`, m.DocumentCount, m.ChunkCount, m.EntityCount, m.RelationCount, m.ClaimCount, m.SummaryCount)
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

func sortEvalResults(results []repository.EvalResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].ID != results[j].ID {
			return results[i].ID < results[j].ID
		}
		return results[i].Question < results[j].Question
	})
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

func stringFromMap(data map[string]any, key string) string {
	value, ok := data[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func stringSliceFromMap(data map[string]any, key string) []string {
	value, ok := data[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func cloneMap(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}
	out := make(map[string]any, len(data))
	for key, value := range data {
		out[key] = value
	}
	return out
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
