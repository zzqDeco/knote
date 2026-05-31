package evalstore

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zzqDeco/knote/internal/kag"
)

type Question struct {
	ID       string `json:"id"`
	Question string `json:"question"`
}

type Result struct {
	ID            string   `json:"id"`
	Question      string   `json:"question"`
	KnowledgeHash string   `json:"knowledge_hash,omitempty"`
	Answer        string   `json:"answer"`
	Evidence      []string `json:"evidence"`
	Explanation   string   `json:"explanation,omitempty"`
	Uncertainty   string   `json:"uncertainty,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	AdapterError  string   `json:"adapter_error,omitempty"`
}

type Report struct {
	Results       []Result
	Total         int
	AdapterErrors int
	KnowledgeHash string
	Path          string
}

var knowledgeHashPaths = []string{".knote/config.yaml", "sources", "artifacts", "evals/questions.jsonl"}

func LoadQuestions(workspace string) ([]Question, error) {
	path := filepath.Join(workspace, "evals", "questions.jsonl")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Question{{ID: "smoke", Question: "What does this knowledge base contain?"}}, nil
		}
		return nil, err
	}
	defer file.Close()
	var questions []Question
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var question Question
		if err := json.Unmarshal([]byte(text), &question); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		question.Question = strings.TrimSpace(question.Question)
		if question.Question == "" {
			return nil, fmt.Errorf("%s:%d: question is required", path, lineNo)
		}
		if strings.TrimSpace(question.ID) == "" {
			question.ID = fmt.Sprintf("q%03d", len(questions)+1)
		}
		questions = append(questions, question)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(questions) == 0 {
		return nil, fmt.Errorf("%s: no questions found", path)
	}
	sortQuestions(questions)
	return questions, nil
}

func ResultFromResponse(question Question, resp kag.Response, err error) Result {
	result := Result{
		ID:       question.ID,
		Question: question.Question,
	}
	if err != nil {
		result.AdapterError = err.Error()
		return result
	}
	result.Answer = stringFromMap(resp.Data, "answer")
	result.Evidence = stringSliceFromMap(resp.Data, "evidence")
	result.Explanation = stringFromMap(resp.Data, "explanation")
	result.Uncertainty = stringFromMap(resp.Data, "uncertainty")
	result.Mode = stringFromMap(resp.Data, "mode")
	return result
}

func Write(workspace string, results []Result) (Report, error) {
	sortResults(results)
	knowledgeHash, err := KnowledgeHash(workspace)
	if err != nil {
		return Report{}, err
	}
	for i := range results {
		results[i].KnowledgeHash = knowledgeHash
	}
	dir := filepath.Join(workspace, "evals")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Report{}, err
	}
	resultsPath := filepath.Join(dir, "results.jsonl")
	if err := writeResults(resultsPath, results); err != nil {
		return Report{}, err
	}
	report := Report{
		Results:       append([]Result(nil), results...),
		Total:         len(results),
		AdapterErrors: countAdapterErrors(results),
		KnowledgeHash: knowledgeHash,
		Path:          filepath.Join(dir, "report.md"),
	}
	if err := atomicWriteText(report.Path, RenderReport(report)); err != nil {
		return Report{}, err
	}
	return report, nil
}

func Gate(workspace string) error {
	reportPath := filepath.Join(workspace, "evals", "report.md")
	resultsPath := filepath.Join(workspace, "evals", "results.jsonl")
	if _, err := os.Stat(reportPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("release requires evals/report.md from a successful /eval run")
		}
		return err
	}
	results, err := LoadResults(resultsPath)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("release requires at least one eval result")
	}
	currentHash, err := KnowledgeHash(workspace)
	if err != nil {
		return err
	}
	for _, result := range results {
		if result.KnowledgeHash == "" {
			return fmt.Errorf("release blocked: eval results are not tied to the current knowledge version")
		}
		if result.KnowledgeHash != currentHash {
			return fmt.Errorf("release blocked: eval results are stale for the current knowledge version")
		}
	}
	if countAdapterErrors(results) > 0 {
		return fmt.Errorf("release blocked: eval report contains adapter errors")
	}
	return nil
}

func LoadResults(path string) ([]Result, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("release requires evals/results.jsonl from a successful /eval run")
		}
		return nil, err
	}
	defer file.Close()
	var results []Result
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var result Result
		if err := json.Unmarshal([]byte(text), &result); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sortResults(results)
	return results, nil
}

func RenderReport(report Report) string {
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

func writeResults(path string, results []Result) error {
	tmp := path + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	for _, result := range results {
		if err := enc.Encode(result); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func KnowledgeHash(workspace string) (string, error) {
	var files []string
	for _, rel := range knowledgeHashPaths {
		path := filepath.Join(workspace, rel)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				files = append(files, filepath.ToSlash(rel)+"\x00missing")
				continue
			}
			return "", err
		}
		if !info.IsDir() {
			files = append(files, filepath.ToSlash(rel))
			continue
		}
		if err := filepath.WalkDir(path, func(item string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			relItem, err := filepath.Rel(workspace, item)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(relItem))
			return nil
		}); err != nil {
			return "", err
		}
	}
	sort.Strings(files)
	hash := sha256.New()
	for _, rel := range files {
		hash.Write([]byte(rel))
		hash.Write([]byte{0})
		if strings.HasSuffix(rel, "\x00missing") {
			hash.Write([]byte{0})
			continue
		}
		data, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		hash.Write(data)
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func atomicWriteText(path string, text string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sortQuestions(questions []Question) {
	sort.Slice(questions, func(i, j int) bool {
		if questions[i].ID != questions[j].ID {
			return questions[i].ID < questions[j].ID
		}
		return questions[i].Question < questions[j].Question
	})
}

func sortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].ID != results[j].ID {
			return results[i].ID < results[j].ID
		}
		return results[i].Question < results[j].Question
	})
}

func countAdapterErrors(results []Result) int {
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
