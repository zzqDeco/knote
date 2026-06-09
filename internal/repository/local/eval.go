package local

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zzqDeco/knote/internal/repository"
)

var knowledgeHashPaths = []string{".knote/config.yaml", "sources", "artifacts", "evals/questions.jsonl"}

func loadEvalQuestions(workspace string) ([]repository.EvalQuestion, error) {
	path := filepath.Join(workspace, "evals", "questions.jsonl")
	var questions []repository.EvalQuestion
	err := readJSONL(path, func(data []byte) error {
		var question repository.EvalQuestion
		if err := json.Unmarshal(data, &question); err != nil {
			return err
		}
		question.Question = strings.TrimSpace(question.Question)
		if question.Question == "" {
			return fmt.Errorf("question is required")
		}
		if strings.TrimSpace(question.ID) == "" {
			question.ID = fmt.Sprintf("q%03d", len(questions)+1)
		}
		questions = append(questions, question)
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return []repository.EvalQuestion{{ID: "smoke", Question: "What does this knowledge base contain?"}}, nil
		}
		return nil, err
	}
	if len(questions) == 0 {
		return nil, fmt.Errorf("%s: no questions found", path)
	}
	sortEvalQuestions(questions)
	return questions, nil
}

func evalGate(workspace string) error {
	reportPath := filepath.Join(workspace, "evals", "report.md")
	resultsPath := filepath.Join(workspace, "evals", "results.jsonl")
	if _, err := os.Stat(reportPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("release requires evals/report.md from a successful /eval run")
		}
		return err
	}
	results, err := loadEvalResults(resultsPath)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("release requires at least one eval result")
	}
	currentHash, err := knowledgeHash(workspace)
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

func loadEvalResults(path string) ([]repository.EvalResult, error) {
	var results []repository.EvalResult
	err := readJSONL(path, func(data []byte) error {
		var result repository.EvalResult
		if err := json.Unmarshal(data, &result); err != nil {
			return err
		}
		results = append(results, result)
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("release requires evals/results.jsonl from a successful /eval run")
		}
		return nil, err
	}
	sortEvalResults(results)
	return results, nil
}

func knowledgeHash(workspace string) (string, error) {
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

func renderEvalReport(report repository.EvalReport) string {
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

func sortEvalQuestions(questions []repository.EvalQuestion) {
	sort.Slice(questions, func(i, j int) bool {
		if questions[i].ID != questions[j].ID {
			return questions[i].ID < questions[j].ID
		}
		return questions[i].Question < questions[j].Question
	})
}

func sortEvalResults(results []repository.EvalResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].ID != results[j].ID {
			return results[i].ID < results[j].ID
		}
		return results[i].Question < results[j].Question
	})
}
