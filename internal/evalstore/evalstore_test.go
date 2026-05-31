package evalstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadQuestionsSmokeFallback(t *testing.T) {
	questions, err := LoadQuestions(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(questions) != 1 || questions[0].ID != "smoke" || questions[0].Question == "" {
		t.Fatalf("unexpected smoke questions: %+v", questions)
	}
}

func TestLoadQuestionsSortsAndAssignsIDs(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "evals", "questions.jsonl"), `{"id":"b","question":"second"}
{"question":"first"}
`)
	questions, err := LoadQuestions(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if got := questions[0].ID + ":" + questions[1].ID; got != "b:q002" {
		t.Fatalf("questions not sorted or assigned as expected: %+v", questions)
	}
}

func TestWriteAndGateStableResults(t *testing.T) {
	workspace := t.TempDir()
	results := []Result{
		{ID: "b", Question: "second", Answer: "B"},
		{ID: "a", Question: "first", Answer: "A", Evidence: []string{"sources/a.md"}},
	}
	report, err := Write(workspace, results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 2 || report.AdapterErrors != 0 {
		t.Fatalf("unexpected report summary: %+v", report)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "evals", "results.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), `{"id":"a"`) {
		t.Fatalf("results were not sorted deterministically:\n%s", data)
	}
	if err := Gate(workspace); err != nil {
		t.Fatal(err)
	}
}

func TestGateRejectsAdapterErrors(t *testing.T) {
	workspace := t.TempDir()
	_, err := Write(workspace, []Result{{ID: "smoke", Question: "q", AdapterError: "adapter failed"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Gate(workspace); err == nil || !strings.Contains(err.Error(), "adapter errors") {
		t.Fatalf("gate should reject adapter errors, got %v", err)
	}
}

func mustWrite(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}
