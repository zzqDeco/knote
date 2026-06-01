package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestStoreListSummariesNewestFirst(t *testing.T) {
	workspace := t.TempDir()
	store := NewStore(workspace)
	oldID := "sess_20260531T010000.000000000"
	newID := "sess_20260531T020000.000000000"
	mustAppend(t, store, oldID, "old")
	mustAppend(t, store, newID, "new")

	oldPath := filepath.Join(workspace, ".knote", "sessions", oldID+".jsonl")
	newPath := filepath.Join(workspace, ".knote", "sessions", newID+".jsonl")
	must(t, os.Chtimes(oldPath, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)))
	must(t, os.Chtimes(newPath, time.Now(), time.Now()))

	summaries, err := store.List(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(summaries))
	}
	if summaries[0].ID != newID {
		t.Fatalf("expected newest first, got %+v", summaries)
	}
	if summaries[0].EventCount != 1 || summaries[0].LastEventAt.IsZero() {
		t.Fatalf("summary missing event metadata: %+v", summaries[0])
	}

	limited, err := store.List(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 1 || limited[0].ID != newID {
		t.Fatalf("limit did not keep newest session: %+v", limited)
	}
}

func TestStoreRejectsUnsafeSessionIDs(t *testing.T) {
	workspace := t.TempDir()
	store := NewStore(workspace)
	for _, sessionID := range []string{"../../outside", "..", ".", "nested/session", `nested\session`, " sess"} {
		t.Run(sessionID, func(t *testing.T) {
			event := protocol.NewEvent(protocol.EventAssistantDone, sessionID, "unsafe", nil)
			if err := store.Append(event); err == nil {
				t.Fatalf("Append should reject unsafe session id %q", sessionID)
			}
			if _, err := store.Load(sessionID); err == nil {
				t.Fatalf("Load should reject unsafe session id %q", sessionID)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(workspace, "outside.jsonl")); err == nil {
		t.Fatal("unsafe session id escaped the sessions directory")
	}
}

func mustAppend(t *testing.T, store Store, sessionID, message string) {
	t.Helper()
	event := protocol.NewEvent(protocol.EventAssistantDone, sessionID, message, nil)
	if err := store.Append(event); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
