package local

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

func NewSessionID() string {
	return "sess_" + time.Now().UTC().Format("20060102T150405.000000000")
}

func appendSessionEvent(workspace string, event protocol.Event) error {
	if err := validateSessionID(event.SessionID); err != nil {
		return err
	}
	path := sessionPath(workspace, event.SessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(event)
}

func loadSessionEvents(workspace string, sessionID string) ([]protocol.Event, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	var events []protocol.Event
	err := readJSONL(sessionPath(workspace, sessionID), func(data []byte) error {
		var event protocol.Event
		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}
		events = append(events, event)
		return nil
	})
	return events, err
}

func listSessions(workspace string, limit int) ([]repository.SessionSummary, error) {
	dir := filepath.Join(workspace, ".knote", "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	summaries := make([]repository.SessionSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".jsonl")
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		events, err := loadSessionEvents(workspace, id)
		if err != nil {
			return nil, err
		}
		summary := repository.SessionSummary{
			ID:         id,
			EventCount: len(events),
			UpdatedAt:  info.ModTime().UTC(),
		}
		if len(events) > 0 {
			summary.LastEventAt = events[len(events)-1].CreatedAt.UTC()
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if !summaries[i].UpdatedAt.Equal(summaries[j].UpdatedAt) {
			return summaries[i].UpdatedAt.After(summaries[j].UpdatedAt)
		}
		if !summaries[i].LastEventAt.Equal(summaries[j].LastEventAt) {
			return summaries[i].LastEventAt.After(summaries[j].LastEventAt)
		}
		return summaries[i].ID > summaries[j].ID
	})
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}
	return summaries, nil
}

func sessionPath(workspace string, sessionID string) string {
	return filepath.Join(workspace, ".knote", "sessions", sessionID+".jsonl")
}

func validateSessionID(sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	if strings.TrimSpace(sessionID) != sessionID {
		return fmt.Errorf("session id contains leading or trailing whitespace")
	}
	if sessionID == "." || sessionID == ".." {
		return fmt.Errorf("session id cannot be a path segment: %s", sessionID)
	}
	if strings.ContainsAny(sessionID, `/\`) {
		return fmt.Errorf("session id cannot contain path separators: %s", sessionID)
	}
	if filepath.Clean(sessionID) != sessionID {
		return fmt.Errorf("session id is not normalized: %s", sessionID)
	}
	return nil
}
