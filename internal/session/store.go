package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type Store struct {
	workspace string
}

type Summary struct {
	ID          string    `json:"id"`
	EventCount  int       `json:"event_count"`
	LastEventAt time.Time `json:"last_event_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func NewStore(workspace string) Store {
	return Store{workspace: workspace}
}

func NewID() string {
	return "sess_" + time.Now().UTC().Format("20060102T150405.000000000")
}

func (s Store) path(sessionID string) string {
	return filepath.Join(s.workspace, ".knote", "sessions", sessionID+".jsonl")
}

func (s Store) Append(event protocol.Event) error {
	if strings.TrimSpace(event.SessionID) == "" {
		return fmt.Errorf("session event missing session id")
	}
	path := s.path(event.SessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	return enc.Encode(event)
}

func (s Store) Load(sessionID string) ([]protocol.Event, error) {
	return loadEvents(s.path(sessionID))
}

func (s Store) List(limit int) ([]Summary, error) {
	dir := filepath.Join(s.workspace, ".knote", "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	summaries := make([]Summary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".jsonl")
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		events, err := loadEvents(path)
		if err != nil {
			return nil, err
		}
		summary := Summary{
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

func loadEvents(path string) ([]protocol.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []protocol.Event
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var event protocol.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}
