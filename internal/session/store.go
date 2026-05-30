package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type Store struct {
	workspace string
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
	file, err := os.Open(s.path(sessionID))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []protocol.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event protocol.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}
