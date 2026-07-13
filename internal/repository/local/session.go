package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

const (
	sessionAuthorizationSuffix           = ".authorization.json"
	sessionAuthorizationLockSuffix       = ".publish-lock"
	sessionAuthorizationLockStale        = time.Minute
	sessionAuthorizationLockPollInterval = 10 * time.Millisecond
)

var sessionAuthorizationMu sync.RWMutex

func NewSessionID() string {
	return "sess_" + time.Now().UTC().Format("20060102T150405.000000000")
}

func appendSessionEvent(workspace string, event protocol.Event) error {
	if err := validateSessionID(event.SessionID); err != nil {
		return err
	}
	path := sessionPath(workspace, event.SessionID)
	if err := secureSessionDirectory(workspace, true); err != nil {
		return err
	}
	if err := secureSessionFile(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(event); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func loadSessionEvents(workspace string, sessionID string) ([]protocol.Event, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	if err := secureSessionDirectory(workspace, false); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	path := sessionPath(workspace, sessionID)
	if err := secureSessionFile(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var events []protocol.Event
	err := readJSONL(path, func(data []byte) error {
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
	dir := sessionsDirectory(workspace)
	if err := secureSessionDirectory(workspace, false); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
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
	return filepath.Join(sessionsDirectory(workspace), sessionID+".jsonl")
}

func sessionAuthorizationPath(workspace string, sessionID string) string {
	return filepath.Join(sessionsDirectory(workspace), sessionID+sessionAuthorizationSuffix)
}

func sessionsDirectory(workspace string) string {
	return filepath.Join(workspace, ".knote", "sessions")
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
	if strings.IndexFunc(sessionID, unicode.IsControl) >= 0 {
		return fmt.Errorf("session id cannot contain control characters")
	}
	if filepath.Clean(sessionID) != sessionID {
		return fmt.Errorf("session id is not normalized: %s", sessionID)
	}
	return nil
}

func bindSessionAuthorization(ctx context.Context, workspace string, envelope protocol.SessionAuthorizationEnvelope) error {
	sessionAuthorizationMu.Lock()
	defer sessionAuthorizationMu.Unlock()

	if err := envelope.Validate(); err != nil {
		return err
	}
	if err := validateSessionID(envelope.SessionID); err != nil {
		return err
	}
	if err := secureSessionDirectory(workspace, true); err != nil {
		return err
	}

	existing, err := loadSessionAuthorizationLocked(workspace, envelope.SessionID)
	if err == nil {
		return validateSameAuthorizationBinding(existing, envelope)
	}
	if err != repository.ErrSessionAuthorizationEnvelopeNotFound {
		return err
	}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	created, err := createSessionAuthorization(ctx, sessionAuthorizationPath(workspace, envelope.SessionID), data)
	if err != nil {
		return err
	}
	if created {
		return nil
	}
	existing, err = loadSessionAuthorizationLocked(workspace, envelope.SessionID)
	if err != nil {
		return err
	}
	return validateSameAuthorizationBinding(existing, envelope)
}

func loadSessionAuthorization(workspace string, sessionID string) (protocol.SessionAuthorizationEnvelope, error) {
	sessionAuthorizationMu.RLock()
	defer sessionAuthorizationMu.RUnlock()
	return loadSessionAuthorizationLocked(workspace, sessionID)
}

func loadSessionAuthorizationLocked(workspace string, sessionID string) (protocol.SessionAuthorizationEnvelope, error) {
	if err := validateSessionID(sessionID); err != nil {
		return protocol.SessionAuthorizationEnvelope{}, err
	}
	if err := secureSessionDirectory(workspace, false); err != nil {
		if os.IsNotExist(err) {
			return protocol.SessionAuthorizationEnvelope{}, repository.ErrSessionAuthorizationEnvelopeNotFound
		}
		return protocol.SessionAuthorizationEnvelope{}, err
	}
	path := sessionAuthorizationPath(workspace, sessionID)
	if err := secureSessionFile(path); err != nil {
		if os.IsNotExist(err) {
			return protocol.SessionAuthorizationEnvelope{}, repository.ErrSessionAuthorizationEnvelopeNotFound
		}
		return protocol.SessionAuthorizationEnvelope{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return protocol.SessionAuthorizationEnvelope{}, repository.ErrSessionAuthorizationEnvelopeNotFound
		}
		return protocol.SessionAuthorizationEnvelope{}, err
	}
	var envelope protocol.SessionAuthorizationEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return protocol.SessionAuthorizationEnvelope{}, fmt.Errorf("decode session authorization envelope: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return protocol.SessionAuthorizationEnvelope{}, err
	}
	if err := envelope.Validate(); err != nil {
		return protocol.SessionAuthorizationEnvelope{}, err
	}
	if envelope.SessionID != sessionID {
		return protocol.SessionAuthorizationEnvelope{}, fmt.Errorf("session authorization envelope session_id does not match path")
	}
	return envelope, nil
}

func listSessionAuthorization(workspace string) ([]protocol.SessionAuthorizationEnvelope, error) {
	sessionAuthorizationMu.RLock()
	defer sessionAuthorizationMu.RUnlock()

	if err := secureSessionDirectory(workspace, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(sessionsDirectory(workspace))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var envelopes []protocol.SessionAuthorizationEnvelope
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), sessionAuthorizationSuffix) {
			continue
		}
		sessionID := strings.TrimSuffix(entry.Name(), sessionAuthorizationSuffix)
		if err := validateSessionID(sessionID); err != nil {
			continue
		}
		envelope, err := loadSessionAuthorizationLocked(workspace, sessionID)
		if err != nil {
			continue
		}
		envelopes = append(envelopes, envelope)
	}
	sort.Slice(envelopes, func(i, j int) bool {
		return envelopes[i].SessionID < envelopes[j].SessionID
	})
	return envelopes, nil
}

func createSessionAuthorization(ctx context.Context, path string, data []byte) (bool, error) {
	temporary, err := stageSessionAuthorization(path, data)
	if err != nil {
		return false, err
	}
	defer os.Remove(temporary)
	return publishSessionAuthorization(ctx, temporary, path)
}

func stageSessionAuthorization(path string, data []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return "", err
	}
	temporary := file.Name()
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	complete = true
	return temporary, nil
}

func publishSessionAuthorization(ctx context.Context, temporary, path string) (bool, error) {
	lockPath := path + sessionAuthorizationLockSuffix
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, err := os.Lstat(path); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}

		if err := os.Mkdir(lockPath, 0o700); err == nil {
			defer os.Remove(lockPath)
			if _, err := os.Lstat(path); err == nil {
				return false, nil
			} else if !os.IsNotExist(err) {
				return false, err
			}
			if err := os.Rename(temporary, path); err != nil {
				return false, err
			}
			if err := syncArtifactDirectory(filepath.Dir(path)); err != nil {
				return false, err
			}
			return true, nil
		} else if !errors.Is(err, os.ErrExist) {
			return false, fmt.Errorf("acquire session authorization publish lock: %w", err)
		}

		if _, err := recoverStaleSessionAuthorizationLock(lockPath, temporary); err != nil {
			return false, err
		}
		timer := time.NewTimer(sessionAuthorizationLockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

func recoverStaleSessionAuthorizationLock(lockPath, temporary string) (bool, error) {
	info, err := os.Lstat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("session authorization publish lock is not a directory")
	}
	if time.Since(info.ModTime()) < sessionAuthorizationLockStale {
		return false, nil
	}
	stalePath := lockPath + ".stale-" + filepath.Base(temporary)
	if err := os.Rename(lockPath, stalePath); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("recover stale session authorization publish lock: %w", err)
	}
	if err := os.Remove(stalePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove stale session authorization publish lock: %w", err)
	}
	return true, nil
}

func validateSameAuthorizationBinding(existing, candidate protocol.SessionAuthorizationEnvelope) error {
	existing.BoundAt = time.Time{}
	candidate.BoundAt = time.Time{}
	if existing != candidate {
		return fmt.Errorf("session authorization envelope already bound to a different authorization context")
	}
	return nil
}

func secureSessionDirectory(workspace string, create bool) error {
	dir := sessionsDirectory(workspace)
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("session storage path is not a directory")
	}
	return os.Chmod(dir, 0o700)
}

func secureSessionFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("session storage path is not a regular file")
	}
	return os.Chmod(path, 0o600)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("session authorization envelope contains trailing JSON")
		}
		return fmt.Errorf("decode session authorization envelope: %w", err)
	}
	return nil
}
