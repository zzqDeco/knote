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

var (
	sessionAuthorizationMu sync.RWMutex
	sessionEventsMu        sync.Mutex
)

type sessionBatchEntry struct {
	sessionID  string
	path       string
	stagedPath string
	backupPath string
	existed    bool
	published  bool
}

func NewSessionID() string {
	return "sess_" + time.Now().UTC().Format("20060102T150405.000000000")
}

func appendSessionEvent(ctx context.Context, workspace string, event protocol.Event) error {
	if err := validateSessionID(event.SessionID); err != nil {
		return err
	}
	sessionEventsMu.Lock()
	defer sessionEventsMu.Unlock()
	if err := ctx.Err(); err != nil {
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

func appendSessionEvents(
	ctx context.Context,
	workspace string,
	events []protocol.Event,
	beforePublish func(sessionID string, published int) error,
) error {
	encoded, sessionIDs, err := encodeSessionBatch(ctx, events)
	if err != nil || len(sessionIDs) == 0 {
		return err
	}

	sessionEventsMu.Lock()
	defer sessionEventsMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := secureSessionDirectory(workspace, true); err != nil {
		return err
	}
	if len(sessionIDs) == 1 {
		sessionID := sessionIDs[0]
		if beforePublish != nil {
			if err := beforePublish(sessionID, 0); err != nil {
				return err
			}
		}
		return appendSingleSessionBatch(ctx, workspace, sessionID, encoded[sessionID])
	}
	dir := sessionsDirectory(workspace)
	entries := make([]sessionBatchEntry, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		if err := ctx.Err(); err != nil {
			return cleanupUnpublishedSessionBatch(dir, entries, err)
		}
		entry, err := stageSessionBatchEntry(workspace, sessionID, encoded[sessionID])
		if err != nil {
			return cleanupUnpublishedSessionBatch(dir, entries, err)
		}
		entries = append(entries, entry)
	}

	published := 0
	for i := range entries {
		if err := ctx.Err(); err != nil {
			return rollbackSessionBatch(dir, entries, err)
		}
		if beforePublish != nil {
			if err := beforePublish(entries[i].sessionID, published); err != nil {
				return rollbackSessionBatch(dir, entries, err)
			}
		}
		if err := replaceArtifactFile(entries[i].stagedPath, entries[i].path); err != nil {
			return rollbackSessionBatch(dir, entries, fmt.Errorf("publish session %q batch: %w", entries[i].sessionID, err))
		}
		entries[i].stagedPath = ""
		entries[i].published = true
		published++
	}
	if err := syncArtifactDirectory(dir); err != nil {
		return rollbackSessionBatch(dir, entries, fmt.Errorf("sync published session batch: %w", err))
	}

	// The synced directory is the commit point. Backup cleanup is best effort so
	// a committed batch is never reported as failed because a 0600 temp remains.
	cleanupSessionBatchFiles(entries)
	return nil
}

func appendSingleSessionBatch(ctx context.Context, workspace, sessionID string, appended []byte) error {
	path := sessionPath(workspace, sessionID)
	existed := true
	if err := secureSessionFile(path); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		existed = false
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	originalSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		_ = file.Close()
		if !existed {
			_ = os.Remove(path)
		}
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return rollbackOpenSessionAppend(file, path, existed, originalSize, err)
	}
	if err := ctx.Err(); err != nil {
		return rollbackOpenSessionAppend(file, path, existed, originalSize, err)
	}
	written, writeErr := file.Write(appended)
	if writeErr == nil && written != len(appended) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return rollbackOpenSessionAppend(file, path, existed, originalSize, writeErr)
	}
	if err := ctx.Err(); err != nil {
		return rollbackOpenSessionAppend(file, path, existed, originalSize, err)
	}
	if err := file.Sync(); err != nil {
		return rollbackOpenSessionAppend(file, path, existed, originalSize, err)
	}
	if err := file.Close(); err != nil {
		return rollbackClosedSessionAppend(path, existed, originalSize, err)
	}
	if !existed {
		if err := syncArtifactDirectory(sessionsDirectory(workspace)); err != nil {
			return rollbackClosedSessionAppend(path, false, originalSize, err)
		}
	}
	return nil
}

func rollbackOpenSessionAppend(file *os.File, path string, existed bool, originalSize int64, cause error) error {
	errs := []error{cause}
	if err := file.Truncate(originalSize); err != nil {
		errs = append(errs, fmt.Errorf("truncate failed session batch: %w", err))
	}
	if err := file.Sync(); err != nil {
		errs = append(errs, fmt.Errorf("sync failed session batch rollback: %w", err))
	}
	if err := file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close failed session batch rollback: %w", err))
	}
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove failed new session batch: %w", err))
		}
		if err := syncArtifactDirectory(filepath.Dir(path)); err != nil {
			errs = append(errs, fmt.Errorf("sync session directory after append rollback: %w", err))
		}
	}
	return errors.Join(errs...)
}

func rollbackClosedSessionAppend(path string, existed bool, originalSize int64, cause error) error {
	errs := []error{cause}
	if existed {
		file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
		if err != nil {
			errs = append(errs, fmt.Errorf("open failed session batch rollback: %w", err))
		} else {
			if err := file.Truncate(originalSize); err != nil {
				errs = append(errs, fmt.Errorf("truncate failed session batch: %w", err))
			}
			if err := file.Sync(); err != nil {
				errs = append(errs, fmt.Errorf("sync failed session batch rollback: %w", err))
			}
			if err := file.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close failed session batch rollback: %w", err))
			}
		}
	} else if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove failed new session batch: %w", err))
	}
	if !existed {
		if err := syncArtifactDirectory(filepath.Dir(path)); err != nil {
			errs = append(errs, fmt.Errorf("sync session directory after append rollback: %w", err))
		}
	}
	return errors.Join(errs...)
}

func encodeSessionBatch(ctx context.Context, events []protocol.Event) (map[string][]byte, []string, error) {
	encoded := make(map[string][]byte)
	for i, event := range events {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := validateSessionID(event.SessionID); err != nil {
			return nil, nil, fmt.Errorf("event %d: %w", i, err)
		}
		data, err := json.Marshal(event)
		if err != nil {
			return nil, nil, fmt.Errorf("encode event %d for session %q: %w", i, event.SessionID, err)
		}
		data = append(data, '\n')
		encoded[event.SessionID] = append(encoded[event.SessionID], data...)
	}
	sessionIDs := make([]string, 0, len(encoded))
	for sessionID := range encoded {
		sessionIDs = append(sessionIDs, sessionID)
	}
	sort.Strings(sessionIDs)
	return encoded, sessionIDs, nil
}

func stageSessionBatchEntry(workspace, sessionID string, appended []byte) (sessionBatchEntry, error) {
	entry := sessionBatchEntry{
		sessionID: sessionID,
		path:      sessionPath(workspace, sessionID),
	}
	original, err := readSessionFileForBatch(entry.path)
	if err != nil {
		return sessionBatchEntry{}, err
	}
	entry.existed = original != nil

	data := make([]byte, 0, len(original)+len(appended))
	data = append(data, original...)
	data = append(data, appended...)
	entry.stagedPath, err = stageSessionBatchFile(entry.path, data, "append")
	if err != nil {
		return sessionBatchEntry{}, err
	}
	if entry.existed {
		entry.backupPath, err = stageSessionBatchBackup(entry.path, original)
		if err != nil {
			_ = os.Remove(entry.stagedPath)
			return sessionBatchEntry{}, err
		}
	}
	return entry, nil
}

func readSessionFileForBatch(path string) ([]byte, error) {
	if err := secureSessionFile(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return []byte{}, nil
	}
	return data, nil
}

func stageSessionBatchFile(path string, data []byte, purpose string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-"+purpose+"-*.tmp")
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

func stageSessionBatchBackup(path string, data []byte) (string, error) {
	placeholder, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-rollback-*.tmp")
	if err != nil {
		return "", err
	}
	backup := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(backup)
		return "", err
	}
	if err := os.Remove(backup); err != nil {
		return "", err
	}
	if err := os.Link(path, backup); err == nil {
		return backup, nil
	}
	return stageSessionBatchFile(path, data, "rollback")
}

func cleanupUnpublishedSessionBatch(dir string, entries []sessionBatchEntry, cause error) error {
	errs := []error{cause}
	for _, entry := range entries {
		for _, path := range []string{entry.stagedPath, entry.backupPath} {
			if path == "" {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove session batch staging %q: %w", path, err))
			}
		}
	}
	if err := syncArtifactDirectory(dir); err != nil {
		errs = append(errs, fmt.Errorf("sync session directory after staging cleanup: %w", err))
	}
	return errors.Join(errs...)
}

func rollbackSessionBatch(dir string, entries []sessionBatchEntry, cause error) error {
	errs := []error{cause}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := &entries[i]
		if !entry.published {
			continue
		}
		if entry.existed {
			if entry.backupPath == "" {
				errs = append(errs, fmt.Errorf("rollback session %q: backup is unavailable", entry.sessionID))
				continue
			}
			if err := replaceArtifactFile(entry.backupPath, entry.path); err != nil {
				errs = append(errs, fmt.Errorf("rollback session %q: %w", entry.sessionID, err))
				continue
			}
			entry.backupPath = ""
		} else if err := os.Remove(entry.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("rollback new session %q: %w", entry.sessionID, err))
			continue
		}
		entry.published = false
	}
	for _, entry := range entries {
		for _, path := range []string{entry.stagedPath, entry.backupPath} {
			if path == "" {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove session batch staging %q: %w", path, err))
			}
		}
	}
	if err := syncArtifactDirectory(dir); err != nil {
		errs = append(errs, fmt.Errorf("sync session directory after rollback: %w", err))
	}
	return errors.Join(errs...)
}

func cleanupSessionBatchFiles(entries []sessionBatchEntry) {
	for _, entry := range entries {
		for _, path := range []string{entry.stagedPath, entry.backupPath} {
			if path != "" {
				_ = os.Remove(path)
			}
		}
	}
}

func loadSessionEvents(workspace string, sessionID string) ([]protocol.Event, error) {
	sessionEventsMu.Lock()
	defer sessionEventsMu.Unlock()
	return loadSessionEventsLocked(workspace, sessionID)
}

func loadSessionEventsLocked(workspace string, sessionID string) ([]protocol.Event, error) {
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
	sessionEventsMu.Lock()
	defer sessionEventsMu.Unlock()

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
		events, err := loadSessionEventsLocked(workspace, id)
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

func rebindSessionAuthorization(
	ctx context.Context,
	workspace string,
	expected protocol.SessionAuthorizationEnvelope,
	replacement protocol.SessionAuthorizationEnvelope,
) error {
	sessionAuthorizationMu.Lock()
	defer sessionAuthorizationMu.Unlock()

	if err := expected.Validate(); err != nil {
		return err
	}
	if err := replacement.Validate(); err != nil {
		return err
	}
	if expected.SessionID != replacement.SessionID {
		return fmt.Errorf("session authorization rebind must keep the same session id")
	}
	if err := validateSessionID(expected.SessionID); err != nil {
		return err
	}
	if err := secureSessionDirectory(workspace, false); err != nil {
		return err
	}
	existing, err := loadSessionAuthorizationLocked(workspace, expected.SessionID)
	if err != nil {
		return err
	}
	if existing != expected {
		return fmt.Errorf("session authorization envelope changed before rebind")
	}
	if validateSameAuthorizationBinding(expected, replacement) == nil {
		return nil
	}

	data, err := json.MarshalIndent(replacement, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := sessionAuthorizationPath(workspace, expected.SessionID)
	temporary, err := stageSessionAuthorization(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	return replaceSessionAuthorization(ctx, workspace, temporary, path, expected)
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

func replaceSessionAuthorization(
	ctx context.Context,
	workspace string,
	temporary string,
	path string,
	expected protocol.SessionAuthorizationEnvelope,
) error {
	lockPath := path + sessionAuthorizationLockSuffix
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.Mkdir(lockPath, 0o700); err == nil {
			defer os.Remove(lockPath)
			existing, err := loadSessionAuthorizationLocked(workspace, expected.SessionID)
			if err != nil {
				return err
			}
			if existing != expected {
				return fmt.Errorf("session authorization envelope changed before rebind")
			}
			if err := replaceArtifactFile(temporary, path); err != nil {
				return err
			}
			if err := syncArtifactDirectory(filepath.Dir(path)); err != nil {
				return err
			}
			return nil
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("acquire session authorization publish lock: %w", err)
		}

		if _, err := recoverStaleSessionAuthorizationLock(lockPath, temporary); err != nil {
			return err
		}
		timer := time.NewTimer(sessionAuthorizationLockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
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
