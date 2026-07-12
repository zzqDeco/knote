package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type artifactPublicationLockRecord struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

type artifactPublicationLock struct {
	path  string
	token string
}

func acquireArtifactPublicationLock(ctx context.Context, artifactsDir string) (*artifactPublicationLock, error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("create artifact publication lock token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	path := filepath.Join(artifactsDir, artifactPublicationLockName)
	record, err := json.Marshal(artifactPublicationLockRecord{Token: token, CreatedAt: time.Now().UTC()})
	if err != nil {
		return nil, err
	}
	record = append(record, '\n')

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if _, writeErr := file.Write(record); writeErr != nil {
				file.Close()
				os.Remove(path)
				return nil, writeErr
			}
			if syncErr := file.Sync(); syncErr != nil {
				file.Close()
				os.Remove(path)
				return nil, syncErr
			}
			if closeErr := file.Close(); closeErr != nil {
				os.Remove(path)
				return nil, closeErr
			}
			if err := ctx.Err(); err != nil {
				lock := &artifactPublicationLock{path: path, token: token}
				lock.release()
				return nil, err
			}
			return &artifactPublicationLock{path: path, token: token}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire artifact publication lock: %w", err)
		}
		if _, err := recoverStaleArtifactPublicationLock(path, token); err != nil {
			return nil, err
		}

		timer := time.NewTimer(artifactPublicationLockPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func recoverStaleArtifactPublicationLock(path, contenderToken string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("artifact publication lock is not a regular file: %s", path)
	}
	if time.Since(info.ModTime()) < artifactPublicationLockStale {
		return false, nil
	}
	stalePath := path + ".stale-" + contenderToken
	if err := os.Rename(path, stalePath); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("recover stale artifact publication lock: %w", err)
	}
	if err := os.Remove(stalePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove stale artifact publication lock: %w", err)
	}
	return true, nil
}

func (l *artifactPublicationLock) release() {
	if l == nil || l.path == "" {
		return
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	var record artifactPublicationLockRecord
	if json.Unmarshal(data, &record) != nil || record.Token != l.token {
		return
	}
	_ = os.Remove(l.path)
	l.path = ""
}
