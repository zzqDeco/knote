package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zzqDeco/knote/internal/audit"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	permissionedAuditPathEnv         = "KNOTE_PERMISSIONED_AUDIT_PATH"
	permissionedAuditWorkspaceDomain = "knote.audit.workspace.v1"
)

type permissionedAuditRecorder struct {
	store     *audit.Store
	residency *permissionedResidencyBoundary
	now       func() time.Time
	sequence  atomic.Uint64
}

func newPermissionedAuditRecorder(
	workspace string,
	residencyBoundary *permissionedResidencyBoundary,
) (*permissionedAuditRecorder, error) {
	if residencyBoundary == nil {
		return nil, fmt.Errorf("initialize audit: residency boundary is required")
	}
	root, err := permissionedAuditRoot(workspace)
	if err != nil {
		return nil, err
	}
	store, err := audit.OpenStore(root, residencyBoundary.AuthorizeAuditStore)
	if err != nil {
		return nil, fmt.Errorf("initialize audit store: %w", err)
	}
	return &permissionedAuditRecorder{
		store: store, residency: residencyBoundary, now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func permissionedAuditRoot(workspace string) (string, error) {
	configured := strings.TrimSpace(os.Getenv(permissionedAuditPathEnv))
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("%s must be an absolute path", permissionedAuditPathEnv)
		}
		return filepath.Clean(configured), nil
	}

	workspaceRoot, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolve workspace for audit store: %w", err)
	}
	workspaceRoot, err = canonicalPathAllowMissing(workspaceRoot)
	if err != nil {
		return "", fmt.Errorf("resolve workspace for audit store: %w", err)
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory for audit store: %w", err)
	}
	digest := sha256.Sum256([]byte(permissionedAuditWorkspaceDomain + "\x00" + workspaceRoot))
	root := filepath.Join(configRoot, "knote", "audit", hex.EncodeToString(digest[:16]))
	insideWorkspace, err := pathWithinDirectory(workspaceRoot, root)
	if err != nil {
		return "", fmt.Errorf("validate audit store path: %w", err)
	}
	if insideWorkspace {
		return "", fmt.Errorf("default audit store must be outside workspace %q", workspaceRoot)
	}
	return root, nil
}

func canonicalPathAllowMissing(path string) (string, error) {
	current := filepath.Clean(path)
	missing := make([]string, 0, 2)
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %q", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func pathWithinDirectory(directory, path string) (bool, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return false, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false, err
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}

func (r *permissionedAuditRecorder) Record(
	ctx context.Context,
	action string,
	outcome protocol.DecisionOutcome,
) (protocol.AuditRecordReference, error) {
	if r == nil || r.store == nil || r.residency == nil || r.now == nil || ctx == nil {
		return protocol.AuditRecordReference{}, audit.ErrStoreUnavailable
	}
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok || authorization.Validate() != nil {
		return protocol.AuditRecordReference{}, audit.ErrAuthorizationDenied
	}
	recordedAt := r.now()
	if recordedAt.IsZero() {
		return protocol.AuditRecordReference{}, audit.ErrInvalidInput
	}
	scope := protocol.TenantScope{
		Version: protocol.EnterpriseContractVersion, TenantID: authorization.TenantID, Region: r.residency.Region(),
	}
	entry := audit.Entry{
		RecordID: permissionedAuditRecordID(
			authorization.RequestID, action, recordedAt, r.sequence.Add(1),
		),
		CorrelationID: authorization.RequestID,
		ActorID:       authorization.PrincipalID,
		Action:        action,
		Outcome:       outcome,
		RecordedAt:    recordedAt.UTC(),
	}
	return r.store.Append(ctx, scope, entry)
}

func permissionedAuditRecordID(
	requestID string,
	action string,
	recordedAt time.Time,
	sequence uint64,
) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"knote.audit.record-id.v1\x00%s\x00%s\x00%d\x00%d",
		requestID,
		action,
		recordedAt.UnixNano(),
		sequence,
	)))
	return "audit_" + hex.EncodeToString(digest[:16])
}
