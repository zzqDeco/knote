package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zzqDeco/knote/internal/audit"
	"github.com/zzqDeco/knote/internal/protocol"
)

const permissionedAuditPathEnv = "KNOTE_PERMISSIONED_AUDIT_PATH"

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
	root := strings.TrimSpace(os.Getenv(permissionedAuditPathEnv))
	if root == "" {
		root = filepath.Join(workspace, ".knote", "audit")
	} else if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("%s must be an absolute path", permissionedAuditPathEnv)
	}
	store, err := audit.OpenStore(root, residencyBoundary.AuthorizeAuditStore)
	if err != nil {
		return nil, fmt.Errorf("initialize audit store: %w", err)
	}
	return &permissionedAuditRecorder{
		store: store, residency: residencyBoundary, now: func() time.Time { return time.Now().UTC() },
	}, nil
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
