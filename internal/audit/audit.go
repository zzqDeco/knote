package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	formatVersion       = "v1"
	recordDigestDomain  = "knote.audit.record.v1"
	genesisDigestDomain = "knote.audit.genesis.v1"
	maxRecordPayload    = 16 << 10
)

var (
	ErrAuthorizationDenied = errors.New("audit reference authorization denied")
	ErrDuplicateRecordID   = errors.New("duplicate audit record id")
	ErrIntegrity           = errors.New("audit ledger integrity failure")
	ErrInvalidInput        = errors.New("invalid audit input")
	ErrResidencyDenied     = errors.New("audit storage residency denied")
	ErrStoreUnavailable    = errors.New("audit store unavailable")
	ErrUnsupportedPlatform = errors.New("audit store platform is unsupported")
)

// Entry is the complete caller-controlled audit surface. Tenant, chain, and
// digest fields are supplied by the store. Protected content, resource bodies,
// paths, assertions, credentials, and generated output have no representation.
type Entry struct {
	RecordID      string
	CorrelationID string
	ActorID       string
	Action        string
	Outcome       protocol.DecisionOutcome
	RecordedAt    time.Time
}

// ResidencyChecker authorizes one audit persistence operation. The store calls
// it before it creates or writes any filesystem object.
type ResidencyChecker func(context.Context, protocol.TenantScope) error

// ListAuthorizer authorizes disclosure of audit record existence and count.
// A nil authorizer is always denied.
type ListAuthorizer func(context.Context, protocol.TenantScope) error

type canonicalRecordFields struct {
	Version       string                   `json:"version"`
	TenantID      string                   `json:"tenant_id"`
	RecordID      string                   `json:"record_id"`
	CorrelationID string                   `json:"correlation_id"`
	ActorID       string                   `json:"actor_id"`
	Action        string                   `json:"action"`
	Outcome       protocol.DecisionOutcome `json:"outcome"`
	RecordedAt    time.Time                `json:"recorded_at"`
}

var validationDigest = protocol.NewContentDigest("knote.audit.validation")

// GenesisDigest returns the deterministic predecessor for a tenant's first
// record. The region is deliberately excluded so a tenant chain remains a
// tenant chain if its approved storage region changes.
func GenesisDigest(scope protocol.TenantScope) (protocol.ContentDigest, error) {
	if err := scope.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	var canonical bytes.Buffer
	canonical.WriteString(genesisDigestDomain)
	canonical.WriteByte(0)
	writeDigestPart(&canonical, []byte(scope.TenantID))
	return protocol.NewContentDigest(canonical.String()), nil
}

// ComputeRecordDigest computes the canonical chain digest. RecordDigest is not
// part of its own input; all other AuditRecordReference fields are validated.
func ComputeRecordDigest(
	scope protocol.TenantScope,
	reference protocol.AuditRecordReference,
) (protocol.ContentDigest, error) {
	candidate := reference
	candidate.RecordDigest = validationDigest
	if err := candidate.ValidateFor(scope); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	fields := canonicalRecordFields{
		Version: candidate.Version, TenantID: candidate.TenantID,
		RecordID: candidate.RecordID, CorrelationID: candidate.CorrelationID,
		ActorID: candidate.ActorID, Action: candidate.Action,
		Outcome: candidate.Outcome, RecordedAt: candidate.RecordedAt,
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("canonicalize audit record: %w", err)
	}
	var canonical bytes.Buffer
	canonical.WriteString(recordDigestDomain)
	canonical.WriteByte(0)
	writeDigestPart(&canonical, []byte(candidate.PreviousDigest))
	writeDigestPart(&canonical, payload)
	return protocol.NewContentDigest(canonical.String()), nil
}

func newReference(
	scope protocol.TenantScope,
	entry Entry,
	previous protocol.ContentDigest,
) (protocol.AuditRecordReference, error) {
	reference := protocol.AuditRecordReference{
		Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
		RecordID: entry.RecordID, CorrelationID: entry.CorrelationID,
		ActorID: entry.ActorID, Action: entry.Action, Outcome: entry.Outcome,
		PreviousDigest: previous, RecordDigest: validationDigest,
		RecordedAt: entry.RecordedAt,
	}
	if err := reference.ValidateFor(scope); err != nil {
		return protocol.AuditRecordReference{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	digest, err := ComputeRecordDigest(scope, reference)
	if err != nil {
		return protocol.AuditRecordReference{}, err
	}
	reference.RecordDigest = digest
	return reference, nil
}

func validateEntry(scope protocol.TenantScope, entry Entry) error {
	genesis, err := GenesisDigest(scope)
	if err != nil {
		return err
	}
	_, err = newReference(scope, entry, genesis)
	return err
}

func writeDigestPart(destination *bytes.Buffer, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	destination.Write(size[:])
	destination.Write(value)
}

func encodeReference(reference protocol.AuditRecordReference) ([]byte, error) {
	payload, err := json.Marshal(reference)
	if err != nil {
		return nil, fmt.Errorf("encode audit reference: %w", err)
	}
	if len(payload) > maxRecordPayload {
		return nil, fmt.Errorf("%w: audit reference exceeds the durable record limit", ErrInvalidInput)
	}
	return payload, nil
}

func decodeReference(payload []byte) (protocol.AuditRecordReference, error) {
	if len(payload) == 0 || len(payload) > maxRecordPayload {
		return protocol.AuditRecordReference{}, integrityError("invalid record payload length", nil)
	}
	var reference protocol.AuditRecordReference
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reference); err != nil {
		return protocol.AuditRecordReference{}, integrityError("decode record payload", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return protocol.AuditRecordReference{}, integrityError("record payload has trailing values", err)
	}
	canonical, err := json.Marshal(reference)
	if err != nil {
		return protocol.AuditRecordReference{}, integrityError("re-encode record payload", err)
	}
	if !bytes.Equal(payload, canonical) {
		return protocol.AuditRecordReference{}, integrityError("record payload is not canonical", nil)
	}
	return reference, nil
}

func integrityError(message string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrIntegrity, message)
	}
	return fmt.Errorf("%w: %s: %v", ErrIntegrity, message, cause)
}

func checksum(domain string, parts ...[]byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	for _, part := range parts {
		writeHashPart(hash, part)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeHashPart(destination byteWriter, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = destination.Write(size[:])
	_, _ = destination.Write(value)
}
