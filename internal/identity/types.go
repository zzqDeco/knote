package identity

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	ErrInvalidInput              = errors.New("identity input is invalid")
	ErrIdentityUnavailable       = errors.New("identity unavailable")
	ErrStoreUnavailable          = errors.New("identity store unavailable")
	ErrConflict                  = errors.New("identity update conflicts with existing state")
	ErrDeprovisioned             = errors.New("identity is deprovisioned")
	ErrAssertionRejected         = errors.New("identity assertion rejected")
	ErrReplayDetected            = errors.New("identity assertion replay rejected")
	ErrAuthorizationUnavailable  = errors.New("identity authorization unavailable")
	ErrPublicationUnavailable    = errors.New("identity membership publication unavailable")
	ErrPublicationTargetMismatch = errors.New("identity membership publication target mismatch")
)

const localStoreVersion = "v1"

// Clock is intentionally small so assertion and durable-store tests can use
// one deterministic time source.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

type ProviderSpec struct {
	ProviderID string
	Issuer     string
	Audiences  []string
}

type ExternalResourceRef struct {
	ProviderID string
	ExternalID string
}

// Provider is safe control-plane metadata. Verification keys and credentials
// are deliberately owned by AssertionVerifier implementations, not this record.
type Provider struct {
	Version    string   `json:"version"`
	TenantID   string   `json:"tenant_id"`
	ProviderID string   `json:"provider_id"`
	Issuer     string   `json:"issuer"`
	Audiences  []string `json:"audiences"`
}

type UserUpsert struct {
	ProviderID        string
	ExternalID        string
	ExternalSubjectID string
	PrincipalID       string
	Active            bool
}

// User is a tenant-scoped SCIM-style resource. ExternalID is scoped to the
// provisioning provider, while ID is the stable service-provider identifier.
type User struct {
	Version           string                 `json:"version"`
	TenantID          string                 `json:"tenant_id"`
	ID                string                 `json:"id"`
	ProviderID        string                 `json:"provider_id"`
	ExternalID        string                 `json:"external_id"`
	ExternalSubjectID string                 `json:"external_subject_id"`
	PrincipalID       string                 `json:"principal_id"`
	State             protocol.IdentityState `json:"state"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	UpdatedRevision   uint64                 `json:"updated_revision"`
}

type GroupUpsert struct {
	ProviderID  string
	ExternalID  string
	GroupID     string
	DisplayName string
	Active      bool
}

type Group struct {
	Version         string                 `json:"version"`
	TenantID        string                 `json:"tenant_id"`
	ID              string                 `json:"id"`
	ProviderID      string                 `json:"provider_id"`
	ExternalID      string                 `json:"external_id"`
	GroupID         string                 `json:"group_id"`
	DisplayName     string                 `json:"display_name,omitempty"`
	MemberUserIDs   []string               `json:"member_user_ids"`
	State           protocol.IdentityState `json:"state"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	UpdatedRevision uint64                 `json:"updated_revision"`
}

type MembershipUpsert struct {
	ProviderID      string
	GroupExternalID string
	UserExternalID  string
	Active          bool
}

type MembershipReplace struct {
	ProviderID      string
	GroupExternalID string
	UserExternalIDs []string
}

type TombstoneKind string

const (
	TombstoneUser  TombstoneKind = "user"
	TombstoneGroup TombstoneKind = "group"
)

type Tombstone struct {
	Version          string        `json:"version"`
	TenantID         string        `json:"tenant_id"`
	Kind             TombstoneKind `json:"kind"`
	ResourceID       string        `json:"resource_id"`
	ProviderID       string        `json:"provider_id"`
	ExternalID       string        `json:"external_id"`
	IdentityRevision uint64        `json:"identity_revision"`
	DeprovisionedAt  time.Time     `json:"deprovisioned_at"`
}

type RevisionReason string

const (
	RevisionTenantRegistered  RevisionReason = "tenant_registered"
	RevisionProviderChanged   RevisionReason = "provider_changed"
	RevisionUserChanged       RevisionReason = "user_changed"
	RevisionGroupChanged      RevisionReason = "group_changed"
	RevisionMembershipChanged RevisionReason = "membership_changed"
	RevisionDeprovisioned     RevisionReason = "deprovisioned"
)

// TenantRevision is append-only. StateDigest binds the canonical normalized
// identity state at this revision without persisting an assertion or secret.
type TenantRevision struct {
	Version           string         `json:"version"`
	TenantID          string         `json:"tenant_id"`
	Number            uint64         `json:"number"`
	Watermark         string         `json:"watermark"`
	PreviousWatermark string         `json:"previous_watermark,omitempty"`
	StateDigest       string         `json:"state_digest"`
	Reason            RevisionReason `json:"reason"`
	CommittedAt       time.Time      `json:"committed_at"`
}

type Change struct {
	Changed  bool
	Revision TenantRevision
}

type TenantSnapshot struct {
	Scope      protocol.TenantScope
	Providers  []Provider
	Users      []User
	Groups     []Group
	Tombstones []Tombstone
	Revision   TenantRevision
}

type ResolvedIdentity struct {
	TenantID          string
	ProviderID        string
	ExternalSubjectID string
	PrincipalID       string
	GroupIDs          []string
	State             protocol.IdentityState
	Watermark         string
}

type Membership struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	GroupID     string `json:"group_id"`
}

type MembershipProjection struct {
	Version   string       `json:"version"`
	TenantID  string       `json:"tenant_id"`
	Watermark string       `json:"identity_watermark"`
	Members   []Membership `json:"members"`
}

// MembershipPublicationTarget binds one tenant to one OpenFGA store. A store
// binding is durable and cannot be reused by another tenant.
type MembershipPublicationTarget struct {
	TenantID             string `json:"tenant_id"`
	StoreID              string `json:"store_id"`
	AuthorizationModelID string `json:"authorization_model_id"`
}

func (t MembershipPublicationTarget) Validate() error {
	if validateCanonicalID("tenant_id", t.TenantID) != nil ||
		validateCanonicalID("store_id", t.StoreID) != nil ||
		validateCanonicalID("authorization_model_id", t.AuthorizationModelID) != nil {
		return fmt.Errorf("%w: membership publication target is invalid", ErrInvalidInput)
	}
	return nil
}

// MembershipWriteRequest carries only canonical identity control-plane data.
// Implementations must make duplicate writes and missing deletes idempotent.
type MembershipWriteRequest struct {
	Target            MembershipPublicationTarget
	IdentityWatermark string
	Writes            []Membership
	Deletes           []Membership
}

func (r MembershipWriteRequest) Validate() error {
	if err := r.Target.Validate(); err != nil || validateCanonicalID("identity_watermark", r.IdentityWatermark) != nil {
		return fmt.Errorf("%w: membership write request is invalid", ErrInvalidInput)
	}
	seen := make(map[Membership]struct{}, len(r.Writes)+len(r.Deletes))
	for _, members := range [][]Membership{r.Deletes, r.Writes} {
		if validatePublicationMembers(r.Target.TenantID, members) != nil {
			return fmt.Errorf("%w: membership write request is invalid", ErrInvalidInput)
		}
		for _, member := range members {
			if _, duplicate := seen[member]; duplicate {
				return fmt.Errorf("%w: membership write request is invalid", ErrInvalidInput)
			}
			seen[member] = struct{}{}
		}
	}
	return nil
}

// MembershipRemoteState is the complete identity-owned state observed in the
// target OpenFGA store with higher consistency. TenantIDs contains every
// tenant binding attached to the isolated identity control object.
type MembershipRemoteState struct {
	Claimed   bool
	TenantIDs []string
	Members   []Membership
}

func (s MembershipRemoteState) Validate(target MembershipPublicationTarget) error {
	if err := target.Validate(); err != nil {
		return err
	}
	for index, tenantID := range s.TenantIDs {
		if validateCanonicalID("tenant_id", tenantID) != nil ||
			index > 0 && tenantID <= s.TenantIDs[index-1] {
			return ErrPublicationUnavailable
		}
	}
	if err := validatePublicationMembers(target.TenantID, s.Members); err != nil {
		return err
	}
	return nil
}

// MembershipPublicationBackend is the remote-authoritative OpenFGA boundary.
// InspectMembershipState must use higher consistency and consume all pages.
// ClaimMembershipStore atomically writes the fixed claim tuple and tenant
// binding, failing on a duplicate fixed claim tuple.
type MembershipPublicationBackend interface {
	InspectMembershipState(context.Context, MembershipPublicationTarget) (MembershipRemoteState, error)
	ClaimMembershipStore(context.Context, MembershipPublicationTarget) error
	ApplyMembershipChanges(context.Context, MembershipWriteRequest) error
}

// MembershipPublicationReceipt is intentionally content-free: tuple members
// remain in the private recovery journal and are never returned to callers.
type MembershipPublicationReceipt struct {
	Version              string    `json:"version"`
	TenantID             string    `json:"tenant_id"`
	StoreID              string    `json:"store_id"`
	AuthorizationModelID string    `json:"authorization_model_id"`
	IdentityWatermark    string    `json:"identity_watermark"`
	ProjectionDigest     string    `json:"projection_digest"`
	MemberCount          int       `json:"member_count"`
	PublishedAt          time.Time `json:"published_at"`
}

func (r MembershipPublicationReceipt) Matches(target MembershipPublicationTarget, watermark string) bool {
	return r.Validate() == nil &&
		r.TenantID == target.TenantID && r.StoreID == target.StoreID &&
		r.AuthorizationModelID == target.AuthorizationModelID &&
		r.IdentityWatermark == watermark
}

func (r MembershipPublicationReceipt) Validate() error {
	if r.Version != protocol.EnterpriseContractVersion ||
		validateCanonicalID("tenant_id", r.TenantID) != nil ||
		validateCanonicalID("store_id", r.StoreID) != nil ||
		validateCanonicalID("authorization_model_id", r.AuthorizationModelID) != nil ||
		validateCanonicalID("identity_watermark", r.IdentityWatermark) != nil ||
		validateDigest("projection_digest", r.ProjectionDigest) != nil ||
		r.MemberCount < 0 || validateUTC("published_at", r.PublishedAt) != nil {
		return fmt.Errorf("%w: membership publication receipt is invalid", ErrInvalidInput)
	}
	return nil
}

func (p MembershipProjection) Validate() error {
	if p.Version != protocol.EnterpriseContractVersion || validateCanonicalID("tenant_id", p.TenantID) != nil ||
		validateCanonicalID("identity_watermark", p.Watermark) != nil {
		return fmt.Errorf("%w: membership projection is invalid", ErrInvalidInput)
	}
	for index, member := range p.Members {
		if member.TenantID != p.TenantID || validateAuthorizationID("principal_id", member.PrincipalID) != nil ||
			validateAuthorizationID("group_id", member.GroupID) != nil {
			return fmt.Errorf("%w: membership projection is invalid", ErrInvalidInput)
		}
		if index > 0 {
			previous := p.Members[index-1]
			if member.GroupID < previous.GroupID ||
				member.GroupID == previous.GroupID && member.PrincipalID <= previous.PrincipalID {
				return fmt.Errorf("%w: memberships must be sorted and unique", ErrInvalidInput)
			}
		}
	}
	return nil
}

func (p MembershipProjection) Clone() MembershipProjection {
	p.Members = slices.Clone(p.Members)
	return p
}

type ReplayDigest string

type NonceUse struct {
	TenantID  string
	Digest    ReplayDigest
	ExpiresAt time.Time
}

// NonceStore consumes an already hashed assertion replay key. Implementations
// never need to receive or persist the original nonce or bearer assertion.
type NonceStore interface {
	Consume(context.Context, NonceUse) error
}

// IdentityDirectory is the read surface needed by the trusted gateway.
type IdentityDirectory interface {
	Tenant(context.Context, string) (protocol.TenantScope, error)
	Provider(context.Context, protocol.TenantScope, string) (Provider, error)
	ResolveActiveIdentity(context.Context, protocol.TenantScope, string, string) (ResolvedIdentity, error)
}
