package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/zzqDeco/knote/internal/protocol"
)

type SourceDocumentSnapshot struct {
	SourceKey           string                 `json:"source_key"`
	SourceVersion       string                 `json:"source_version"`
	ContentDigest       protocol.ContentDigest `json:"content_digest"`
	ACLVersion          string                 `json:"acl_version"`
	AuthorizationObject string                 `json:"authz_object"`
	Sensitivity         Sensitivity            `json:"sensitivity"`
	SecurityDomain      string                 `json:"security_domain"`
}

func (d SourceDocumentSnapshot) Validate() error {
	if err := validateToken("source_key", d.SourceKey); err != nil {
		return err
	}
	if err := validateToken("source_version", d.SourceVersion); err != nil {
		return err
	}
	if err := d.ContentDigest.Validate(); err != nil {
		return err
	}
	if err := validateToken("acl_version", d.ACLVersion); err != nil {
		return err
	}
	if err := validateToken("authz_object", d.AuthorizationObject); err != nil {
		return err
	}
	if err := d.Sensitivity.Validate(); err != nil {
		return err
	}
	return validateToken("security_domain", d.SecurityDomain)
}

type SourceSnapshotRef struct {
	Scope          Scope                  `json:"scope"`
	SourceID       string                 `json:"source_id"`
	Version        string                 `json:"version"`
	SecurityDomain string                 `json:"security_domain"`
	Digest         protocol.ContentDigest `json:"digest"`
	DocumentCount  int                    `json:"document_count"`
}

func (r SourceSnapshotRef) Validate() error {
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if err := validateToken("source_id", r.SourceID); err != nil {
		return err
	}
	if err := validateToken("snapshot version", r.Version); err != nil {
		return err
	}
	if err := validateToken("security_domain", r.SecurityDomain); err != nil {
		return err
	}
	if err := r.Digest.Validate(); err != nil {
		return err
	}
	if r.DocumentCount < 0 {
		return fmt.Errorf("document_count must be non-negative")
	}
	return nil
}

// SourceSnapshot is immutable after construction: its fields are private and
// Documents returns a defensive copy in canonical source-key order.
type SourceSnapshot struct {
	ref       SourceSnapshotRef
	documents []SourceDocumentSnapshot
}

func NewSourceSnapshot(
	scope Scope,
	sourceID string,
	version string,
	securityDomain string,
	documents []SourceDocumentSnapshot,
) (SourceSnapshot, error) {
	if err := scope.Validate(); err != nil {
		return SourceSnapshot{}, err
	}
	if err := validateToken("source_id", sourceID); err != nil {
		return SourceSnapshot{}, err
	}
	if err := validateToken("snapshot version", version); err != nil {
		return SourceSnapshot{}, err
	}
	if err := validateToken("security_domain", securityDomain); err != nil {
		return SourceSnapshot{}, err
	}
	canonical := append([]SourceDocumentSnapshot(nil), documents...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].SourceKey < canonical[j].SourceKey })
	for i, document := range canonical {
		if err := document.Validate(); err != nil {
			return SourceSnapshot{}, fmt.Errorf("source document %q: %w", document.SourceKey, err)
		}
		if document.SourceVersion != version {
			return SourceSnapshot{}, fmt.Errorf("source document %q has version %q, want snapshot version %q", document.SourceKey, document.SourceVersion, version)
		}
		if document.SecurityDomain != securityDomain {
			return SourceSnapshot{}, fmt.Errorf("source document %q has security domain %q, want %q", document.SourceKey, document.SecurityDomain, securityDomain)
		}
		if i > 0 && canonical[i-1].SourceKey == document.SourceKey {
			return SourceSnapshot{}, fmt.Errorf("duplicate source_key %q", document.SourceKey)
		}
	}
	digestInput := struct {
		Scope          Scope                    `json:"scope"`
		SourceID       string                   `json:"source_id"`
		Version        string                   `json:"version"`
		SecurityDomain string                   `json:"security_domain"`
		Documents      []SourceDocumentSnapshot `json:"documents"`
	}{Scope: scope, SourceID: sourceID, Version: version, SecurityDomain: securityDomain, Documents: canonical}
	data, err := json.Marshal(digestInput)
	if err != nil {
		return SourceSnapshot{}, fmt.Errorf("marshal source snapshot: %w", err)
	}
	return SourceSnapshot{
		ref: SourceSnapshotRef{
			Scope: scope, SourceID: sourceID, Version: version, SecurityDomain: securityDomain,
			Digest: protocol.NewContentDigest(string(data)), DocumentCount: len(canonical),
		},
		documents: canonical,
	}, nil
}

func (s SourceSnapshot) Ref() SourceSnapshotRef {
	return s.ref
}

func (s SourceSnapshot) Documents() []SourceDocumentSnapshot {
	return append([]SourceDocumentSnapshot(nil), s.documents...)
}

func (s SourceSnapshot) Validate() error {
	if err := s.ref.Validate(); err != nil {
		return err
	}
	rebuilt, err := NewSourceSnapshot(s.ref.Scope, s.ref.SourceID, s.ref.Version, s.ref.SecurityDomain, s.documents)
	if err != nil {
		return err
	}
	if rebuilt.ref != s.ref {
		return fmt.Errorf("source snapshot digest or document count does not match its contents")
	}
	return nil
}

func (s SourceSnapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SourceSnapshotRef
		Documents []SourceDocumentSnapshot `json:"documents"`
	}{SourceSnapshotRef: s.ref, Documents: s.Documents()})
}

func (s *SourceSnapshot) UnmarshalJSON(data []byte) error {
	var wire struct {
		SourceSnapshotRef
		Documents []SourceDocumentSnapshot `json:"documents"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	rebuilt, err := NewSourceSnapshot(
		wire.Scope, wire.SourceID, wire.Version, wire.SecurityDomain, wire.Documents,
	)
	if err != nil {
		return err
	}
	if rebuilt.ref != wire.SourceSnapshotRef {
		return fmt.Errorf("source snapshot reference does not match its contents")
	}
	*s = rebuilt
	return nil
}
