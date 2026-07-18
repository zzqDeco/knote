package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type Store struct {
	root          string
	syncDirectory func(string) error
}

func NewStore(root string) (*Store, error) {
	return newStore(root, syncConnectorDirectory)
}

func newStore(root string, syncDir func(string) error) (*Store, error) {
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("connector store root must be an absolute path")
	}
	root = filepath.Clean(root)
	if root == filepath.VolumeName(root)+string(filepath.Separator) {
		return nil, fmt.Errorf("connector store root cannot be a filesystem root")
	}
	if err := createConnectorDirectoriesDurably(root, syncDir); err != nil {
		return nil, fmt.Errorf("create connector store root: %w", err)
	}
	if err := validateConnectorDirectory(root); err != nil {
		return nil, fmt.Errorf("validate connector store root: %w", err)
	}
	store := &Store{root: root, syncDirectory: syncDir}
	if err := store.ensureDir(store.tenantsDir()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) Register(registration Registration) error {
	if err := registration.Validate(); err != nil {
		return err
	}
	return s.withLock(func() error {
		ref := registration.Ref()
		path := s.registrationPath(ref)
		var existing Registration
		if err := s.readJSON(path, &existing); err == nil {
			if err := existing.Validate(); err != nil {
				return fmt.Errorf("%w: persisted registration: %v", ErrStoreIntegrity, err)
			}
			if !registrationsEqual(existing, registration) {
				return ErrRegistrationConflict
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if err := s.writeJSONOnce(path, registration); err != nil {
			if errors.Is(err, ErrJournalConflict) {
				return ErrRegistrationConflict
			}
			return err
		}
		for _, directory := range []string{
			s.journalDir(ref), s.eventsDir(ref), s.deadLetterDir(ref), s.reconciliationReceiptsDir(ref),
			s.resourceOwnersDir(ref), s.reconciliationOwnershipClaimsDir(ref),
		} {
			if err := s.ensureDir(directory); err != nil {
				return err
			}
		}
		_, err := s.loadStateLocked(ref, true)
		return err
	})
}

func registrationsEqual(left, right Registration) bool {
	leftTime, rightTime := left.RegisteredAt, right.RegisteredAt
	left.RegisteredAt, right.RegisteredAt = time.Time{}, time.Time{}
	return left == right && leftTime.Equal(rightTime)
}

func (s *Store) Registration(ref ConnectorRef) (Registration, error) {
	if err := ref.Validate(); err != nil {
		return Registration{}, err
	}
	var registration Registration
	err := s.withLock(func() error {
		var err error
		registration, err = s.loadRegistrationLocked(ref)
		return err
	})
	return registration, err
}

func (s *Store) Journal(ref ConnectorRef) ([]JournalEntry, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	var journal []JournalEntry
	err := s.withLock(func() error {
		state, err := s.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		journal = make([]JournalEntry, len(state.events))
		for index := range state.events {
			journal[index] = state.events[index].entry
		}
		return nil
	})
	return journal, err
}

func (s *Store) Cursor(ref ConnectorRef) (Cursor, error) {
	if err := ref.Validate(); err != nil {
		return Cursor{}, err
	}
	var cursor Cursor
	err := s.withLock(func() error {
		state, err := s.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		cursor = state.cursor
		return nil
	})
	return cursor, err
}

func (s *Store) DeadLetters(ref ConnectorRef) ([]DeadLetter, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	var records []DeadLetter
	err := s.withLock(func() error {
		state, err := s.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		records = make([]DeadLetter, 0, 1)
		for _, event := range state.events {
			if event.deadLetter != nil {
				records = append(records, *event.deadLetter)
			}
		}
		return nil
	})
	return records, err
}

func (s *Store) Eligibility(ref ConnectorRef, sequence uint64) (ServingEligibility, error) {
	if err := ref.Validate(); err != nil {
		return ServingEligibility{}, err
	}
	if sequence == 0 {
		return ServingEligibility{}, fmt.Errorf("serving eligibility sequence must be greater than zero")
	}
	var eligibility ServingEligibility
	err := s.withLock(func() error {
		state, err := s.loadStateLocked(ref, true)
		if err != nil {
			return err
		}
		if sequence > uint64(len(state.events)) || state.events[sequence-1].eligibility == nil {
			return ErrNotServingEligible
		}
		eligibility = *state.events[sequence-1].eligibility
		return nil
	})
	return eligibility, err
}

func (s *Store) ResourceOwnership(ref ConnectorRef, resourceID protocol.ResourceID) (ResourceOwnership, error) {
	if err := ref.Validate(); err != nil {
		return ResourceOwnership{}, err
	}
	if err := resourceID.Validate(); err != nil {
		return ResourceOwnership{}, err
	}
	var ownership ResourceOwnership
	err := s.withLock(func() error {
		registration, err := s.loadRegistrationLocked(ref)
		if err != nil {
			return err
		}
		ownership, err = s.loadResourceOwnershipLocked(ref, resourceID)
		if err != nil {
			return err
		}
		return validateResourceOwnershipForRegistration(ownership, registration)
	})
	return ownership, err
}

func (s *Store) loadResourceOwnershipLocked(ref ConnectorRef, resourceID protocol.ResourceID) (ResourceOwnership, error) {
	owners := []ResourceOwnership{}
	var direct ResourceOwnership
	if err := s.readJSON(s.resourceOwnershipPath(ref, resourceID), &direct); err == nil {
		if err := direct.Validate(); err != nil {
			return ResourceOwnership{}, fmt.Errorf("%w: persisted resource ownership: %v", ErrStoreIntegrity, err)
		}
		if direct.TenantID != ref.Scope.TenantID || direct.ResourceID != resourceID {
			return ResourceOwnership{}, fmt.Errorf("%w: resource ownership crosses its tenant partition", ErrStoreIntegrity)
		}
		owners = append(owners, direct)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ResourceOwnership{}, err
	}
	claimed, found, err := s.loadReconciliationClaimedOwnershipLocked(ref, resourceID)
	if err != nil {
		return ResourceOwnership{}, err
	}
	if found {
		owners = append(owners, claimed)
	}
	if len(owners) == 0 {
		return ResourceOwnership{}, ErrResourceOwnershipRequired
	}
	if len(owners) != 1 {
		return ResourceOwnership{}, fmt.Errorf("%w: resource has multiple durable owners", ErrStoreIntegrity)
	}
	return owners[0], nil
}

func (s *Store) loadReconciliationClaimedOwnershipLocked(
	ref ConnectorRef,
	resourceID protocol.ResourceID,
) (ResourceOwnership, bool, error) {
	directory := s.reconciliationOwnershipClaimsDir(ref)
	if err := s.cleanupTemporaryFiles(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ResourceOwnership{}, false, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return ResourceOwnership{}, false, nil
	}
	if err != nil {
		return ResourceOwnership{}, false, err
	}
	var owner ResourceOwnership
	found := false
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return ResourceOwnership{}, false, fmt.Errorf(
				"%w: unexpected reconciliation ownership claim entry %q", ErrStoreIntegrity, entry.Name(),
			)
		}
		var claim ReconciliationOwnershipClaim
		if err := s.readJSON(filepath.Join(directory, entry.Name()), &claim); err != nil {
			return ResourceOwnership{}, false, err
		}
		if err := claim.Validate(); err != nil {
			return ResourceOwnership{}, false, fmt.Errorf("%w: reconciliation ownership claim: %v", ErrStoreIntegrity, err)
		}
		if claim.TenantID != ref.Scope.TenantID {
			return ResourceOwnership{}, false, fmt.Errorf(
				"%w: reconciliation ownership claim crosses its tenant partition", ErrStoreIntegrity,
			)
		}
		if entry.Name() != filepath.Base(s.reconciliationOwnershipClaimPath(ref, claim)) {
			return ResourceOwnership{}, false, fmt.Errorf(
				"%w: reconciliation ownership claim filename does not match its binding", ErrStoreIntegrity,
			)
		}
		if !containsResourceID(claim.ResourceIDs, resourceID) {
			continue
		}
		if found {
			return ResourceOwnership{}, false, fmt.Errorf(
				"%w: resource appears in multiple reconciliation ownership claims", ErrStoreIntegrity,
			)
		}
		owner, err = claim.Ownership(resourceID)
		if err != nil {
			return ResourceOwnership{}, false, fmt.Errorf("%w: reconciliation ownership claim: %v", ErrStoreIntegrity, err)
		}
		found = true
	}
	return owner, found, nil
}

func (s *Store) loadResourceOwnershipOptionalLocked(
	ref ConnectorRef,
	resourceID protocol.ResourceID,
) (ResourceOwnership, bool, error) {
	ownership, err := s.loadResourceOwnershipLocked(ref, resourceID)
	if errors.Is(err, ErrResourceOwnershipRequired) {
		return ResourceOwnership{}, false, nil
	}
	return ownership, err == nil, err
}

func validateResourceOwnershipForRegistration(ownership ResourceOwnership, registration Registration) error {
	if ownership.TenantID != registration.Scope.TenantID || ownership.ConnectorID != registration.ConnectorID ||
		ownership.SourceID != registration.SourceID {
		return ErrResourceOwnership
	}
	return nil
}

func (s *Store) ensureEventResourceOwnershipLocked(
	ref ConnectorRef,
	registration Registration,
	event protocol.ConnectorEventEnvelope,
	fingerprint protocol.ConnectorEventFingerprint,
	boundAt time.Time,
) (ResourceOwnership, error) {
	if event.Kind == protocol.ConnectorSnapshotComplete {
		return ResourceOwnership{}, ErrResourceOwnershipRequired
	}
	ownership, err := s.loadResourceOwnershipLocked(ref, event.ResourceID)
	if err == nil {
		if err := validateResourceOwnershipForRegistration(ownership, registration); err != nil {
			return ResourceOwnership{}, err
		}
		if ownership.BoundSequence == event.Sequence &&
			(ownership.BoundEventID != event.EventID || ownership.BoundFingerprint != fingerprint) {
			return ResourceOwnership{}, ErrJournalConflict
		}
		if ownership.BoundSequence > event.Sequence {
			return ResourceOwnership{}, fmt.Errorf("%w: resource ownership is bound to a future sequence", ErrStoreIntegrity)
		}
		return ownership, nil
	}
	if !errors.Is(err, ErrResourceOwnershipRequired) {
		return ResourceOwnership{}, err
	}
	if event.Kind != protocol.ConnectorContentUpsert {
		return ResourceOwnership{}, ErrResourceOwnershipRequired
	}
	ownership = ResourceOwnership{
		Version: ConnectorCoreVersion, TenantID: registration.Scope.TenantID, ResourceID: event.ResourceID,
		ConnectorID: registration.ConnectorID, SourceID: registration.SourceID, BoundEventID: event.EventID,
		BoundFingerprint: fingerprint, BoundSequence: event.Sequence, BoundAt: boundAt,
	}
	if err := ownership.ValidateForEvent(event, sourceOwnershipFor(registration)); err != nil {
		return ResourceOwnership{}, err
	}
	if err := s.writeJSONOnce(s.resourceOwnershipPath(ref, event.ResourceID), ownership); err != nil {
		if errors.Is(err, ErrJournalConflict) {
			return ResourceOwnership{}, ErrResourceOwnership
		}
		return ResourceOwnership{}, err
	}
	return ownership, nil
}

func (s *Store) claimReconciliationResourceOwnershipsLocked(
	ref ConnectorRef,
	registration Registration,
	resourceIDs []protocol.ResourceID,
	event *protocol.ConnectorEventEnvelope,
	eventFingerprint protocol.ConnectorEventFingerprint,
	requestDigest protocol.ContentDigest,
	boundAt time.Time,
) error {
	resources := append([]protocol.ResourceID{}, resourceIDs...)
	sort.Slice(resources, func(i, j int) bool { return resources[i] < resources[j] })
	unique := resources[:0]
	for _, resourceID := range resources {
		if err := resourceID.Validate(); err != nil {
			return err
		}
		if len(unique) == 0 || unique[len(unique)-1] != resourceID {
			unique = append(unique, resourceID)
		}
	}
	unowned := make([]protocol.ResourceID, 0, len(unique))
	for _, resourceID := range unique {
		ownership, found, err := s.loadResourceOwnershipOptionalLocked(ref, resourceID)
		if err != nil {
			return err
		}
		if found {
			if err := validateResourceOwnershipForRegistration(ownership, registration); err != nil {
				return err
			}
			continue
		}
		unowned = append(unowned, resourceID)
	}
	if len(unowned) == 0 {
		return nil
	}
	claim := ReconciliationOwnershipClaim{
		Version: ConnectorCoreVersion, TenantID: registration.Scope.TenantID,
		ConnectorID: registration.ConnectorID, SourceID: registration.SourceID,
		ResourceIDs: unowned, BoundAt: boundAt,
	}
	if event != nil {
		if event.TenantID != registration.Scope.TenantID || event.ConnectorID != registration.ConnectorID ||
			event.Kind != protocol.ConnectorSnapshotComplete {
			return ErrResourceOwnership
		}
		claim.BoundEventID = event.EventID
		claim.BoundFingerprint = eventFingerprint
		claim.BoundSequence = event.Sequence
	} else {
		claim.RequestDigest = requestDigest
	}
	if err := claim.Validate(); err != nil {
		return err
	}
	if err := s.writeJSONOnce(s.reconciliationOwnershipClaimPath(ref, claim), claim); err != nil {
		if errors.Is(err, ErrJournalConflict) {
			return ErrResourceOwnership
		}
		return err
	}
	return nil
}

func (s *Store) requireResourceOwnershipsLocked(
	ref ConnectorRef,
	registration Registration,
	resourceIDs []protocol.ResourceID,
) ([]protocol.ResourceID, error) {
	owned := append([]protocol.ResourceID{}, resourceIDs...)
	sort.Slice(owned, func(i, j int) bool { return owned[i] < owned[j] })
	unique := owned[:0]
	for _, resourceID := range owned {
		if len(unique) > 0 && unique[len(unique)-1] == resourceID {
			continue
		}
		ownership, err := s.loadResourceOwnershipLocked(ref, resourceID)
		if err != nil {
			return nil, err
		}
		if err := validateResourceOwnershipForRegistration(ownership, registration); err != nil {
			return nil, err
		}
		unique = append(unique, resourceID)
	}
	return unique, nil
}

type durableAttempt struct {
	intent  ApplyAttempt
	failure *ApplyFailureRecord
}

type durableEvent struct {
	entry              JournalEntry
	attempts           []durableAttempt
	delivery           *DeliveryRecord
	reconciliation     *SnapshotReconciliationReceipt
	checkpoint         *protocol.ConnectorCheckpoint
	eligibility        *ServingEligibility
	publicationIntent  *PublicationIntent
	publicationReceipt *PublicationReceipt
	deadLetter         *DeadLetter
}

type durableState struct {
	registration    Registration
	events          []durableEvent
	reconciliations []ReconciliationReservationReceipt
	cursor          Cursor
}

func (s *Store) loadStateLocked(ref ConnectorRef, repairCursor bool) (durableState, error) {
	registration, err := s.loadRegistrationLocked(ref)
	if err != nil {
		return durableState{}, err
	}
	entries, err := s.readJournalLocked(ref)
	if err != nil {
		return durableState{}, err
	}
	state := durableState{registration: registration, events: make([]durableEvent, len(entries))}
	for index, entry := range entries {
		event, err := s.readDurableEventLocked(ref, entry)
		if err != nil {
			return durableState{}, fmt.Errorf("%w: event sequence %d: %v", ErrStoreIntegrity, entry.Event.Sequence, err)
		}
		if entry.Event.Kind == protocol.ConnectorSnapshotComplete {
			intent := entry.SnapshotReconciliation
			if intent == nil || intent.SourceID != registration.SourceID {
				return durableState{}, fmt.Errorf("%w: snapshot reconciliation source ownership mismatch", ErrStoreIntegrity)
			}
			if _, err := s.requireResourceOwnershipsLocked(ref, registration, intent.OwnedResourceIDs); err != nil {
				return durableState{}, fmt.Errorf("%w: snapshot resource ownership: %v", ErrStoreIntegrity, err)
			}
		} else {
			ownership, err := s.loadResourceOwnershipLocked(ref, entry.Event.ResourceID)
			if err != nil {
				return durableState{}, fmt.Errorf("%w: event resource ownership: %v", ErrStoreIntegrity, err)
			}
			if err := validateResourceOwnershipForRegistration(ownership, registration); err != nil {
				return durableState{}, fmt.Errorf("%w: event resource ownership: %v", ErrStoreIntegrity, err)
			}
			if event.delivery != nil && event.delivery.ResourceOwnership != ownership {
				return durableState{}, fmt.Errorf("%w: delivery resource ownership changed", ErrStoreIntegrity)
			}
		}
		if event.publicationIntent != nil && event.publicationIntent.SourceID != registration.SourceID {
			return durableState{}, fmt.Errorf("%w: publication source ownership mismatch", ErrStoreIntegrity)
		}
		if event.publicationReceipt != nil && event.publicationReceipt.SourceID != registration.SourceID {
			return durableState{}, fmt.Errorf("%w: publication receipt source ownership mismatch", ErrStoreIntegrity)
		}
		state.events[index] = event
	}
	reconciliations, err := s.readReconciliationReceiptsLocked(ref, registration)
	if err != nil {
		return durableState{}, err
	}
	state.reconciliations = reconciliations
	if err := validateDurableSequence(state.events); err != nil {
		return durableState{}, fmt.Errorf("%w: %v", ErrStoreIntegrity, err)
	}
	state.cursor = deriveCursor(ref, state.events)
	if err := state.cursor.ValidateFor(ref); err != nil {
		return durableState{}, fmt.Errorf("%w: derived cursor: %v", ErrStoreIntegrity, err)
	}
	if err := s.reconcileCursorLocked(ref, state.cursor, repairCursor); err != nil {
		return durableState{}, err
	}
	return state, nil
}

func (s *Store) readReconciliationReceiptsLocked(
	ref ConnectorRef,
	registration Registration,
) ([]ReconciliationReservationReceipt, error) {
	directory := s.reconciliationReceiptsDir(ref)
	if err := s.cleanupTemporaryFiles(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []ReconciliationReservationReceipt{}, nil
	}
	if err != nil {
		return nil, err
	}
	receipts := make([]ReconciliationReservationReceipt, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("%w: unexpected reconciliation receipt entry %q", ErrStoreIntegrity, entry.Name())
		}
		var receipt ReconciliationReservationReceipt
		if err := s.readJSON(filepath.Join(directory, entry.Name()), &receipt); err != nil {
			return nil, err
		}
		if err := receipt.Validate(); err != nil {
			return nil, fmt.Errorf("%w: reconciliation receipt: %v", ErrStoreIntegrity, err)
		}
		if receipt.TenantID != registration.Scope.TenantID || receipt.ConnectorID != registration.ConnectorID ||
			receipt.SourceID != registration.SourceID {
			return nil, fmt.Errorf("%w: reconciliation receipt crosses connector source ownership", ErrStoreIntegrity)
		}
		expectedName := filepath.Base(s.reconciliationReservationReceiptPath(ref, receipt.RequestDigest))
		if entry.Name() != expectedName {
			return nil, fmt.Errorf("%w: reconciliation receipt filename does not match its request", ErrStoreIntegrity)
		}
		if _, err := s.requireResourceOwnershipsLocked(ref, registration, receipt.Request.OwnedResourceIDs); err != nil {
			return nil, fmt.Errorf("%w: reconciliation receipt ownership: %v", ErrStoreIntegrity, err)
		}
		receipts = append(receipts, receipt)
	}
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].ApplicationOrder < receipts[j].ApplicationOrder
	})
	for index := range receipts {
		if receipts[index].ApplicationOrder != uint64(index+1) {
			return nil, fmt.Errorf("%w: reconciliation receipt application order is not contiguous", ErrStoreIntegrity)
		}
		if index > 0 && receipts[index].Request.ProjectionBaseSequence < receipts[index-1].Request.ProjectionBaseSequence {
			return nil, fmt.Errorf("%w: reconciliation receipt projection base moves backwards", ErrStoreIntegrity)
		}
	}
	return receipts, nil
}

func (s *Store) nextReconciliationApplicationOrderLocked(ref ConnectorRef) (uint64, error) {
	registration, err := s.loadRegistrationLocked(ref)
	if err != nil {
		return 0, err
	}
	receipts, err := s.readReconciliationReceiptsLocked(ref, registration)
	if err != nil {
		return 0, err
	}
	if len(receipts) == 0 {
		return 1, nil
	}
	last := receipts[len(receipts)-1].ApplicationOrder
	if last == ^uint64(0) {
		return 0, fmt.Errorf("reconciliation receipt application order overflow")
	}
	return last + 1, nil
}

func (s *Store) loadRegistrationLocked(ref ConnectorRef) (Registration, error) {
	var registration Registration
	if err := s.readJSON(s.registrationPath(ref), &registration); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Registration{}, ErrNotRegistered
		}
		return Registration{}, err
	}
	if err := registration.Validate(); err != nil {
		return Registration{}, fmt.Errorf("%w: persisted registration: %v", ErrStoreIntegrity, err)
	}
	if err := registration.ValidateRef(ref); err != nil {
		if errors.Is(err, ErrOwnershipMismatch) {
			return Registration{}, ErrOwnershipMismatch
		}
		return Registration{}, err
	}
	return registration, nil
}

func (s *Store) readJournalLocked(ref ConnectorRef) ([]JournalEntry, error) {
	directory := s.journalDir(ref)
	if err := s.cleanupTemporaryFiles(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []JournalEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	journal := make([]JournalEntry, 0, len(entries))
	seenEventIDs := make(map[string]struct{}, len(entries))
	seenIdempotencyKeys := make(map[string]struct{}, len(entries))
	for _, directoryEntry := range entries {
		if directoryEntry.IsDir() || !isSequenceJSONName(directoryEntry.Name()) {
			return nil, fmt.Errorf("%w: unexpected journal entry %q", ErrStoreIntegrity, directoryEntry.Name())
		}
		sequence, err := parseSequenceJSONName(directoryEntry.Name())
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrStoreIntegrity, err)
		}
		var entry JournalEntry
		if err := s.readJSON(filepath.Join(directory, directoryEntry.Name()), &entry); err != nil {
			return nil, err
		}
		if err := entry.ValidateFor(ref); err != nil {
			return nil, fmt.Errorf("%w: journal entry: %v", ErrStoreIntegrity, err)
		}
		if entry.Event.Sequence != sequence {
			return nil, fmt.Errorf("%w: journal filename does not match event sequence", ErrStoreIntegrity)
		}
		if _, duplicate := seenEventIDs[entry.Event.EventID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate event_id %q", ErrStoreIntegrity, entry.Event.EventID)
		}
		if _, duplicate := seenIdempotencyKeys[entry.Event.IdempotencyKey]; duplicate {
			return nil, fmt.Errorf("%w: duplicate idempotency_key %q", ErrStoreIntegrity, entry.Event.IdempotencyKey)
		}
		seenEventIDs[entry.Event.EventID] = struct{}{}
		seenIdempotencyKeys[entry.Event.IdempotencyKey] = struct{}{}
		journal = append(journal, entry)
	}
	sort.Slice(journal, func(i, j int) bool { return journal[i].Event.Sequence < journal[j].Event.Sequence })
	for index, entry := range journal {
		if entry.Event.Sequence != uint64(index+1) {
			return nil, fmt.Errorf("%w: journal sequence is not contiguous from one", ErrStoreIntegrity)
		}
	}
	return journal, nil
}

func (s *Store) readDurableEventLocked(ref ConnectorRef, entry JournalEntry) (durableEvent, error) {
	event := durableEvent{entry: entry}
	directory := s.eventDir(ref, entry.Event.Sequence)
	if err := s.validateEventDirectory(directory); err != nil {
		return durableEvent{}, err
	}
	attempts, err := s.readAttemptsLocked(ref, entry)
	if err != nil {
		return durableEvent{}, err
	}
	event.attempts = attempts
	if found, err := s.readOptionalJSON(s.receiptPath(ref, entry.Event.Sequence), &event.delivery); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.delivery = nil
	}
	if found, err := s.readOptionalJSON(s.reconciliationReceiptPath(ref, entry.Event.Sequence), &event.reconciliation); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.reconciliation = nil
	}
	if found, err := s.readOptionalJSON(s.checkpointPath(ref, entry.Event.Sequence), &event.checkpoint); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.checkpoint = nil
	}
	if found, err := s.readOptionalJSON(s.eligibilityPath(ref, entry.Event.Sequence), &event.eligibility); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.eligibility = nil
	}
	if found, err := s.readOptionalJSON(s.publicationIntentPath(ref, entry.Event.Sequence), &event.publicationIntent); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.publicationIntent = nil
	}
	if found, err := s.readOptionalJSON(s.publicationReceiptPath(ref, entry.Event.Sequence), &event.publicationReceipt); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.publicationReceipt = nil
	}
	if found, err := s.readOptionalJSON(s.deadLetterPath(ref, entry.Event.Sequence), &event.deadLetter); err != nil {
		return durableEvent{}, err
	} else if !found {
		event.deadLetter = nil
	}
	if err := validateDurableEvent(event); err != nil {
		return durableEvent{}, err
	}
	return event, nil
}

func (s *Store) validateEventDirectory(path string) error {
	if err := s.cleanupTemporaryFiles(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "attempts" && entry.IsDir() {
			continue
		}
		if !entry.IsDir() && (entry.Name() == "receipt.json" || entry.Name() == "reconciliation_receipt.json" ||
			entry.Name() == "checkpoint.json" || entry.Name() == "eligibility.json" ||
			entry.Name() == "publication_intent.json" || entry.Name() == "publication_receipt.json") {
			continue
		}
		return fmt.Errorf("unexpected event state entry %q", entry.Name())
	}
	return nil
}

func (s *Store) readAttemptsLocked(ref ConnectorRef, entry JournalEntry) ([]durableAttempt, error) {
	directory := s.attemptsDir(ref, entry.Event.Sequence)
	if err := s.cleanupTemporaryFiles(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	directories, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []durableAttempt{}, nil
	}
	if err != nil {
		return nil, err
	}
	attempts := make([]durableAttempt, 0, len(directories))
	for _, attemptEntry := range directories {
		if !attemptEntry.IsDir() || !isAttemptName(attemptEntry.Name()) {
			return nil, fmt.Errorf("unexpected attempt entry %q", attemptEntry.Name())
		}
		attemptNumber, err := parseAttemptName(attemptEntry.Name())
		if err != nil {
			return nil, err
		}
		attemptDirectory := filepath.Join(directory, attemptEntry.Name())
		if err := s.cleanupTemporaryFiles(attemptDirectory); err != nil {
			return nil, err
		}
		children, err := os.ReadDir(attemptDirectory)
		if err != nil {
			return nil, err
		}
		if len(children) == 0 {
			if err := os.Remove(attemptDirectory); err != nil {
				return nil, err
			}
			if err := s.syncDirectory(directory); err != nil {
				return nil, err
			}
			continue
		}
		for _, child := range children {
			if child.IsDir() || child.Name() != "intent.json" && child.Name() != "failure.json" {
				return nil, fmt.Errorf("unexpected apply attempt state %q", child.Name())
			}
		}
		var intent ApplyAttempt
		if err := s.readJSON(filepath.Join(attemptDirectory, "intent.json"), &intent); err != nil {
			return nil, err
		}
		attempt := durableAttempt{intent: intent}
		if found, err := s.readOptionalJSON(filepath.Join(attemptDirectory, "failure.json"), &attempt.failure); err != nil {
			return nil, err
		} else if !found {
			attempt.failure = nil
		}
		if err := validateAttempt(entry, attemptNumber, attempt); err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	sort.Slice(attempts, func(i, j int) bool { return attempts[i].intent.Attempt < attempts[j].intent.Attempt })
	for index, attempt := range attempts {
		if attempt.intent.Attempt != uint32(index+1) {
			return nil, fmt.Errorf("apply attempts are not contiguous from one")
		}
		if index < len(attempts)-1 && attempt.failure == nil {
			return nil, fmt.Errorf("unfinished apply attempt precedes a later attempt")
		}
		if index < len(attempts)-1 && !attempt.failure.Retryable {
			return nil, fmt.Errorf("permanent apply failure precedes a later attempt")
		}
	}
	return attempts, nil
}

func validateAttempt(entry JournalEntry, number uint32, attempt durableAttempt) error {
	intent := attempt.intent
	if intent.Version != ConnectorCoreVersion || intent.TenantID != entry.Event.TenantID ||
		intent.ConnectorID != entry.Event.ConnectorID || intent.EventID != entry.Event.EventID ||
		intent.EventFingerprint != entry.EventFingerprint || intent.Attempt != number {
		return fmt.Errorf("apply attempt does not match its journal event")
	}
	if err := validateUTC("started_at", intent.StartedAt); err != nil {
		return err
	}
	if attempt.failure == nil {
		return nil
	}
	failure := *attempt.failure
	if failure.Version != ConnectorCoreVersion || failure.TenantID != intent.TenantID ||
		failure.ConnectorID != intent.ConnectorID || failure.EventID != intent.EventID ||
		failure.EventFingerprint != intent.EventFingerprint || failure.Attempt != intent.Attempt {
		return fmt.Errorf("apply failure does not match its attempt")
	}
	if err := validateErrorCode(failure.ErrorCode); err != nil {
		return err
	}
	return validateUTC("failed_at", failure.FailedAt)
}

func validateDurableEvent(event durableEvent) error {
	envelope := event.entry.Event
	if (event.delivery != nil || event.reconciliation != nil) && event.deadLetter != nil {
		return fmt.Errorf("event has both a successful receipt and a dead letter")
	}
	if envelope.Kind == protocol.ConnectorSnapshotComplete {
		if event.delivery != nil {
			return fmt.Errorf("snapshot completion cannot contain an ordinary delivery receipt")
		}
		if event.entry.SnapshotReconciliation == nil {
			return ErrSnapshotReconciliationRequired
		}
		if event.reconciliation != nil {
			if len(event.attempts) == 0 || event.attempts[len(event.attempts)-1].failure != nil {
				return fmt.Errorf("snapshot reconciliation receipt does not have a successful durable attempt")
			}
			intent := *event.entry.SnapshotReconciliation
			if err := event.reconciliation.ValidateFor(intent, reconciliationRequestForSnapshotIntent(intent)); err != nil {
				return err
			}
		}
	} else if event.reconciliation != nil {
		return fmt.Errorf("non-snapshot event contains a reconciliation receipt")
	}
	if event.delivery != nil {
		delivery := *event.delivery
		if delivery.Version != ConnectorCoreVersion {
			return fmt.Errorf("unsupported delivery record version %q", delivery.Version)
		}
		if err := delivery.Receipt.ValidateFor(envelope); err != nil {
			return err
		}
		if delivery.Receipt.State != protocol.ConnectorDeliveryApplied {
			return fmt.Errorf("delivery record must contain an applied receipt")
		}
		if int(delivery.Receipt.Attempts) != len(event.attempts) || delivery.Receipt.Attempts == 0 {
			return fmt.Errorf("delivery receipt attempt does not have a durable intent")
		}
		if event.attempts[delivery.Receipt.Attempts-1].failure != nil {
			return fmt.Errorf("applied delivery receipt points to a failed attempt")
		}
		request := applyRequestFor(event.entry, delivery.Receipt.Attempts)
		request.SourceOwnership = delivery.SourceOwnership
		request.ResourceOwnership = delivery.ResourceOwnership
		request.Tombstone = cloneTombstone(delivery.Tombstone)
		if err := delivery.Result.ValidateFor(request); err != nil {
			return err
		}
		if envelope.Kind == protocol.ConnectorResourceTombstone {
			if delivery.Tombstone == nil {
				return fmt.Errorf("tombstone delivery record is missing its tombstone")
			}
			if err := delivery.Tombstone.ValidateFor(envelope); err != nil {
				return err
			}
		} else if delivery.Tombstone != nil {
			return fmt.Errorf("non-tombstone delivery contains a tombstone")
		}
	}
	if event.deadLetter != nil {
		deadLetter := *event.deadLetter
		deadLetterFingerprint, err := protocol.NewConnectorEventFingerprint(deadLetter.Event)
		if err != nil || deadLetter.Version != ConnectorCoreVersion ||
			deadLetterFingerprint != event.entry.EventFingerprint ||
			deadLetter.Stage != failureStageForEvent(envelope) {
			return fmt.Errorf("dead letter does not match its journal event")
		}
		if err := deadLetter.Receipt.ValidateFor(envelope); err != nil {
			return err
		}
		if deadLetter.Receipt.State != protocol.ConnectorDeliveryDeadLettered {
			return fmt.Errorf("dead letter must contain a dead-lettered receipt")
		}
		if len(deadLetter.Failures) == 0 || deadLetter.Receipt.Attempts != uint32(len(deadLetter.Failures)) {
			return fmt.Errorf("dead letter failures do not match receipt attempts")
		}
		if len(event.attempts) != len(deadLetter.Failures) {
			return fmt.Errorf("dead letter failures do not match durable attempts")
		}
		for index, failure := range deadLetter.Failures {
			if event.attempts[index].failure == nil || *event.attempts[index].failure != failure {
				return fmt.Errorf("dead letter failure does not match durable attempt")
			}
		}
		if deadLetter.Receipt.ErrorCode != deadLetter.Failures[len(deadLetter.Failures)-1].ErrorCode {
			return fmt.Errorf("dead letter error code does not match the final failure")
		}
	}
	if event.checkpoint != nil {
		if event.deadLetter != nil || envelope.Kind == protocol.ConnectorSnapshotComplete && event.reconciliation == nil ||
			envelope.Kind != protocol.ConnectorSnapshotComplete && event.delivery == nil {
			return fmt.Errorf("checkpoint exists without its required durable apply receipt")
		}
		checkpoint := *event.checkpoint
		if checkpoint.LastSequence != envelope.Sequence || checkpoint.TenantID != envelope.TenantID ||
			checkpoint.ConnectorID != envelope.ConnectorID || checkpoint.CommittedEventID != envelope.EventID ||
			checkpoint.CommittedEventFingerprint != event.entry.EventFingerprint ||
			checkpoint.IdempotencyKey != envelope.IdempotencyKey ||
			checkpoint.SourceWatermark != envelope.SourceWatermark || checkpoint.ACLWatermark != envelope.ACLWatermark {
			return fmt.Errorf("checkpoint does not exactly match its event")
		}
		if err := checkpoint.ValidateEvent(envelope); err != nil {
			return err
		}
	}
	if event.eligibility != nil {
		if event.checkpoint == nil || event.deadLetter != nil ||
			envelope.Kind == protocol.ConnectorSnapshotComplete && event.reconciliation == nil ||
			envelope.Kind != protocol.ConnectorSnapshotComplete && event.delivery == nil {
			return fmt.Errorf("serving eligibility exists before receipt and checkpoint")
		}
		if err := validateEligibility(*event.eligibility, event); err != nil {
			return err
		}
	}
	if event.publicationIntent != nil {
		if event.eligibility == nil || event.deadLetter != nil {
			return fmt.Errorf("publication intent exists before serving eligibility")
		}
		if err := event.publicationIntent.Validate(); err != nil {
			return err
		}
		if !reflect.DeepEqual(event.publicationIntent.Eligibility, *event.eligibility) {
			return fmt.Errorf("publication intent does not match durable serving eligibility")
		}
	}
	if event.publicationReceipt != nil {
		if event.publicationIntent == nil {
			return fmt.Errorf("publication receipt exists without a durable intent")
		}
		if err := event.publicationReceipt.ValidateFor(*event.publicationIntent); err != nil {
			return err
		}
	}
	return nil
}

func validateEligibility(eligibility ServingEligibility, event durableEvent) error {
	envelope := event.entry.Event
	outputDigest, tombstone, err := durableEventOutput(event)
	if err != nil {
		return err
	}
	if eligibility.Version != ConnectorCoreVersion || eligibility.TenantID != envelope.TenantID ||
		eligibility.ConnectorID != envelope.ConnectorID || eligibility.EventID != envelope.EventID ||
		eligibility.Fingerprint != event.entry.EventFingerprint || eligibility.Sequence != envelope.Sequence ||
		eligibility.Checkpoint != *event.checkpoint || eligibility.OutputDigest != outputDigest {
		return fmt.Errorf("serving eligibility does not match its durable event state")
	}
	if !reflect.DeepEqual(eligibility.Tombstone, tombstone) {
		return fmt.Errorf("serving eligibility tombstone does not match its delivery")
	}
	if !reflect.DeepEqual(eligibility.ReconciliationTombstones, durableReconciliationTombstones(event)) {
		return fmt.Errorf("serving eligibility reconciliation tombstones do not match its receipt")
	}
	if err := eligibility.OutputDigest.Validate(); err != nil {
		return err
	}
	return validateUTC("eligible_at", eligibility.EligibleAt)
}

func durableReconciliationTombstones(event durableEvent) []ReconciliationTombstone {
	if event.reconciliation == nil {
		return []ReconciliationTombstone{}
	}
	return cloneReconciliationTombstones(event.reconciliation.DerivedTombstones)
}

func durableEventOutput(event durableEvent) (protocol.ContentDigest, *protocol.ConnectorTombstone, error) {
	if event.entry.Event.Kind == protocol.ConnectorSnapshotComplete {
		if event.reconciliation == nil || event.entry.SnapshotReconciliation == nil {
			return "", nil, ErrSnapshotReconciliationRequired
		}
		return event.entry.SnapshotReconciliation.PlanDigest, nil, nil
	}
	if event.delivery == nil {
		return "", nil, fmt.Errorf("event has no applied delivery")
	}
	return event.delivery.Result.OutputDigest, cloneTombstone(event.delivery.Tombstone), nil
}

func validateDurableSequence(events []durableEvent) error {
	var checkpointSequence uint64
	var eligibilitySequence uint64
	var publishedSequence uint64
	var terminal bool
	for index := range events {
		event := events[index]
		sequence := event.entry.Event.Sequence
		if terminal {
			return fmt.Errorf("journal continues after an unfinished or dead-lettered event")
		}
		if event.checkpoint != nil {
			if sequence != checkpointSequence+1 {
				return fmt.Errorf("checkpoints are not contiguous")
			}
			if checkpointSequence > 0 {
				previous := events[index-1].checkpoint
				if previous == nil || previous.ValidateEvent(event.entry.Event) != nil {
					return fmt.Errorf("checkpoint sequence does not accept its immediately following event")
				}
			}
			checkpointSequence = sequence
		}
		if event.eligibility != nil {
			if sequence != eligibilitySequence+1 || sequence > checkpointSequence {
				return fmt.Errorf("serving eligibility records are not contiguous")
			}
			eligibilitySequence = sequence
		}
		if event.publicationIntent != nil && sequence != publishedSequence+1 {
			return fmt.Errorf("publication intent is not for the exact next sequence")
		}
		if event.publicationReceipt != nil {
			if sequence != publishedSequence+1 || sequence > eligibilitySequence {
				return fmt.Errorf("publication receipts are not contiguous")
			}
			publishedSequence = sequence
		}
		if event.deadLetter != nil || event.checkpoint == nil || event.eligibility == nil || event.publicationReceipt == nil {
			terminal = true
		}
	}
	return nil
}

func deriveCursor(ref ConnectorRef, events []durableEvent) Cursor {
	cursor := Cursor{
		Version: ConnectorCoreVersion, TenantID: ref.Scope.TenantID,
		ConnectorID: ref.ConnectorID, AppendedSequence: uint64(len(events)),
	}
	for index := range events {
		event := events[index]
		if event.checkpoint != nil {
			checkpoint := *event.checkpoint
			cursor.Checkpoint = &checkpoint
		}
		if event.publicationReceipt != nil {
			receipt := *event.publicationReceipt
			cursor.Serving = &ServingCursor{
				Sequence: receipt.Sequence, EventID: receipt.EventID, Fingerprint: receipt.EventFingerprint,
				SourceWatermark: receipt.SourceWatermark,
				ACLWatermark:    receipt.ACLWatermark, PublishedAt: receipt.PublishedAt,
			}
		}
		if event.deadLetter != nil {
			receipt := event.deadLetter.Receipt
			cursor.Blocked = &DeadLetterCursor{
				Sequence: receipt.Sequence, EventID: receipt.EventID, Fingerprint: receipt.EventFingerprint,
				Attempts: receipt.Attempts, ErrorCode: receipt.ErrorCode, HandledAt: receipt.HandledAt,
			}
		}
	}
	return cursor
}

func (c Cursor) ValidateFor(ref ConnectorRef) error {
	if c.Version != ConnectorCoreVersion || c.TenantID != ref.Scope.TenantID || c.ConnectorID != ref.ConnectorID {
		return fmt.Errorf("connector cursor crosses its registration scope")
	}
	checkpointSequence := uint64(0)
	if c.Checkpoint != nil {
		if err := c.Checkpoint.Validate(); err != nil {
			return err
		}
		if c.Checkpoint.TenantID != c.TenantID || c.Checkpoint.ConnectorID != c.ConnectorID {
			return fmt.Errorf("connector checkpoint crosses its cursor scope")
		}
		checkpointSequence = c.Checkpoint.LastSequence
	}
	if checkpointSequence > c.AppendedSequence {
		return fmt.Errorf("connector checkpoint is ahead of the journal")
	}
	servingSequence := uint64(0)
	if c.Serving != nil {
		servingSequence = c.Serving.Sequence
		if servingSequence == 0 || servingSequence > checkpointSequence {
			return fmt.Errorf("connector serving cursor is ahead of the checkpoint")
		}
		for _, field := range []struct {
			name  string
			value string
		}{
			{"event_id", c.Serving.EventID},
			{"source_watermark", c.Serving.SourceWatermark},
			{"acl_watermark", c.Serving.ACLWatermark},
		} {
			if err := validateOpaqueID(field.name, field.value); err != nil {
				return err
			}
		}
		if err := c.Serving.Fingerprint.Validate(); err != nil {
			return err
		}
		if err := validateUTC("published_at", c.Serving.PublishedAt); err != nil {
			return err
		}
	}
	if c.Blocked != nil {
		if c.Blocked.Sequence != checkpointSequence+1 || c.Blocked.Sequence != c.AppendedSequence {
			return fmt.Errorf("dead-letter cursor is not the immediate uncommitted sequence")
		}
		if c.Blocked.Attempts == 0 {
			return fmt.Errorf("dead-letter cursor attempts must be greater than zero")
		}
		if err := c.Blocked.Fingerprint.Validate(); err != nil {
			return err
		}
		if err := validateErrorCode(c.Blocked.ErrorCode); err != nil {
			return err
		}
		if err := validateUTC("handled_at", c.Blocked.HandledAt); err != nil {
			return err
		}
	}
	if c.AppendedSequence > checkpointSequence+1 || servingSequence+1 < checkpointSequence {
		return fmt.Errorf("connector cursor contains more than one unfinished stage")
	}
	return nil
}

func (s *Store) reconcileCursorLocked(ref ConnectorRef, derived Cursor, repair bool) error {
	path := s.cursorPath(ref)
	var persisted Cursor
	if err := s.readJSON(path, &persisted); err == nil {
		if err := persisted.ValidateFor(ref); err != nil {
			return fmt.Errorf("%w: persisted cursor: %v", ErrStoreIntegrity, err)
		}
		if reflect.DeepEqual(persisted, derived) {
			return nil
		}
		if !repair {
			return fmt.Errorf("%w: persisted cursor does not match durable stages", ErrStoreIntegrity)
		}
		return s.writeJSON(path, derived)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !repair {
		return fmt.Errorf("%w: authoritative cursor is missing", ErrStoreIntegrity)
	}
	return s.writeJSON(path, derived)
}

func (s *Store) withLock(fn func() error) (err error) {
	path := filepath.Join(s.root, ".lock")
	if info, inspectErr := os.Lstat(path); inspectErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("connector store lock is not a regular file")
	} else if inspectErr != nil && !errors.Is(inspectErr, os.ErrNotExist) {
		return inspectErr
	}
	lock, err := acquireConnectorFileLock(path)
	if err != nil {
		return fmt.Errorf("open connector store lock: %w", err)
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	return fn()
}

func (s *Store) withConnectorLock(ctx context.Context, ref ConnectorRef, fn func() error) (err error) {
	if ctx == nil {
		return fmt.Errorf("connector lock context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := s.withLock(func() error {
		if _, err := s.loadRegistrationLocked(ref); err != nil {
			return err
		}
		return s.ensureDir(s.connectorDir(ref))
	}); err != nil {
		return err
	}
	path := s.connectorLockPath(ref)
	if info, inspectErr := os.Lstat(path); inspectErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("connector stream lock is not a regular file")
	} else if inspectErr != nil && !errors.Is(inspectErr, os.ErrNotExist) {
		return inspectErr
	}
	lock, err := acquireConnectorFileLockContext(ctx, path)
	if err != nil {
		return fmt.Errorf("open connector stream lock: %w", err)
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

func (s *Store) ensureDir(path string) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	if err := createConnectorDirectoriesDurably(path, s.syncDirectory); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("connector store directory is not a real directory: %s", path)
	}
	return validateConnectorDirectory(path)
}

func createConnectorDirectoriesDurably(path string, syncDir func(string) error) error {
	path = filepath.Clean(path)
	if err := validateExistingConnectorPathComponents(path); err != nil {
		return err
	}
	missing := make([]string, 0, 4)
	current := path
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("connector store directory is not a real directory: %s", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for connector store directory %s", path)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := validateExistingConnectorPathComponents(directory); err != nil {
			return err
		}
		created := false
		if err := createConnectorDirectory(directory); err == nil {
			created = true
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := validateExistingConnectorPathComponents(directory); err != nil {
			return err
		}
		if created {
			if err := secureConnectorDirectory(directory); err != nil {
				return err
			}
		}
		if err := validateConnectorDirectory(directory); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(directory)); err != nil {
			return fmt.Errorf("sync parent of connector store directory: %w", err)
		}
	}
	return nil
}

func validateExistingConnectorPathComponents(path string) error {
	path = filepath.Clean(path)
	volumeRoot := filepath.VolumeName(path) + string(filepath.Separator)
	relative, err := filepath.Rel(volumeRoot, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("connector store path is not rooted on its volume")
	}

	current := volumeRoot
	components := []string{}
	if relative != "." {
		components = strings.Split(relative, string(filepath.Separator))
	}
	for index := -1; index < len(components); index++ {
		if index >= 0 {
			current = filepath.Join(current, components[index])
		}
		if err := validateConnectorPathComponent(current); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("validate connector store path component %s: %w", current, err)
		}
	}
	return nil
}

func deterministicJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (s *Store) writeJSONOnce(path string, value any) error {
	data, err := deterministicJSON(value)
	if err != nil {
		return err
	}
	if existing, err := s.readFile(path); err == nil {
		if bytes.Equal(existing, data) {
			return s.syncDirectory(filepath.Dir(path))
		}
		return ErrJournalConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.atomicWrite(path, data)
}

func (s *Store) writeJSON(path string, value any) error {
	data, err := deterministicJSON(value)
	if err != nil {
		return err
	}
	return s.atomicWrite(path, data)
}

func (s *Store) atomicWrite(path string, data []byte) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	if err := s.ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("connector store target is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".connector-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := secureConnectorFile(temporary); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceConnectorFile(temporaryPath, path); err != nil {
		return err
	}
	return s.syncDirectory(filepath.Dir(path))
}

func (s *Store) removeFileDurably(path string) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("connector store removal target is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return s.syncDirectory(filepath.Dir(path))
}

func (s *Store) readOptionalJSON(path string, destination any) (bool, error) {
	if err := s.readJSON(path, destination); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Store) readJSON(path string, destination any) error {
	data, err := s.readFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode connector store record: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode connector store record: %w", err)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("record contains multiple JSON values")
		}
		return err
	}
	return nil
}

func (s *Store) readFile(path string) ([]byte, error) {
	if err := s.requireWithinRoot(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("connector store record is not a regular file")
	}
	return os.ReadFile(path)
}

func (s *Store) cleanupTemporaryFiles(directory string) error {
	if err := s.requireWithinRoot(directory); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".connector-") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("connector temporary record is not a regular file")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return s.syncDirectory(directory)
	}
	return nil
}

func (s *Store) requireWithinRoot(path string) error {
	relative, err := filepath.Rel(s.root, filepath.Clean(path))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("connector store path escapes its root")
	}
	return nil
}

func partitionKey(prefix string, values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + "_" + hex.EncodeToString(sum[:16])
}

func sequenceName(sequence uint64) string { return fmt.Sprintf("%020d.json", sequence) }
func attemptName(attempt uint32) string   { return fmt.Sprintf("%010d", attempt) }

func isSequenceJSONName(name string) bool {
	if len(name) != 25 || !strings.HasSuffix(name, ".json") {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimSuffix(name, ".json"), 10, 64)
	return err == nil
}

func parseSequenceJSONName(name string) (uint64, error) {
	if !isSequenceJSONName(name) {
		return 0, fmt.Errorf("invalid journal filename %q", name)
	}
	sequence, err := strconv.ParseUint(strings.TrimSuffix(name, ".json"), 10, 64)
	if err != nil || sequence == 0 {
		return 0, fmt.Errorf("invalid journal sequence filename %q", name)
	}
	return sequence, nil
}

func isAttemptName(name string) bool {
	if len(name) != 10 {
		return false
	}
	value, err := strconv.ParseUint(name, 10, 32)
	return err == nil && value > 0
}

func parseAttemptName(name string) (uint32, error) {
	if !isAttemptName(name) {
		return 0, fmt.Errorf("invalid apply attempt directory %q", name)
	}
	value, _ := strconv.ParseUint(name, 10, 32)
	return uint32(value), nil
}

func (s *Store) tenantsDir() string { return filepath.Join(s.root, "tenants") }
func (s *Store) tenantDir(ref ConnectorRef) string {
	return filepath.Join(s.tenantsDir(), partitionKey("tenant", ref.Scope.TenantID))
}
func (s *Store) connectorDir(ref ConnectorRef) string {
	return filepath.Join(s.tenantDir(ref), "connectors", partitionKey("connector", ref.Scope.TenantID, ref.ConnectorID))
}
func (s *Store) connectorLockPath(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), ".stream.lock")
}
func (s *Store) resourceOwnersDir(ref ConnectorRef) string {
	return filepath.Join(s.tenantDir(ref), "resource_owners")
}
func (s *Store) resourceOwnershipPath(ref ConnectorRef, resourceID protocol.ResourceID) string {
	return filepath.Join(s.resourceOwnersDir(ref), partitionKey("resource", ref.Scope.TenantID, string(resourceID))+".json")
}
func (s *Store) reconciliationOwnershipClaimsDir(ref ConnectorRef) string {
	return filepath.Join(s.tenantDir(ref), "reconciliation_owner_claims")
}
func (s *Store) reconciliationOwnershipClaimPath(
	ref ConnectorRef,
	claim ReconciliationOwnershipClaim,
) string {
	binding := string(claim.RequestDigest)
	if binding == "" {
		binding = string(claim.BoundFingerprint) + ":" + strconv.FormatUint(claim.BoundSequence, 10)
	}
	return filepath.Join(
		s.reconciliationOwnershipClaimsDir(ref),
		partitionKey("reconciliation-owner-claim", claim.TenantID, claim.ConnectorID, claim.SourceID, binding)+".json",
	)
}
func (s *Store) registrationPath(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), "registration.json")
}
func (s *Store) cursorPath(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), "cursor.json")
}
func (s *Store) journalDir(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), "journal")
}
func (s *Store) journalPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.journalDir(ref), sequenceName(sequence))
}
func (s *Store) eventsDir(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), "events")
}
func (s *Store) eventDir(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventsDir(ref), strings.TrimSuffix(sequenceName(sequence), ".json"))
}
func (s *Store) attemptsDir(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "attempts")
}
func (s *Store) attemptDir(ref ConnectorRef, sequence uint64, attempt uint32) string {
	return filepath.Join(s.attemptsDir(ref, sequence), attemptName(attempt))
}
func (s *Store) attemptIntentPath(ref ConnectorRef, sequence uint64, attempt uint32) string {
	return filepath.Join(s.attemptDir(ref, sequence, attempt), "intent.json")
}
func (s *Store) attemptFailurePath(ref ConnectorRef, sequence uint64, attempt uint32) string {
	return filepath.Join(s.attemptDir(ref, sequence, attempt), "failure.json")
}
func (s *Store) receiptPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "receipt.json")
}
func (s *Store) reconciliationReceiptPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "reconciliation_receipt.json")
}
func (s *Store) checkpointPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "checkpoint.json")
}
func (s *Store) eligibilityPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "eligibility.json")
}
func (s *Store) publicationIntentPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "publication_intent.json")
}
func (s *Store) publicationReceiptPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.eventDir(ref, sequence), "publication_receipt.json")
}
func (s *Store) reconciliationDir(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), "reconciliation")
}
func (s *Store) reconciliationPendingPath(ref ConnectorRef) string {
	return filepath.Join(s.reconciliationDir(ref), "pending.json")
}
func (s *Store) reconciliationReceiptsDir(ref ConnectorRef) string {
	return filepath.Join(s.reconciliationDir(ref), "receipts")
}
func (s *Store) reconciliationReservationReceiptPath(ref ConnectorRef, digest protocol.ContentDigest) string {
	return filepath.Join(s.reconciliationReceiptsDir(ref), partitionKey("request", string(digest))+".json")
}
func (s *Store) deadLetterDir(ref ConnectorRef) string {
	return filepath.Join(s.connectorDir(ref), "dlq")
}
func (s *Store) deadLetterPath(ref ConnectorRef, sequence uint64) string {
	return filepath.Join(s.deadLetterDir(ref), sequenceName(sequence))
}

func applyRequestFor(entry JournalEntry, attempt uint32) ApplyRequest {
	return ApplyRequest{
		Version: ConnectorCoreVersion, Event: entry.Event,
		EventFingerprint: entry.EventFingerprint, Attempt: attempt,
	}
}

func cloneTombstone(value *protocol.ConnectorTombstone) *protocol.ConnectorTombstone {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
