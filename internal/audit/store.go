package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	lockFileName               = ".audit.lock"
	transactionFileName        = ".audit.txn"
	transactionPendingFileName = ".audit.txn.pending"
	tenantsDirName             = "tenants"
	ledgerFileName             = "ledger.bin"
	headFileName               = "head.bin"
	tenantKeyDomain            = "knote.audit.tenant-path.v1"
	maxHeadFileSize            = 16 << 10
)

// Store is a durable, content-free audit ledger partitioned by tenant.
type Store struct {
	root          string
	residency     ResidencyChecker
	threadLock    *sync.Mutex
	syncDirectory func(string) error
}

type tenantLedger struct {
	scope      protocol.TenantScope
	references []protocol.AuditRecordReference
	recordIDs  map[string]struct{}
	lastDigest protocol.ContentDigest
	ledgerSize uint64
}

var auditStoreLocks sync.Map

// OpenStore opens an audit store and verifies every existing tenant chain. It
// does not create the root or any lock file; the first allowed Append owns all
// filesystem creation.
func OpenStore(root string, residency ResidencyChecker) (*Store, error) {
	return openStore(root, residency, syncAuditDirectory)
}

// Open is an alias for OpenStore.
func Open(root string, residency ResidencyChecker) (*Store, error) {
	return OpenStore(root, residency)
}

func openStore(
	root string,
	residency ResidencyChecker,
	syncDirectory func(string) error,
) (*Store, error) {
	if residency == nil || syncDirectory == nil {
		return nil, fmt.Errorf("%w: residency checker and directory sync are required", ErrInvalidInput)
	}
	resolvedRoot, err := canonicalAuditRoot(root)
	if err != nil {
		return nil, err
	}
	lockValue, _ := auditStoreLocks.LoadOrStore(resolvedRoot, &sync.Mutex{})
	store := &Store{
		root: resolvedRoot, residency: residency,
		threadLock: lockValue.(*sync.Mutex), syncDirectory: syncDirectory,
	}
	if err := store.verifyOnOpen(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

// Append persists one new reference after residency approval. The returned
// reference contains the store-owned predecessor and record digests.
func (s *Store) Append(
	ctx context.Context,
	scope protocol.TenantScope,
	entry Entry,
) (protocol.AuditRecordReference, error) {
	if err := s.validate(ctx); err != nil {
		return protocol.AuditRecordReference{}, err
	}
	if err := validateEntry(scope, entry); err != nil {
		return protocol.AuditRecordReference{}, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.AuditRecordReference{}, err
	}
	var appended protocol.AuditRecordReference
	err := s.withWriteLock(ctx, func() error {
		if err := s.residency(ctx, scope); err != nil {
			return errors.Join(ErrResidencyDenied, err)
		}
		return nil
	}, func() error {
		if err := s.ensureDirectory(s.tenantsPath()); err != nil {
			return err
		}
		tenantPath := s.tenantPath(scope.TenantID)
		ledger, exists, err := s.loadTenantLocked(scope)
		if err != nil {
			return err
		}
		if exists {
			if _, duplicate := ledger.recordIDs[entry.RecordID]; duplicate {
				return ErrDuplicateRecordID
			}
			appended, err = newReference(scope, entry, ledger.lastDigest)
			if err != nil {
				return err
			}
			frame, err := encodeFrame(uint64(len(ledger.references))+1, appended)
			if err != nil {
				return err
			}
			return s.appendFrameLocked(tenantPath, ledger, frame, appended.RecordDigest)
		}

		genesis, err := GenesisDigest(scope)
		if err != nil {
			return err
		}
		appended, err = newReference(scope, entry, genesis)
		if err != nil {
			return err
		}
		return s.createTenantLedgerLocked(tenantPath, scope, genesis, appended)
	})
	if err != nil {
		return protocol.AuditRecordReference{}, err
	}
	return appended, nil
}

// ListReferences returns references in persisted chain order. Authorization is
// checked before the store reveals whether the tenant has any records.
func (s *Store) ListReferences(
	ctx context.Context,
	scope protocol.TenantScope,
	authorize ListAuthorizer,
) ([]protocol.AuditRecordReference, error) {
	if err := s.validate(ctx); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if authorize == nil {
		return nil, ErrAuthorizationDenied
	}
	if err := authorize(ctx, scope); err != nil {
		return nil, errors.Join(ErrAuthorizationDenied, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var references []protocol.AuditRecordReference
	err := s.withExistingLock(ctx, func(rootExists bool) error {
		if !rootExists {
			references = []protocol.AuditRecordReference{}
			return nil
		}
		ledger, exists, err := s.loadTenantLocked(scope)
		if err != nil {
			return err
		}
		if !exists {
			references = []protocol.AuditRecordReference{}
			return nil
		}
		references = append([]protocol.AuditRecordReference(nil), ledger.references...)
		return nil
	})
	return references, err
}

// Verify explicitly verifies one tenant's full chain and durable head. A tenant
// with no ledger is a valid empty chain.
func (s *Store) Verify(ctx context.Context, scope protocol.TenantScope) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return s.withExistingLock(ctx, func(rootExists bool) error {
		if !rootExists {
			return nil
		}
		_, _, err := s.loadTenantLocked(scope)
		return err
	})
}

func (s *Store) validate(ctx context.Context) error {
	if s == nil || s.root == "" || s.residency == nil || s.threadLock == nil || s.syncDirectory == nil {
		return ErrStoreUnavailable
	}
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	return ctx.Err()
}

func (s *Store) verifyOnOpen() error {
	return s.withExistingLock(context.Background(), func(rootExists bool) error {
		if !rootExists {
			return nil
		}
		entries, err := os.ReadDir(s.tenantsPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return integrityError("read tenant ledger directory", err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if !entry.IsDir() || !isTenantKey(entry.Name()) {
				return integrityError("unexpected tenant ledger entry", nil)
			}
			path := filepath.Join(s.tenantsPath(), entry.Name())
			header, err := readLedgerHeaderFile(filepath.Join(path, ledgerFileName))
			if err != nil {
				return err
			}
			if tenantKey(header.Scope.TenantID) != entry.Name() {
				return integrityError("tenant ledger path does not match its tenant", nil)
			}
			if _, err := s.readTenantDirectory(path, header.Scope); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) createTenantLedgerLocked(
	tenantPath string,
	scope protocol.TenantScope,
	genesis protocol.ContentDigest,
	reference protocol.AuditRecordReference,
) error {
	headerBytes, err := encodeLedgerHeader(ledgerHeader{
		FormatVersion: formatVersion, Scope: scope, GenesisDigest: genesis,
	})
	if err != nil {
		return err
	}
	frame, err := encodeFrame(1, reference)
	if err != nil {
		return err
	}
	ledgerBytes := append(headerBytes, frame...)
	headBytes, err := encodeHead(durableHead{
		FormatVersion: formatVersion, Scope: scope, RecordCount: 1,
		LedgerSize: uint64(len(ledgerBytes)), LastDigest: reference.RecordDigest,
	})
	if err != nil {
		return err
	}
	nextHead, err := decodeHead(headBytes)
	if err != nil {
		return err
	}
	if err := s.beginTransaction(auditTransaction{
		FormatVersion: formatVersion, Kind: transactionCreate,
		Scope: scope, Next: nextHead,
	}); err != nil {
		return err
	}
	if err := s.ensureDirectory(tenantPath); err != nil {
		return err
	}
	entries, err := os.ReadDir(tenantPath)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return integrityError("new tenant ledger directory is not empty", nil)
	}
	if err := s.atomicFile(filepath.Join(tenantPath, ledgerFileName), ledgerBytes, false); err != nil {
		return fmt.Errorf("create tenant audit ledger: %w", err)
	}
	if err := s.atomicFile(filepath.Join(tenantPath, headFileName), headBytes, false); err != nil {
		return fmt.Errorf("create tenant audit head: %w", err)
	}
	return s.finishTransaction()
}

func (s *Store) appendFrameLocked(
	tenantPath string,
	ledger tenantLedger,
	frame []byte,
	lastDigest protocol.ContentDigest,
) error {
	previousHead := durableHeadForLedger(ledger)
	newSize := ledger.ledgerSize + uint64(len(frame))
	nextHead := durableHead{
		FormatVersion: formatVersion, Scope: ledger.scope,
		RecordCount: uint64(len(ledger.references)) + 1,
		LedgerSize:  newSize, LastDigest: lastDigest,
	}
	headBytes, err := encodeHead(nextHead)
	if err != nil {
		return err
	}
	if err := s.beginTransaction(auditTransaction{
		FormatVersion: formatVersion, Kind: transactionAppend,
		Scope: ledger.scope, Previous: &previousHead, Next: nextHead,
	}); err != nil {
		return err
	}

	ledgerPath := filepath.Join(tenantPath, ledgerFileName)
	file, err := openAuditAppend(ledgerPath)
	if err != nil {
		return fmt.Errorf("open tenant audit ledger for append: %w", err)
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != ledger.ledgerSize {
		return integrityError("audit ledger changed before append", nil)
	}
	written, err := file.Write(frame)
	if err != nil {
		return fmt.Errorf("append tenant audit ledger: %w", err)
	}
	if written != len(frame) {
		return fmt.Errorf("append tenant audit ledger: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync tenant audit ledger: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close tenant audit ledger: %w", err)
	}
	closeFile = false
	if err := s.atomicFile(filepath.Join(tenantPath, headFileName), headBytes, true); err != nil {
		return fmt.Errorf("advance tenant audit head: %w", err)
	}
	return s.finishTransaction()
}

func (s *Store) loadTenantLocked(
	scope protocol.TenantScope,
) (tenantLedger, bool, error) {
	tenantPath := s.tenantPath(scope.TenantID)
	info, err := os.Lstat(tenantPath)
	if errors.Is(err, os.ErrNotExist) {
		return tenantLedger{}, false, nil
	}
	if err != nil {
		return tenantLedger{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return tenantLedger{}, false, integrityError("tenant ledger path is not a real directory", nil)
	}
	ledger, err := s.readTenantDirectory(tenantPath, scope)
	return ledger, true, err
}

func (s *Store) readTenantDirectory(
	tenantPath string,
	scope protocol.TenantScope,
) (tenantLedger, error) {
	if filepath.Base(tenantPath) != tenantKey(scope.TenantID) {
		return tenantLedger{}, integrityError("tenant ledger path mismatch", nil)
	}
	entries, err := os.ReadDir(tenantPath)
	if err != nil {
		return tenantLedger{}, integrityError("read tenant ledger directory", err)
	}
	if len(entries) != 2 {
		return tenantLedger{}, integrityError("tenant ledger requires exactly ledger and head files", nil)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() != ledgerFileName && entry.Name() != headFileName {
			return tenantLedger{}, integrityError("unexpected tenant ledger file", nil)
		}
	}

	ledger, err := readLedgerFile(filepath.Join(tenantPath, ledgerFileName), scope)
	if err != nil {
		return tenantLedger{}, err
	}
	headData, err := readAuditFile(filepath.Join(tenantPath, headFileName), maxHeadFileSize)
	if err != nil {
		return tenantLedger{}, integrityError("read durable audit head", err)
	}
	head, err := decodeHead(headData)
	if err != nil {
		return tenantLedger{}, err
	}
	if head.Scope != scope || head.RecordCount != uint64(len(ledger.references)) ||
		head.LedgerSize != ledger.ledgerSize || head.LastDigest != ledger.lastDigest {
		return tenantLedger{}, integrityError("durable audit head does not match the ledger", nil)
	}
	return ledger, nil
}

func readLedgerFile(path string, expectedScope protocol.TenantScope) (tenantLedger, error) {
	file, err := openAuditRead(path)
	if err != nil {
		return tenantLedger{}, integrityError("open tenant audit ledger", err)
	}
	defer file.Close()
	initialInfo, err := file.Stat()
	if err != nil {
		return tenantLedger{}, integrityError("inspect tenant audit ledger", err)
	}
	if !initialInfo.Mode().IsRegular() || initialInfo.Size() <= 0 {
		return tenantLedger{}, integrityError("tenant audit ledger is not a non-empty regular file", nil)
	}
	ledger, consumed, err := decodeLedgerReader(file, expectedScope)
	if err != nil {
		return tenantLedger{}, err
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return tenantLedger{}, integrityError("reinspect tenant audit ledger", err)
	}
	if initialInfo.Size() != finalInfo.Size() || consumed != uint64(initialInfo.Size()) {
		return tenantLedger{}, integrityError("tenant audit ledger size changed or is truncated", nil)
	}
	ledger.ledgerSize = consumed
	return ledger, nil
}

func readLedgerPrefix(
	path string,
	expectedScope protocol.TenantScope,
	size uint64,
) (tenantLedger, error) {
	if size == 0 || size > uint64(^uint64(0)>>1) {
		return tenantLedger{}, integrityError("invalid audit ledger prefix size", nil)
	}
	file, err := openAuditRead(path)
	if err != nil {
		return tenantLedger{}, integrityError("open tenant audit ledger prefix", err)
	}
	defer file.Close()
	initialInfo, err := file.Stat()
	if err != nil {
		return tenantLedger{}, integrityError("inspect tenant audit ledger prefix", err)
	}
	if !initialInfo.Mode().IsRegular() || initialInfo.Size() < int64(size) {
		return tenantLedger{}, integrityError("tenant audit ledger prefix is truncated", nil)
	}
	reader := io.NewSectionReader(file, 0, int64(size))
	ledger, consumed, err := decodeLedgerReader(reader, expectedScope)
	if err != nil {
		return tenantLedger{}, err
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return tenantLedger{}, integrityError("reinspect tenant audit ledger prefix", err)
	}
	if initialInfo.Size() != finalInfo.Size() || consumed != size {
		return tenantLedger{}, integrityError("tenant audit ledger changed while reading its prefix", nil)
	}
	ledger.ledgerSize = consumed
	return ledger, nil
}

func decodeLedgerReader(
	reader io.Reader,
	expectedScope protocol.TenantScope,
) (tenantLedger, uint64, error) {
	header, consumed, err := decodeLedgerHeader(reader)
	if err != nil {
		return tenantLedger{}, 0, err
	}
	if header.Scope != expectedScope {
		return tenantLedger{}, 0, integrityError("tenant audit ledger crosses its tenant scope", nil)
	}
	ledger := tenantLedger{
		scope: header.Scope, references: []protocol.AuditRecordReference{},
		recordIDs: make(map[string]struct{}), lastDigest: header.GenesisDigest,
	}
	expectedSequence := uint64(1)
	for {
		frame, present, err := decodeFrame(reader)
		if err != nil {
			return tenantLedger{}, 0, err
		}
		if !present {
			break
		}
		consumed += frame.Size
		if frame.Sequence != expectedSequence {
			return tenantLedger{}, 0, integrityError("audit record frames are reordered or missing", nil)
		}
		reference := frame.Reference
		if err := reference.ValidateFor(header.Scope); err != nil {
			return tenantLedger{}, 0, integrityError("invalid audit record reference", err)
		}
		if reference.PreviousDigest != ledger.lastDigest {
			return tenantLedger{}, 0, integrityError("audit record predecessor is missing or crosses a chain", nil)
		}
		if _, duplicate := ledger.recordIDs[reference.RecordID]; duplicate {
			return tenantLedger{}, 0, integrityError("duplicate audit record id", nil)
		}
		computed, err := ComputeRecordDigest(header.Scope, reference)
		if err != nil || computed != reference.RecordDigest {
			return tenantLedger{}, 0, integrityError("audit record digest mismatch", err)
		}
		ledger.recordIDs[reference.RecordID] = struct{}{}
		ledger.references = append(ledger.references, reference)
		ledger.lastDigest = reference.RecordDigest
		expectedSequence++
	}
	if len(ledger.references) == 0 {
		return tenantLedger{}, 0, integrityError("tenant audit ledger has no records", nil)
	}
	return ledger, consumed, nil
}

func readLedgerHeaderFile(path string) (ledgerHeader, error) {
	file, err := openAuditRead(path)
	if err != nil {
		return ledgerHeader{}, integrityError("open tenant audit ledger header", err)
	}
	defer file.Close()
	header, _, err := decodeLedgerHeader(file)
	return header, err
}

func readAuditFile(path string, limit int64) ([]byte, error) {
	file, err := openAuditRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("audit file has an invalid size")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("audit file changed while reading")
	}
	return data, nil
}

func (s *Store) withExistingLock(
	ctx context.Context,
	operation func(rootExists bool) error,
) (err error) {
	s.threadLock.Lock()
	defer s.threadLock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(s.root)
	if errors.Is(err, os.ErrNotExist) {
		return operation(false)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return integrityError("audit store root is not a real directory", nil)
	}
	lockPath := filepath.Join(s.root, lockFileName)
	lockInfo, lockErr := os.Lstat(lockPath)
	if errors.Is(lockErr, os.ErrNotExist) {
		hasData, inspectErr := s.validateRootLayout(false, true)
		if inspectErr != nil {
			return inspectErr
		}
		if hasData {
			return integrityError("audit store data exists without its process lock", nil)
		}
		return operation(true)
	}
	if lockErr != nil {
		return lockErr
	}
	if lockInfo.Mode()&os.ModeSymlink != 0 || !lockInfo.Mode().IsRegular() || lockInfo.Size() != 0 {
		return integrityError("audit process lock is not an empty regular file", nil)
	}
	lock, err := acquireAuditFileLock(ctx, lockPath, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if _, err := s.validateRootLayout(true, true); err != nil {
		return err
	}
	if err := s.recoverTransactionLocked(); err != nil {
		return err
	}
	if _, err := s.validateRootLayout(true, false); err != nil {
		return err
	}
	return operation(true)
}

func (s *Store) withWriteLock(
	ctx context.Context,
	prewrite func() error,
	operation func() error,
) (err error) {
	s.threadLock.Lock()
	defer s.threadLock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if prewrite == nil || operation == nil {
		return ErrStoreUnavailable
	}
	if err := prewrite(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureAuditDirectoryDurably(s.root, s.syncDirectory); err != nil {
		return fmt.Errorf("create audit store root: %w", err)
	}
	lockPath := filepath.Join(s.root, lockFileName)
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != 0 {
			return integrityError("audit process lock is not an empty regular file", nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock, err := acquireAuditFileLock(ctx, lockPath, true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := s.syncDirectory(s.root); err != nil {
		return fmt.Errorf("sync audit lock directory: %w", err)
	}
	if _, err := s.validateRootLayout(true, true); err != nil {
		return err
	}
	if err := s.recoverTransactionLocked(); err != nil {
		return err
	}
	if _, err := s.validateRootLayout(true, false); err != nil {
		return err
	}
	return operation()
}

// validateRootLayout returns whether the root contains tenant ledger data.
func (s *Store) validateRootLayout(requireLock, allowRecoveryFiles bool) (bool, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return false, err
	}
	var hasLock, hasData bool
	for _, entry := range entries {
		switch entry.Name() {
		case lockFileName:
			if entry.IsDir() {
				return false, integrityError("audit process lock is a directory", nil)
			}
			hasLock = true
		case tenantsDirName:
			if !entry.IsDir() {
				return false, integrityError("audit tenants path is not a directory", nil)
			}
			tenantEntries, err := os.ReadDir(s.tenantsPath())
			if err != nil {
				return false, err
			}
			hasData = len(tenantEntries) > 0
		case transactionFileName, transactionPendingFileName:
			if !allowRecoveryFiles {
				return false, integrityError("unexpected audit transaction file", nil)
			}
			if entry.IsDir() {
				return false, integrityError("audit transaction path is a directory", nil)
			}
			hasData = true
		default:
			return false, integrityError("unexpected audit store root entry", nil)
		}
	}
	if requireLock && !hasLock {
		return false, integrityError("audit process lock is missing", nil)
	}
	return hasData, nil
}

func (s *Store) ensureDirectory(path string) error {
	if !pathWithinRoot(s.root, path) {
		return fmt.Errorf("%w: audit path escapes the store root", ErrInvalidInput)
	}
	return ensureAuditDirectoryDurably(path, s.syncDirectory)
}

func (s *Store) atomicFile(path string, data []byte, replace bool) error {
	if !pathWithinRoot(s.root, path) {
		return fmt.Errorf("%w: audit path escapes the store root", ErrInvalidInput)
	}
	return writeAuditFileAtomically(path, data, replace, s.syncDirectory)
}

func (s *Store) tenantsPath() string { return filepath.Join(s.root, tenantsDirName) }

func (s *Store) tenantPath(tenantID string) string {
	return filepath.Join(s.tenantsPath(), tenantKey(tenantID))
}

func tenantKey(tenantID string) string {
	digest := sha256.Sum256([]byte(tenantKeyDomain + "\x00" + tenantID))
	return hex.EncodeToString(digest[:])
}

func isTenantKey(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func pathWithinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, filepath.Clean(path))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
