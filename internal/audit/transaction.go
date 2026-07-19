package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	transactionChecksumDomain = "knote.audit.transaction.v1"
	maxTransactionFileSize    = 32 << 10

	transactionCreate transactionKind = "create"
	transactionAppend transactionKind = "append"
)

var transactionMagic = [8]byte{'K', 'N', 'A', 'U', 'D', 'T', '0', '1'}

type transactionKind string

type auditTransaction struct {
	FormatVersion string               `json:"format_version"`
	Kind          transactionKind      `json:"kind"`
	Scope         protocol.TenantScope `json:"scope"`
	Previous      *durableHead         `json:"previous,omitempty"`
	Next          durableHead          `json:"next"`
}

func encodeTransaction(transaction auditTransaction) ([]byte, error) {
	if err := validateTransaction(transaction); err != nil {
		return nil, err
	}
	return encodeMetadataEnvelope(transactionMagic, transactionChecksumDomain, transaction)
}

func decodeTransaction(data []byte) (auditTransaction, error) {
	var transaction auditTransaction
	reader := bytes.NewReader(data)
	consumed, err := decodeMetadataEnvelope(
		reader,
		transactionMagic,
		transactionChecksumDomain,
		&transaction,
	)
	if err != nil {
		return auditTransaction{}, err
	}
	if consumed != uint64(len(data)) || reader.Len() != 0 {
		return auditTransaction{}, integrityError("audit transaction has trailing bytes", nil)
	}
	if err := validateTransaction(transaction); err != nil {
		return auditTransaction{}, integrityError("invalid audit transaction", err)
	}
	return transaction, nil
}

func validateTransaction(transaction auditTransaction) error {
	if transaction.FormatVersion != formatVersion {
		return fmt.Errorf("unsupported transaction format")
	}
	if err := transaction.Scope.Validate(); err != nil {
		return err
	}
	if err := validateTransactionHead(transaction.Next, transaction.Scope); err != nil {
		return err
	}
	switch transaction.Kind {
	case transactionCreate:
		if transaction.Previous != nil || transaction.Next.RecordCount != 1 {
			return fmt.Errorf("invalid create transaction transition")
		}
	case transactionAppend:
		if transaction.Previous == nil {
			return fmt.Errorf("append transaction has no previous head")
		}
		if err := validateTransactionHead(*transaction.Previous, transaction.Scope); err != nil {
			return err
		}
		if transaction.Next.RecordCount != transaction.Previous.RecordCount+1 ||
			transaction.Next.LedgerSize <= transaction.Previous.LedgerSize {
			return fmt.Errorf("invalid append transaction transition")
		}
	default:
		return fmt.Errorf("unsupported transaction kind")
	}
	return nil
}

func validateTransactionHead(head durableHead, scope protocol.TenantScope) error {
	if head.FormatVersion != formatVersion || head.Scope != scope ||
		head.RecordCount == 0 || head.LedgerSize == 0 {
		return fmt.Errorf("invalid transaction head")
	}
	return head.LastDigest.Validate()
}

func durableHeadForLedger(ledger tenantLedger) durableHead {
	return durableHead{
		FormatVersion: formatVersion,
		Scope:         ledger.scope,
		RecordCount:   uint64(len(ledger.references)),
		LedgerSize:    ledger.ledgerSize,
		LastDigest:    ledger.lastDigest,
	}
}

func (s *Store) beginTransaction(transaction auditTransaction) (err error) {
	data, err := encodeTransaction(transaction)
	if err != nil {
		return err
	}
	transactionPath := filepath.Join(s.root, transactionFileName)
	pendingPath := filepath.Join(s.root, transactionPendingFileName)
	for _, path := range []string{transactionPath, pendingPath} {
		if _, err := os.Lstat(path); err == nil {
			return integrityError("audit transaction already exists", nil)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	file, err := os.OpenFile(pendingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create pending audit transaction: %w", err)
	}
	installed := false
	defer func() {
		if !installed {
			_ = file.Close()
			if removeErr := os.Remove(pendingPath); removeErr == nil {
				_ = s.syncDirectory(s.root)
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	written, err := file.Write(data)
	if err != nil {
		return fmt.Errorf("write pending audit transaction: %w", err)
	}
	if written != len(data) {
		return fmt.Errorf("write pending audit transaction: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync pending audit transaction: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pending audit transaction: %w", err)
	}
	if err := installAuditFile(pendingPath, transactionPath); err != nil {
		return fmt.Errorf("publish audit transaction: %w", err)
	}
	installed = true
	if err := s.syncDirectory(s.root); err != nil {
		return fmt.Errorf("sync audit transaction directory: %w", err)
	}
	return nil
}

func (s *Store) finishTransaction() error {
	path := filepath.Join(s.root, transactionFileName)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove completed audit transaction: %w", err)
	}
	if err := s.syncDirectory(s.root); err != nil {
		return fmt.Errorf("sync completed audit transaction: %w", err)
	}
	return nil
}

func (s *Store) recoverTransactionLocked() error {
	pendingPath := filepath.Join(s.root, transactionPendingFileName)
	if info, err := os.Lstat(pendingPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return integrityError("pending audit transaction is not a regular file", nil)
		}
		if err := os.Remove(pendingPath); err != nil {
			return fmt.Errorf("remove unpublished audit transaction: %w", err)
		}
		if err := s.syncDirectory(s.root); err != nil {
			return fmt.Errorf("sync unpublished audit transaction removal: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	transactionPath := filepath.Join(s.root, transactionFileName)
	if _, err := os.Lstat(transactionPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	data, err := readAuditFile(transactionPath, maxTransactionFileSize)
	if err != nil {
		return integrityError("read audit transaction", err)
	}
	transaction, err := decodeTransaction(data)
	if err != nil {
		return err
	}
	tenantPath := s.tenantPath(transaction.Scope.TenantID)
	switch transaction.Kind {
	case transactionCreate:
		if err := s.recoverCreateTransaction(tenantPath, transaction); err != nil {
			return err
		}
	case transactionAppend:
		if err := s.recoverAppendTransaction(tenantPath, transaction); err != nil {
			return err
		}
	default:
		return integrityError("unsupported audit transaction kind", nil)
	}
	return s.finishTransaction()
}

func (s *Store) recoverCreateTransaction(tenantPath string, transaction auditTransaction) error {
	info, err := os.Lstat(tenantPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return integrityError("transaction tenant path is not a real directory", nil)
	}
	if err := s.cleanTransactionTemps(tenantPath); err != nil {
		return err
	}
	entries, err := os.ReadDir(tenantPath)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if err := os.Remove(tenantPath); err != nil {
			return err
		}
		return s.syncDirectory(s.tenantsPath())
	}
	if err := validateRecoveryEntries(entries, true); err != nil {
		return err
	}
	ledger, ledgerExists, err := readRecoveryLedger(tenantPath, transaction.Scope)
	if err != nil {
		return err
	}
	head, headExists, err := readRecoveryHead(tenantPath)
	if err != nil {
		return err
	}
	if !ledgerExists || durableHeadForLedger(ledger) != transaction.Next {
		return integrityError("create transaction ledger does not match its intent", nil)
	}
	if headExists {
		if head != transaction.Next {
			return integrityError("create transaction head does not match its intent", nil)
		}
		return nil
	}
	headBytes, err := encodeHead(transaction.Next)
	if err != nil {
		return err
	}
	if err := s.atomicFile(filepath.Join(tenantPath, headFileName), headBytes, false); err != nil {
		return fmt.Errorf("recover tenant audit head: %w", err)
	}
	return nil
}

func (s *Store) recoverAppendTransaction(tenantPath string, transaction auditTransaction) error {
	if transaction.Previous == nil {
		return integrityError("append transaction has no previous head", nil)
	}
	info, err := os.Lstat(tenantPath)
	if err != nil {
		return integrityError("inspect append transaction tenant directory", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return integrityError("append transaction tenant path is not a real directory", nil)
	}
	if err := s.cleanTransactionTemps(tenantPath); err != nil {
		return err
	}
	entries, err := os.ReadDir(tenantPath)
	if err != nil {
		return integrityError("read append transaction tenant directory", err)
	}
	if err := validateRecoveryEntries(entries, false); err != nil {
		return err
	}
	state, err := s.recoverAppendLedgerState(tenantPath, transaction.Scope, *transaction.Previous, transaction.Next)
	if err != nil {
		return err
	}
	head, exists, err := readRecoveryHead(tenantPath)
	if err != nil {
		return err
	}
	if !exists {
		return integrityError("append transaction durable head is missing", nil)
	}
	switch state {
	case transactionLedgerPrevious:
		if head != *transaction.Previous {
			return integrityError("aborted append transaction head changed", nil)
		}
		return nil
	case transactionLedgerNext:
		if head == transaction.Next {
			return nil
		}
		if head != *transaction.Previous {
			return integrityError("append transaction head is neither previous nor next", nil)
		}
		headBytes, err := encodeHead(transaction.Next)
		if err != nil {
			return err
		}
		if err := s.atomicFile(filepath.Join(tenantPath, headFileName), headBytes, true); err != nil {
			return fmt.Errorf("recover advanced tenant audit head: %w", err)
		}
		return nil
	default:
		return integrityError("unknown append transaction ledger state", nil)
	}
}

type transactionLedgerState uint8

const (
	transactionLedgerPrevious transactionLedgerState = iota + 1
	transactionLedgerNext
)

func (s *Store) recoverAppendLedgerState(
	tenantPath string,
	scope protocol.TenantScope,
	previous durableHead,
	next durableHead,
) (transactionLedgerState, error) {
	path := filepath.Join(tenantPath, ledgerFileName)
	info, err := os.Lstat(path)
	if err != nil {
		return 0, integrityError("inspect append transaction ledger", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return 0, integrityError("append transaction ledger is not a regular file", nil)
	}
	size := uint64(info.Size())
	switch {
	case size == previous.LedgerSize:
		ledger, err := readLedgerFile(path, scope)
		if err != nil || durableHeadForLedger(ledger) != previous {
			return 0, integrityError("append transaction previous ledger mismatch", err)
		}
		return transactionLedgerPrevious, nil
	case size == next.LedgerSize:
		ledger, err := readLedgerFile(path, scope)
		if err != nil || durableHeadForLedger(ledger) != next {
			return 0, integrityError("append transaction next ledger mismatch", err)
		}
		return transactionLedgerNext, nil
	case size > previous.LedgerSize && size < next.LedgerSize:
		ledger, err := readLedgerPrefix(path, scope, previous.LedgerSize)
		if err != nil || durableHeadForLedger(ledger) != previous {
			return 0, integrityError("partial append does not preserve the previous ledger", err)
		}
		if err := truncateAuditFile(path, int64(previous.LedgerSize)); err != nil {
			return 0, fmt.Errorf("roll back partial audit append: %w", err)
		}
		return transactionLedgerPrevious, nil
	default:
		return 0, integrityError("append transaction ledger size is outside its transition", nil)
	}
}

func readRecoveryLedger(tenantPath string, scope protocol.TenantScope) (tenantLedger, bool, error) {
	path := filepath.Join(tenantPath, ledgerFileName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return tenantLedger{}, false, nil
	} else if err != nil {
		return tenantLedger{}, false, err
	}
	ledger, err := readLedgerFile(path, scope)
	return ledger, true, err
}

func readRecoveryHead(tenantPath string) (durableHead, bool, error) {
	path := filepath.Join(tenantPath, headFileName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return durableHead{}, false, nil
	} else if err != nil {
		return durableHead{}, false, err
	}
	data, err := readAuditFile(path, maxHeadFileSize)
	if err != nil {
		return durableHead{}, false, integrityError("read transaction durable head", err)
	}
	head, err := decodeHead(data)
	return head, true, err
}

func validateRecoveryEntries(entries []os.DirEntry, allowMissingHead bool) error {
	var ledger, head bool
	for _, entry := range entries {
		if entry.IsDir() {
			return integrityError("unexpected transaction tenant directory", nil)
		}
		switch entry.Name() {
		case ledgerFileName:
			ledger = true
		case headFileName:
			head = true
		default:
			return integrityError("unexpected transaction tenant file", nil)
		}
	}
	if !ledger || !allowMissingHead && !head {
		return integrityError("transaction tenant files are incomplete", nil)
	}
	return nil
}

func (s *Store) cleanTransactionTemps(tenantPath string) error {
	info, err := os.Lstat(tenantPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return integrityError("transaction tenant path is not a real directory", nil)
	}
	entries, err := os.ReadDir(tenantPath)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".audit-") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		path := filepath.Join(tenantPath, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return integrityError("audit transaction temporary path is not a regular file", nil)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return s.syncDirectory(tenantPath)
	}
	return nil
}
