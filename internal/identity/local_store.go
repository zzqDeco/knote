package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	registryFileName = "registry.json"
	tenantDirectory  = "tenants"
)

type localStoreConfig struct {
	clock Clock
}

type LocalStoreOption func(*localStoreConfig) error

func WithClock(clock Clock) LocalStoreOption {
	return func(config *localStoreConfig) error {
		if clock == nil {
			return fmt.Errorf("%w: clock is required", ErrInvalidInput)
		}
		config.clock = clock
		return nil
	}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type LocalStore struct {
	root        string
	clock       Clock
	lock        *sync.Mutex
	processLock *processLock
}

type registryState struct {
	Version string               `json:"version"`
	Tenants []tenantRegistration `json:"tenants"`
}

type tenantRegistration struct {
	Version      string    `json:"version"`
	TenantID     string    `json:"tenant_id"`
	Region       string    `json:"region"`
	FileKey      string    `json:"file_key"`
	RegisteredAt time.Time `json:"registered_at"`
}

type tenantState struct {
	Version    string               `json:"version"`
	Scope      protocol.TenantScope `json:"scope"`
	Providers  []Provider           `json:"providers"`
	Users      []User               `json:"users"`
	Groups     []Group              `json:"groups"`
	Tombstones []Tombstone          `json:"tombstones"`
	Replays    []replayRecord       `json:"replays"`
	Revisions  []TenantRevision     `json:"revisions"`
}

type replayRecord struct {
	Digest    ReplayDigest `json:"digest"`
	ExpiresAt time.Time    `json:"expires_at"`
}

var localStoreLocks sync.Map

func OpenLocalStore(root string, options ...LocalStoreOption) (*LocalStore, error) {
	if root == "" || root != strings.TrimSpace(root) {
		return nil, fmt.Errorf("%w: identity store path is invalid", ErrInvalidInput)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("%w: identity store path is invalid", ErrInvalidInput)
	}
	config := localStoreConfig{clock: systemClock{}}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: local store option is nil", ErrInvalidInput)
		}
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(absolute, tenantDirectory), 0o700); err != nil {
		return nil, storeFailure("create identity store", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, publicationDirectory), 0o700); err != nil {
		return nil, storeFailure("create identity publication store", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, storeFailure("resolve identity store", err)
	}
	absolute = resolvedRoot
	if err := ensurePrivateDirectory(absolute); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Join(absolute, tenantDirectory)); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Join(absolute, publicationDirectory)); err != nil {
		return nil, err
	}
	lockValue, _ := localStoreLocks.LoadOrStore(absolute, &sync.Mutex{})
	store := &LocalStore{
		root: absolute, clock: config.clock, lock: lockValue.(*sync.Mutex), processLock: newProcessLock(absolute),
	}
	release, err := store.acquireStoreLock(context.Background())
	if err != nil {
		return nil, err
	}
	defer release()
	registry, err := store.loadRegistryLocked()
	if errors.Is(err, os.ErrNotExist) {
		registry = registryState{Version: localStoreVersion, Tenants: []tenantRegistration{}}
		if err := store.writeRegistryLocked(registry); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := validateRegistry(registry); err != nil {
		return nil, err
	}
	for _, tenant := range registry.Tenants {
		state, err := store.loadTenantByRegistrationLocked(tenant)
		if err != nil {
			return nil, err
		}
		if err := validateTenantState(state); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *LocalStore) RegisterTenant(ctx context.Context, scope protocol.TenantScope) (Change, error) {
	if s == nil || s.lock == nil || s.processLock == nil || s.clock == nil || ctx == nil {
		return Change{}, ErrStoreUnavailable
	}
	if err := validateScope(scope); err != nil {
		return Change{}, err
	}
	if err := ctx.Err(); err != nil {
		return Change{}, err
	}
	release, err := s.acquireStoreLock(ctx)
	if err != nil {
		return Change{}, err
	}
	defer release()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return Change{}, err
	}
	if index := registrationIndex(registry, scope.TenantID); index >= 0 {
		registration := registry.Tenants[index]
		if registration.Region != scope.Region {
			return Change{}, ErrConflict
		}
		state, err := s.loadTenantByRegistrationLocked(registration)
		if err != nil {
			return Change{}, err
		}
		return Change{Revision: currentRevision(state)}, nil
	}
	now, err := s.now()
	if err != nil {
		return Change{}, err
	}
	state := tenantState{
		Version:   localStoreVersion,
		Scope:     scope,
		Providers: []Provider{}, Users: []User{}, Groups: []Group{},
		Tombstones: []Tombstone{}, Replays: []replayRecord{}, Revisions: []TenantRevision{},
	}
	if err := appendRevision(&state, RevisionTenantRegistered, now); err != nil {
		return Change{}, err
	}
	registration := tenantRegistration{
		Version: protocol.EnterpriseContractVersion, TenantID: scope.TenantID,
		Region: scope.Region, FileKey: tenantFileKey(scope.TenantID), RegisteredAt: now,
	}
	if err := s.writeTenantLocked(registration, state); err != nil {
		return Change{}, err
	}
	registry.Tenants = append(registry.Tenants, registration)
	canonicalizeRegistry(&registry)
	if err := s.writeRegistryLocked(registry); err != nil {
		return Change{}, err
	}
	return Change{Changed: true, Revision: currentRevision(state)}, nil
}

func (s *LocalStore) Tenant(ctx context.Context, tenantID string) (protocol.TenantScope, error) {
	if s == nil || s.lock == nil || s.processLock == nil || ctx == nil {
		return protocol.TenantScope{}, ErrStoreUnavailable
	}
	if err := validateCanonicalID("tenant_id", tenantID); err != nil {
		return protocol.TenantScope{}, ErrIdentityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return protocol.TenantScope{}, err
	}
	release, err := s.acquireStoreLock(ctx)
	if err != nil {
		return protocol.TenantScope{}, err
	}
	defer release()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return protocol.TenantScope{}, err
	}
	index := registrationIndex(registry, tenantID)
	if index < 0 {
		return protocol.TenantScope{}, ErrIdentityUnavailable
	}
	registration := registry.Tenants[index]
	return protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: registration.TenantID,
		Region:   registration.Region,
	}, nil
}

func (s *LocalStore) Snapshot(ctx context.Context, scope protocol.TenantScope) (TenantSnapshot, error) {
	state, err := s.readTenant(ctx, scope)
	if err != nil {
		return TenantSnapshot{}, err
	}
	return snapshotFromState(state), nil
}

func (s *LocalStore) CurrentRevision(ctx context.Context, scope protocol.TenantScope) (TenantRevision, error) {
	state, err := s.readTenant(ctx, scope)
	if err != nil {
		return TenantRevision{}, err
	}
	return currentRevision(state), nil
}

func (s *LocalStore) Provider(ctx context.Context, scope protocol.TenantScope, providerID string) (Provider, error) {
	if err := validateCanonicalID("provider_id", providerID); err != nil {
		return Provider{}, ErrIdentityUnavailable
	}
	state, err := s.readTenant(ctx, scope)
	if err != nil {
		return Provider{}, err
	}
	index := providerIndex(state, providerID)
	if index < 0 {
		return Provider{}, ErrIdentityUnavailable
	}
	return copyProvider(state.Providers[index]), nil
}

func (s *LocalStore) readTenant(ctx context.Context, scope protocol.TenantScope) (tenantState, error) {
	if s == nil || s.lock == nil || s.processLock == nil || ctx == nil {
		return tenantState{}, ErrStoreUnavailable
	}
	if err := validateScope(scope); err != nil {
		return tenantState{}, ErrIdentityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return tenantState{}, err
	}
	release, err := s.acquireStoreLock(ctx)
	if err != nil {
		return tenantState{}, err
	}
	defer release()
	return s.loadTenantForScopeLocked(scope)
}

func (s *LocalStore) updateTenant(
	ctx context.Context,
	scope protocol.TenantScope,
	reason RevisionReason,
	mutate func(*tenantState, time.Time, uint64) (bool, error),
) (tenantState, Change, error) {
	if s == nil || s.lock == nil || s.processLock == nil || s.clock == nil || ctx == nil || mutate == nil {
		return tenantState{}, Change{}, ErrStoreUnavailable
	}
	if err := validateScope(scope); err != nil {
		return tenantState{}, Change{}, ErrIdentityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return tenantState{}, Change{}, err
	}
	release, err := s.acquireStoreLock(ctx)
	if err != nil {
		return tenantState{}, Change{}, err
	}
	defer release()
	state, registration, err := s.loadTenantAndRegistrationLocked(scope)
	if err != nil {
		return tenantState{}, Change{}, err
	}
	now, err := s.now()
	if err != nil {
		return tenantState{}, Change{}, err
	}
	nextRevision := currentRevision(state).Number + 1
	changed, err := mutate(&state, now, nextRevision)
	if err != nil {
		return tenantState{}, Change{}, err
	}
	if !changed {
		return state, Change{Revision: currentRevision(state)}, nil
	}
	if err := appendRevision(&state, reason, now); err != nil {
		return tenantState{}, Change{}, err
	}
	if err := ctx.Err(); err != nil {
		return tenantState{}, Change{}, err
	}
	if err := s.writeTenantLocked(registration, state); err != nil {
		return tenantState{}, Change{}, err
	}
	return state, Change{Changed: true, Revision: currentRevision(state)}, nil
}

func (s *LocalStore) loadTenantForScopeLocked(scope protocol.TenantScope) (tenantState, error) {
	state, _, err := s.loadTenantAndRegistrationLocked(scope)
	return state, err
}

func (s *LocalStore) loadTenantAndRegistrationLocked(scope protocol.TenantScope) (tenantState, tenantRegistration, error) {
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return tenantState{}, tenantRegistration{}, err
	}
	index := registrationIndex(registry, scope.TenantID)
	if index < 0 || registry.Tenants[index].Region != scope.Region {
		return tenantState{}, tenantRegistration{}, ErrIdentityUnavailable
	}
	registration := registry.Tenants[index]
	state, err := s.loadTenantByRegistrationLocked(registration)
	if err != nil {
		return tenantState{}, tenantRegistration{}, err
	}
	if state.Scope != scope {
		return tenantState{}, tenantRegistration{}, ErrIdentityUnavailable
	}
	return state, registration, nil
}

func (s *LocalStore) loadRegistryLocked() (registryState, error) {
	var registry registryState
	if err := readStrictJSON(filepath.Join(s.root, registryFileName), &registry); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return registryState{}, os.ErrNotExist
		}
		return registryState{}, storeFailure("read tenant registry", err)
	}
	if err := validateRegistry(registry); err != nil {
		return registryState{}, err
	}
	return registry, nil
}

func (s *LocalStore) loadTenantByRegistrationLocked(registration tenantRegistration) (tenantState, error) {
	var state tenantState
	if err := readStrictJSON(s.tenantPath(registration), &state); err != nil {
		return tenantState{}, storeFailure("read tenant identity state", err)
	}
	if err := validateTenantState(state); err != nil {
		return tenantState{}, err
	}
	if state.Scope.TenantID != registration.TenantID || state.Scope.Region != registration.Region {
		return tenantState{}, ErrStoreUnavailable
	}
	return state, nil
}

func (s *LocalStore) writeRegistryLocked(registry registryState) error {
	canonicalizeRegistry(&registry)
	if err := validateRegistry(registry); err != nil {
		return err
	}
	return atomicWriteJSON(filepath.Join(s.root, registryFileName), registry)
}

func (s *LocalStore) writeTenantLocked(registration tenantRegistration, state tenantState) error {
	canonicalizeTenantState(&state)
	if err := validateTenantState(state); err != nil {
		return err
	}
	return atomicWriteJSON(s.tenantPath(registration), state)
}

func (s *LocalStore) tenantPath(registration tenantRegistration) string {
	return filepath.Join(s.root, tenantDirectory, registration.FileKey+".json")
}

func (s *LocalStore) now() (time.Time, error) {
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", ErrStoreUnavailable)
	}
	return now, nil
}

func (s *LocalStore) acquireStoreLock(ctx context.Context) (func(), error) {
	if s == nil || s.lock == nil || s.processLock == nil || ctx == nil {
		return nil, ErrStoreUnavailable
	}
	s.lock.Lock()
	if err := ctx.Err(); err != nil {
		s.lock.Unlock()
		return nil, err
	}
	releaseProcess, err := s.processLock.acquire(ctx)
	if err != nil {
		s.lock.Unlock()
		return nil, err
	}
	return func() {
		releaseProcess()
		s.lock.Unlock()
	}, nil
}

func readStrictJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("identity state has trailing data")
	}
	return nil
}

func atomicWriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return storeFailure("encode identity state", err)
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return storeFailure("create identity state directory", err)
	}
	temporary, err := os.CreateTemp(directory, ".identity-*.tmp")
	if err != nil {
		return storeFailure("stage identity state", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return storeFailure("protect identity state", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return storeFailure("write identity state", err)
	}
	if err := temporary.Sync(); err != nil {
		return storeFailure("sync identity state", err)
	}
	if err := temporary.Close(); err != nil {
		return storeFailure("close identity state", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return storeFailure("publish identity state", err)
	}
	if err := syncIdentityDirectory(directory); err != nil {
		return storeFailure("sync identity state directory", err)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return storeFailure("inspect identity store", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: identity store is not a directory", ErrStoreUnavailable)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return storeFailure("protect identity store", err)
		}
	}
	return nil
}

func storeFailure(operation string, err error) error {
	if err == nil {
		return ErrStoreUnavailable
	}
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}

var _ IdentityDirectory = (*LocalStore)(nil)
var _ NonceStore = (*LocalStore)(nil)
