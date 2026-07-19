package residency

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	// ErrDenied is returned for every runtime residency denial. The gate does
	// not expose provider or policy details across the protected boundary.
	ErrDenied = errors.New("residency authorization denied")

	// ErrInvalidConfiguration identifies construction-time failures in trusted
	// scope, provider, or destination configuration.
	ErrInvalidConfiguration = errors.New("invalid residency configuration")
)

// PolicyProvider returns the authoritative current residency policy for the
// trusted tenant scope. Implementations must return an immutable value snapshot
// and synchronize policy rotation with CurrentPolicy calls.
type PolicyProvider interface {
	CurrentPolicy(context.Context, protocol.TenantScope) (protocol.ResidencyPolicy, error)
}

// PolicyProviderFunc adapts a function to PolicyProvider.
type PolicyProviderFunc func(context.Context, protocol.TenantScope) (protocol.ResidencyPolicy, error)

func (f PolicyProviderFunc) CurrentPolicy(
	ctx context.Context,
	scope protocol.TenantScope,
) (protocol.ResidencyPolicy, error) {
	return f(ctx, scope)
}

// Destination is trusted operator configuration for one operation and data
// class. Region values must never be populated from tool or model arguments.
type Destination struct {
	Operation protocol.ResidencyOperationKind
	DataClass protocol.ResidencyDataClass
	Region    string
}

// DestinationConfig is copied by NewGate. Later caller mutation cannot change
// the regions enforced by an existing gate.
type DestinationConfig []Destination

type destinationKey struct {
	operation protocol.ResidencyOperationKind
	dataClass protocol.ResidencyDataClass
	region    string
}

// Gate authorizes one trusted tenant scope against current policy and trusted
// destinations. A Gate created by NewGate is safe for concurrent use.
type Gate struct {
	scope        protocol.TenantScope
	provider     PolicyProvider
	destinations map[destinationKey]struct{}

	// Provider calls are serialized so a provider need not support concurrent
	// reads. Policy rotation still belongs to the provider's synchronization.
	providerMu sync.Mutex
}

// NewGate validates and snapshots all trusted gate configuration. It does not
// fetch policy: an unavailable or missing policy must fail closed at each use.
func NewGate(
	scope protocol.TenantScope,
	provider PolicyProvider,
	destinations DestinationConfig,
) (*Gate, error) {
	if err := scope.Validate(); err != nil {
		return nil, invalidConfiguration("tenant scope: %v", err)
	}
	if isNilProvider(provider) {
		return nil, invalidConfiguration("policy provider is required")
	}
	if len(destinations) == 0 {
		return nil, invalidConfiguration("at least one trusted destination is required")
	}

	trusted := make(map[destinationKey]struct{}, len(destinations))
	for index, destination := range destinations {
		if !knownOperation(destination.Operation) {
			return nil, invalidConfiguration(
				"destination %d has unsupported operation %q",
				index,
				destination.Operation,
			)
		}
		if !knownDataClass(destination.DataClass) {
			return nil, invalidConfiguration(
				"destination %d has unsupported data class %q",
				index,
				destination.DataClass,
			)
		}
		if !canonicalRegion(destination.Region) {
			return nil, invalidConfiguration(
				"destination %d has invalid region %q",
				index,
				destination.Region,
			)
		}

		key := destinationKey{
			operation: destination.Operation,
			dataClass: destination.DataClass,
			region:    destination.Region,
		}
		if _, duplicate := trusted[key]; duplicate {
			return nil, invalidConfiguration(
				"destination %d duplicates operation %q, data class %q, and region %q",
				index,
				destination.Operation,
				destination.DataClass,
				destination.Region,
			)
		}
		trusted[key] = struct{}{}
	}

	return &Gate{
		scope:        scope,
		provider:     provider,
		destinations: trusted,
	}, nil
}

// Authorize checks a complete request against the authoritative current policy
// and the configured destination. Requests must pin the exact trusted tenant
// and current policy watermark.
func (g *Gate) Authorize(ctx context.Context, request protocol.ResidencyCheckRequest) error {
	if g == nil || ctx == nil || ctx.Err() != nil || isNilProvider(g.provider) {
		return ErrDenied
	}
	if err := g.scope.Validate(); err != nil {
		return ErrDenied
	}
	if request.Version != protocol.EnterpriseContractVersion ||
		request.TenantID != g.scope.TenantID {
		return ErrDenied
	}

	_, configured := g.destinations[destinationKey{
		operation: request.Operation,
		dataClass: request.DataClass,
		region:    request.DestinationRegion,
	}]
	if !configured {
		return ErrDenied
	}

	policy, err := g.currentPolicy(ctx)
	if err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	if err := request.ValidateFor(policy, g.scope); err != nil {
		return ErrDenied
	}
	return nil
}

// Check is an alias for Authorize.
func (g *Gate) Check(ctx context.Context, request protocol.ResidencyCheckRequest) error {
	return g.Authorize(ctx, request)
}

// Execute invokes callback exactly once only after the complete residency
// request has been authorized.
func (g *Gate) Execute(
	ctx context.Context,
	request protocol.ResidencyCheckRequest,
	callback func(context.Context) error,
) error {
	return g.execute(ctx, request, "", callback)
}

// Store executes a persistence callback only after a store authorization.
func (g *Gate) Store(
	ctx context.Context,
	request protocol.ResidencyCheckRequest,
	callback func(context.Context) error,
) error {
	return g.execute(ctx, request, protocol.ResidencyStore, callback)
}

// Process executes a processing callback only after a process authorization.
func (g *Gate) Process(
	ctx context.Context,
	request protocol.ResidencyCheckRequest,
	callback func(context.Context) error,
) error {
	return g.execute(ctx, request, protocol.ResidencyProcess, callback)
}

// Egress executes a network callback only after an egress authorization.
func (g *Gate) Egress(
	ctx context.Context,
	request protocol.ResidencyCheckRequest,
	callback func(context.Context) error,
) error {
	return g.execute(ctx, request, protocol.ResidencyEgress, callback)
}

func (g *Gate) execute(
	ctx context.Context,
	request protocol.ResidencyCheckRequest,
	requiredOperation protocol.ResidencyOperationKind,
	callback func(context.Context) error,
) error {
	if callback == nil || requiredOperation != "" && request.Operation != requiredOperation {
		return ErrDenied
	}
	if err := g.Authorize(ctx, request); err != nil {
		return ErrDenied
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	return callback(ctx)
}

func (g *Gate) currentPolicy(ctx context.Context) (protocol.ResidencyPolicy, error) {
	g.providerMu.Lock()
	defer g.providerMu.Unlock()

	if ctx.Err() != nil {
		return protocol.ResidencyPolicy{}, ErrDenied
	}
	policy, err := g.provider.CurrentPolicy(ctx, g.scope)
	if err != nil || ctx.Err() != nil {
		return protocol.ResidencyPolicy{}, ErrDenied
	}
	policy = clonePolicy(policy)
	if err := policy.ValidateFor(g.scope); err != nil {
		return protocol.ResidencyPolicy{}, ErrDenied
	}
	return policy, nil
}

func clonePolicy(policy protocol.ResidencyPolicy) protocol.ResidencyPolicy {
	policy.StorageRegions = cloneStrings(policy.StorageRegions)
	policy.ProcessingRegions = cloneStrings(policy.ProcessingRegions)
	policy.EgressRegions = cloneStrings(policy.EgressRegions)
	return policy
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append(make([]string, 0, len(values)), values...)
}

func knownOperation(operation protocol.ResidencyOperationKind) bool {
	switch operation {
	case protocol.ResidencyStore, protocol.ResidencyProcess, protocol.ResidencyEgress:
		return true
	default:
		return false
	}
}

func knownDataClass(dataClass protocol.ResidencyDataClass) bool {
	switch dataClass {
	case protocol.ResidencyProtectedContent,
		protocol.ResidencyIdentity,
		protocol.ResidencyACL,
		protocol.ResidencyAudit,
		protocol.ResidencyTelemetry,
		protocol.ResidencyBackup:
		return true
	default:
		return false
	}
}

func canonicalRegion(region string) bool {
	if len(region) == 0 || len(region) > 32 {
		return false
	}
	for index, character := range []byte(region) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && character == '-' {
			continue
		}
		return false
	}
	return true
}

func isNilProvider(provider PolicyProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func invalidConfiguration(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfiguration, fmt.Sprintf(format, values...))
}
