package residency

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

var residencyDataClasses = []protocol.ResidencyDataClass{
	protocol.ResidencyProtectedContent,
	protocol.ResidencyIdentity,
	protocol.ResidencyACL,
	protocol.ResidencyAudit,
	protocol.ResidencyTelemetry,
	protocol.ResidencyBackup,
}

func TestGateExecutesEveryOperationAndDataClass(t *testing.T) {
	scope := testTenantScope()
	provider := newRotatingPolicyProvider(scope, testPolicy("residency-v1"))
	gate := mustGate(t, scope, provider, testDestinations())

	var callbacks atomic.Int64
	for _, operation := range []protocol.ResidencyOperationKind{
		protocol.ResidencyStore,
		protocol.ResidencyProcess,
		protocol.ResidencyEgress,
	} {
		for _, dataClass := range residencyDataClasses {
			operation := operation
			dataClass := dataClass
			t.Run(string(operation)+"/"+string(dataClass), func(t *testing.T) {
				request := testRequest(operation, dataClass, testDestinationRegion(operation), "residency-v1")
				callback := func(context.Context) error {
					callbacks.Add(1)
					return nil
				}

				var err error
				switch operation {
				case protocol.ResidencyStore:
					err = gate.Store(context.Background(), request, callback)
				case protocol.ResidencyProcess:
					err = gate.Process(context.Background(), request, callback)
				case protocol.ResidencyEgress:
					err = gate.Egress(context.Background(), request, callback)
				}
				if err != nil {
					t.Fatalf("authorized callback: %v", err)
				}
			})
		}
	}

	want := int64(3 * len(residencyDataClasses))
	if got := callbacks.Load(); got != want {
		t.Fatalf("callback calls = %d, want %d", got, want)
	}
	if got := provider.calls.Load(); got != want {
		t.Fatalf("policy provider calls = %d, want %d", got, want)
	}
}

func TestGateFailsClosedForInvalidRequestsAndPolicies(t *testing.T) {
	errUnavailable := errors.New("policy unavailable")
	tests := []struct {
		name         string
		change       func(*protocol.ResidencyCheckRequest, *protocol.ResidencyPolicy)
		providerErr  error
		destinations DestinationConfig
	}{
		{
			name: "missing policy",
			change: func(_ *protocol.ResidencyCheckRequest, policy *protocol.ResidencyPolicy) {
				*policy = protocol.ResidencyPolicy{}
			},
		},
		{name: "provider failure", providerErr: errUnavailable},
		{
			name: "stale policy watermark",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.PolicyWatermark = "residency-v0"
			},
		},
		{
			name: "missing policy watermark",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.PolicyWatermark = ""
			},
		},
		{
			name: "request tenant mismatch",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.TenantID = "tenant-b"
			},
		},
		{
			name: "policy tenant mismatch",
			change: func(_ *protocol.ResidencyCheckRequest, policy *protocol.ResidencyPolicy) {
				policy.TenantID = "tenant-b"
			},
		},
		{
			name: "policy region mismatch",
			change: func(_ *protocol.ResidencyCheckRequest, policy *protocol.ResidencyPolicy) {
				policy.HomeRegion = "cn-north"
			},
		},
		{
			name: "unsupported request version",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.Version = "v2"
			},
		},
		{
			name: "missing request id",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.RequestID = ""
			},
		},
		{
			name: "unknown operation",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.Operation = "replicate"
			},
		},
		{
			name: "unknown data class",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.DataClass = "credentials"
			},
		},
		{
			name: "caller selected another allowed region",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.DestinationRegion = "cn-east"
			},
		},
		{
			name: "unknown region",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.DestinationRegion = "moon-1"
			},
		},
		{
			name: "malformed region",
			change: func(request *protocol.ResidencyCheckRequest, _ *protocol.ResidencyPolicy) {
				request.DestinationRegion = "CN-NORTH"
			},
		},
		{
			name: "policy denies trusted destination",
			change: func(_ *protocol.ResidencyCheckRequest, policy *protocol.ResidencyPolicy) {
				policy.StorageRegions = []string{"cn-east"}
			},
		},
		{
			name: "destination is not configured for the class",
			destinations: DestinationConfig{
				{
					Operation: protocol.ResidencyProcess,
					DataClass: protocol.ResidencyProtectedContent,
					Region:    "cn-east",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scope := testTenantScope()
			policy := testPolicy("residency-v1")
			request := testRequest(
				protocol.ResidencyStore,
				protocol.ResidencyProtectedContent,
				"cn-north",
				policy.PolicyWatermark,
			)
			if test.change != nil {
				test.change(&request, &policy)
			}
			provider := newRotatingPolicyProvider(scope, policy)
			provider.err = test.providerErr
			destinations := test.destinations
			if destinations == nil {
				destinations = testDestinations()
			}
			gate := mustGate(t, scope, provider, destinations)

			var sideEffects atomic.Int64
			err := gate.Execute(context.Background(), request, func(context.Context) error {
				sideEffects.Add(1)
				return nil
			})
			assertDenied(t, err)
			if got := sideEffects.Load(); got != 0 {
				t.Fatalf("denial reached %d protected callbacks", got)
			}
		})
	}
}

func TestOperationWrappersDenyBeforeWriteNetworkAndSubprocess(t *testing.T) {
	scope := testTenantScope()
	provider := newRotatingPolicyProvider(scope, testPolicy("residency-v1"))
	gate := mustGate(t, scope, provider, testDestinations())

	var writes atomic.Int64
	store := testRequest(
		protocol.ResidencyStore,
		protocol.ResidencyBackup,
		"cn-north",
		"residency-v0",
	)
	assertDenied(t, gate.Store(context.Background(), store, func(context.Context) error {
		writes.Add(1)
		return nil
	}))

	var subprocesses atomic.Int64
	process := testRequest(
		protocol.ResidencyProcess,
		protocol.ResidencyProtectedContent,
		"cn-east",
		"residency-v1",
	)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	assertDenied(t, gate.Process(cancelled, process, func(context.Context) error {
		subprocesses.Add(1)
		return nil
	}))

	var networkCalls atomic.Int64
	egress := testRequest(
		protocol.ResidencyEgress,
		protocol.ResidencyTelemetry,
		"cn-east",
		"residency-v1",
	)
	assertDenied(t, gate.Egress(context.Background(), egress, func(context.Context) error {
		networkCalls.Add(1)
		return nil
	}))

	if writes.Load() != 0 || subprocesses.Load() != 0 || networkCalls.Load() != 0 {
		t.Fatalf(
			"denials reached side effects: writes=%d subprocesses=%d network=%d",
			writes.Load(),
			subprocesses.Load(),
			networkCalls.Load(),
		)
	}
}

func TestGatePolicyRotationInvalidatesOldWatermark(t *testing.T) {
	scope := testTenantScope()
	provider := newRotatingPolicyProvider(scope, testPolicy("residency-v1"))
	gate := mustGate(t, scope, provider, testDestinations())
	requestV1 := testRequest(
		protocol.ResidencyStore,
		protocol.ResidencyAudit,
		"cn-north",
		"residency-v1",
	)

	var writes atomic.Int64
	write := func(context.Context) error {
		writes.Add(1)
		return nil
	}
	if err := gate.Store(context.Background(), requestV1, write); err != nil {
		t.Fatalf("v1 store: %v", err)
	}

	provider.rotate(testPolicy("residency-v2"))
	assertDenied(t, gate.Store(context.Background(), requestV1, write))
	if got := writes.Load(); got != 1 {
		t.Fatalf("stale watermark reached callback: writes = %d", got)
	}

	requestV2 := requestV1
	requestV2.PolicyWatermark = "residency-v2"
	requestV2.RequestID = "request-store-audit-v2"
	if err := gate.Store(context.Background(), requestV2, write); err != nil {
		t.Fatalf("v2 store: %v", err)
	}
	if got := writes.Load(); got != 2 {
		t.Fatalf("writes after policy rotation = %d, want 2", got)
	}
	if got := provider.calls.Load(); got != 3 {
		t.Fatalf("policy provider calls = %d, want 3", got)
	}
}

func TestGateRejectsNilAndCancelledInputsBeforeCallback(t *testing.T) {
	scope := testTenantScope()
	policy := testPolicy("residency-v1")
	request := testRequest(
		protocol.ResidencyProcess,
		protocol.ResidencyProtectedContent,
		"cn-east",
		policy.PolicyWatermark,
	)

	t.Run("nil context", func(t *testing.T) {
		provider := newRotatingPolicyProvider(scope, policy)
		gate := mustGate(t, scope, provider, testDestinations())
		var calls atomic.Int64
		assertDenied(t, gate.Process(nil, request, func(context.Context) error {
			calls.Add(1)
			return nil
		}))
		if provider.calls.Load() != 0 || calls.Load() != 0 {
			t.Fatalf("nil context reached provider or callback: provider=%d callback=%d", provider.calls.Load(), calls.Load())
		}
	})

	t.Run("cancelled before provider", func(t *testing.T) {
		provider := newRotatingPolicyProvider(scope, policy)
		gate := mustGate(t, scope, provider, testDestinations())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var calls atomic.Int64
		assertDenied(t, gate.Process(ctx, request, func(context.Context) error {
			calls.Add(1)
			return nil
		}))
		if provider.calls.Load() != 0 || calls.Load() != 0 {
			t.Fatalf("cancellation reached provider or callback: provider=%d callback=%d", provider.calls.Load(), calls.Load())
		}
	})

	t.Run("cancelled by provider", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var providerCalls atomic.Int64
		provider := PolicyProviderFunc(func(context.Context, protocol.TenantScope) (protocol.ResidencyPolicy, error) {
			providerCalls.Add(1)
			cancel()
			return policy, nil
		})
		gate := mustGate(t, scope, provider, testDestinations())
		var calls atomic.Int64
		assertDenied(t, gate.Process(ctx, request, func(context.Context) error {
			calls.Add(1)
			return nil
		}))
		if providerCalls.Load() != 1 || calls.Load() != 0 {
			t.Fatalf("post-provider cancellation calls: provider=%d callback=%d", providerCalls.Load(), calls.Load())
		}
	})

	t.Run("nil callback", func(t *testing.T) {
		provider := newRotatingPolicyProvider(scope, policy)
		gate := mustGate(t, scope, provider, testDestinations())
		assertDenied(t, gate.Process(context.Background(), request, nil))
		if provider.calls.Load() != 0 {
			t.Fatalf("nil callback reached provider %d times", provider.calls.Load())
		}
	})

	t.Run("nil gate", func(t *testing.T) {
		var gate *Gate
		var calls atomic.Int64
		assertDenied(t, gate.Process(context.Background(), request, func(context.Context) error {
			calls.Add(1)
			return nil
		}))
		if calls.Load() != 0 {
			t.Fatalf("nil gate reached callback %d times", calls.Load())
		}
	})
}

func TestGateCopiesTrustedDestinationConfiguration(t *testing.T) {
	scope := testTenantScope()
	policy := testPolicy("residency-v1")
	policy.StorageRegions = []string{"cn-east", "cn-north", "cn-west"}
	destinations := testDestinations()
	gate := mustGate(t, scope, newRotatingPolicyProvider(scope, policy), destinations)

	for index := range destinations {
		if destinations[index].Operation == protocol.ResidencyStore &&
			destinations[index].DataClass == protocol.ResidencyProtectedContent {
			destinations[index].Region = "cn-west"
			break
		}
	}

	var writes atomic.Int64
	trusted := testRequest(
		protocol.ResidencyStore,
		protocol.ResidencyProtectedContent,
		"cn-north",
		policy.PolicyWatermark,
	)
	if err := gate.Store(context.Background(), trusted, func(context.Context) error {
		writes.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("copied trusted destination: %v", err)
	}

	callerControlled := trusted
	callerControlled.RequestID = "request-caller-region"
	callerControlled.DestinationRegion = "cn-west"
	assertDenied(t, gate.Store(context.Background(), callerControlled, func(context.Context) error {
		writes.Add(1)
		return nil
	}))
	if got := writes.Load(); got != 1 {
		t.Fatalf("caller-controlled destination reached callback: writes = %d", got)
	}
}

func TestNewGateRejectsInvalidTrustedConfiguration(t *testing.T) {
	scope := testTenantScope()
	provider := PolicyProviderFunc(func(context.Context, protocol.TenantScope) (protocol.ResidencyPolicy, error) {
		return testPolicy("residency-v1"), nil
	})
	var typedNil *nilPolicyProvider
	var nilFunc PolicyProviderFunc

	tests := []struct {
		name         string
		scope        protocol.TenantScope
		provider     PolicyProvider
		destinations DestinationConfig
	}{
		{name: "invalid scope", scope: protocol.TenantScope{}, provider: provider, destinations: testDestinations()},
		{name: "nil provider", scope: scope, provider: nil, destinations: testDestinations()},
		{name: "typed nil provider", scope: scope, provider: typedNil, destinations: testDestinations()},
		{name: "nil provider function", scope: scope, provider: nilFunc, destinations: testDestinations()},
		{name: "missing destinations", scope: scope, provider: provider},
		{
			name:     "unknown operation",
			scope:    scope,
			provider: provider,
			destinations: DestinationConfig{
				{Operation: "replicate", DataClass: protocol.ResidencyBackup, Region: "cn-east"},
			},
		},
		{
			name:     "unknown data class",
			scope:    scope,
			provider: provider,
			destinations: DestinationConfig{
				{Operation: protocol.ResidencyStore, DataClass: "credential", Region: "cn-east"},
			},
		},
		{
			name:     "invalid region",
			scope:    scope,
			provider: provider,
			destinations: DestinationConfig{
				{Operation: protocol.ResidencyStore, DataClass: protocol.ResidencyBackup, Region: "CN-East"},
			},
		},
		{
			name:     "duplicate destination",
			scope:    scope,
			provider: provider,
			destinations: DestinationConfig{
				{Operation: protocol.ResidencyStore, DataClass: protocol.ResidencyBackup, Region: "cn-east"},
				{Operation: protocol.ResidencyStore, DataClass: protocol.ResidencyBackup, Region: "cn-east"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewGate(test.scope, test.provider, test.destinations)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewGate error = %v, want %v", err, ErrInvalidConfiguration)
			}
		})
	}
}

func TestGateAllowsMultipleTrustedRegionsForOneOperationAndClass(t *testing.T) {
	scope := testTenantScope()
	destinations := testDestinations()
	destinations = append(destinations, Destination{
		Operation: protocol.ResidencyStore,
		DataClass: protocol.ResidencyBackup,
		Region:    "cn-east",
	})
	gate := mustGate(
		t,
		scope,
		newRotatingPolicyProvider(scope, testPolicy("residency-v1")),
		destinations,
	)

	var writes atomic.Int64
	for index, region := range []string{"cn-east", "cn-north"} {
		request := testRequest(
			protocol.ResidencyStore,
			protocol.ResidencyBackup,
			region,
			"residency-v1",
		)
		request.RequestID = fmt.Sprintf("request-multi-region-%d", index)
		if err := gate.Store(context.Background(), request, func(context.Context) error {
			writes.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("store in %s: %v", region, err)
		}
	}
	if got := writes.Load(); got != 2 {
		t.Fatalf("multi-region writes = %d, want 2", got)
	}
}

func TestGatePropagatesCallbackErrorAfterSingleAuthorization(t *testing.T) {
	scope := testTenantScope()
	provider := newRotatingPolicyProvider(scope, testPolicy("residency-v1"))
	gate := mustGate(t, scope, provider, testDestinations())
	request := testRequest(
		protocol.ResidencyEgress,
		protocol.ResidencyTelemetry,
		"cn-north",
		"residency-v1",
	)
	wantErr := errors.New("network failed")
	var calls atomic.Int64
	err := gate.Egress(context.Background(), request, func(context.Context) error {
		calls.Add(1)
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("callback error = %v, want %v", err, wantErr)
	}
	if calls.Load() != 1 || provider.calls.Load() != 1 {
		t.Fatalf("calls: callback=%d provider=%d, want 1 each", calls.Load(), provider.calls.Load())
	}
}

func TestGateIsSafeForConcurrentUse(t *testing.T) {
	scope := testTenantScope()
	policy := testPolicy("residency-v1")
	var providerCalls atomic.Int64
	var activeProviderCalls atomic.Int64
	var maximumProviderCalls atomic.Int64
	provider := PolicyProviderFunc(func(_ context.Context, gotScope protocol.TenantScope) (protocol.ResidencyPolicy, error) {
		if gotScope != scope {
			return protocol.ResidencyPolicy{}, errors.New("unexpected tenant scope")
		}
		providerCalls.Add(1)
		active := activeProviderCalls.Add(1)
		for {
			maximum := maximumProviderCalls.Load()
			if active <= maximum || maximumProviderCalls.CompareAndSwap(maximum, active) {
				break
			}
		}
		runtime.Gosched()
		activeProviderCalls.Add(-1)
		return policy, nil
	})
	gate := mustGate(t, scope, provider, testDestinations())

	const workers = 64
	start := make(chan struct{})
	errs := make([]error, workers)
	var callbacks atomic.Int64
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			defer wait.Done()
			<-start
			request := testRequest(
				protocol.ResidencyProcess,
				protocol.ResidencyProtectedContent,
				"cn-east",
				policy.PolicyWatermark,
			)
			request.RequestID = fmt.Sprintf("request-concurrent-%d", index)
			errs[index] = gate.Process(context.Background(), request, func(context.Context) error {
				callbacks.Add(1)
				return nil
			})
		}()
	}
	close(start)
	wait.Wait()

	for index, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", index, err)
		}
	}
	if callbacks.Load() != workers || providerCalls.Load() != workers {
		t.Fatalf("concurrent calls: callbacks=%d provider=%d, want %d", callbacks.Load(), providerCalls.Load(), workers)
	}
	if maximumProviderCalls.Load() != 1 {
		t.Fatalf("concurrent provider calls = %d, want 1", maximumProviderCalls.Load())
	}
}

type rotatingPolicyProvider struct {
	wantScope protocol.TenantScope
	calls     atomic.Int64

	mu     sync.RWMutex
	policy protocol.ResidencyPolicy
	err    error
}

func newRotatingPolicyProvider(
	scope protocol.TenantScope,
	policy protocol.ResidencyPolicy,
) *rotatingPolicyProvider {
	return &rotatingPolicyProvider{wantScope: scope, policy: policy}
}

func (p *rotatingPolicyProvider) CurrentPolicy(
	_ context.Context,
	scope protocol.TenantScope,
) (protocol.ResidencyPolicy, error) {
	p.calls.Add(1)
	if scope != p.wantScope {
		return protocol.ResidencyPolicy{}, errors.New("unexpected tenant scope")
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.policy, p.err
}

func (p *rotatingPolicyProvider) rotate(policy protocol.ResidencyPolicy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy = policy
}

type nilPolicyProvider struct{}

func (*nilPolicyProvider) CurrentPolicy(
	context.Context,
	protocol.TenantScope,
) (protocol.ResidencyPolicy, error) {
	panic("typed nil provider must not be called")
}

func testTenantScope() protocol.TenantScope {
	return protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: "tenant-a",
		Region:   "cn-east",
	}
}

func testPolicy(watermark string) protocol.ResidencyPolicy {
	return protocol.ResidencyPolicy{
		Version:           protocol.EnterpriseContractVersion,
		TenantID:          "tenant-a",
		HomeRegion:        "cn-east",
		StorageRegions:    []string{"cn-east", "cn-north"},
		ProcessingRegions: []string{"cn-east", "cn-north"},
		EgressRegions:     []string{"cn-east", "cn-north"},
		PolicyWatermark:   watermark,
	}
}

func testDestinations() DestinationConfig {
	destinations := make(DestinationConfig, 0, 3*len(residencyDataClasses))
	for _, operation := range []protocol.ResidencyOperationKind{
		protocol.ResidencyStore,
		protocol.ResidencyProcess,
		protocol.ResidencyEgress,
	} {
		for _, dataClass := range residencyDataClasses {
			destinations = append(destinations, Destination{
				Operation: operation,
				DataClass: dataClass,
				Region:    testDestinationRegion(operation),
			})
		}
	}
	return destinations
}

func testDestinationRegion(operation protocol.ResidencyOperationKind) string {
	if operation == protocol.ResidencyProcess {
		return "cn-east"
	}
	return "cn-north"
}

func testRequest(
	operation protocol.ResidencyOperationKind,
	dataClass protocol.ResidencyDataClass,
	region string,
	watermark string,
) protocol.ResidencyCheckRequest {
	return protocol.ResidencyCheckRequest{
		Version:           protocol.EnterpriseContractVersion,
		TenantID:          "tenant-a",
		RequestID:         "request-" + string(operation) + "-" + string(dataClass),
		Operation:         operation,
		DataClass:         dataClass,
		DestinationRegion: region,
		PolicyWatermark:   watermark,
	}
}

func mustGate(
	t *testing.T,
	scope protocol.TenantScope,
	provider PolicyProvider,
	destinations DestinationConfig,
) *Gate {
	t.Helper()
	gate, err := NewGate(scope, provider, destinations)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return gate
}

func assertDenied(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want %v", err, ErrDenied)
	}
}
