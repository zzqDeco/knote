package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now.UTC()}
}

func (c *testClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type testRequestIDs struct {
	mu   sync.Mutex
	next int
}

func (s *testRequestIDs) NextRequestID() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return "request_test_" + formatTestSequence(s.next), nil
}

func formatTestSequence(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	result := make([]byte, 0, 8)
	for value > 0 {
		result = append(result, digits[value%10])
		value /= 10
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return string(result)
}

func testScope(tenantID string) protocol.TenantScope {
	return protocol.TenantScope{
		Version:  protocol.EnterpriseContractVersion,
		TenantID: tenantID,
		Region:   "cn-east",
	}
}

func testProvider() ProviderSpec {
	return ProviderSpec{
		ProviderID: "provider-main",
		Issuer:     "https://identity.example.test",
		Audiences:  []string{"knote-cli"},
	}
}

func openTestStore(t *testing.T, root string, clock Clock) *LocalStore {
	t.Helper()
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenLocalStore(root, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func registerTestTenant(t *testing.T, store *LocalStore, scope protocol.TenantScope) {
	t.Helper()
	if _, err := store.RegisterTenant(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertProvider(context.Background(), scope, testProvider()); err != nil {
		t.Fatal(err)
	}
}

func signTestClaims(t *testing.T, privateKey ed25519.PrivateKey, claims AssertionClaims) []byte {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signTestPayload(privateKey, payload)
}

func signTestPayload(privateKey ed25519.PrivateKey, payload []byte) []byte {
	signature := ed25519.Sign(privateKey, payload)
	return []byte(base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature))
}
