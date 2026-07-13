package authorized

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
)

const maxQueryCacheCapacity = 10_000

// QueryCache is a bounded, insertion-ordered cache for authorized query
// results. Entries are only usable through Service, which revalidates every
// authorization and evidence boundary before returning a hit.
type QueryCache struct {
	mu           sync.Mutex
	capacity     int
	now          func() time.Time
	nextRevision uint64
	entries      map[queryCacheKey]queryCacheEntry
	invalidated  map[protocol.ResourceID]struct{}
	disabled     bool
}

type queryCacheKey struct {
	questionDigest     [sha256.Size]byte
	contractVersion    string
	tenantID           string
	knowledgeBaseID    string
	principalID        string
	authorizationModel string
	identityWatermark  string
	aclWatermark       string
	agentID            string
	taskID             string
	consistency        protocol.ConsistencyPreference
	retrieverVersion   string
	promptVersion      string
	retrieveLimit      int
	evidenceLimit      int
	expandLimit        int
}

type queryCacheEntry struct {
	revision    uint64
	result      QueryResult
	resourceIDs map[protocol.ResourceID]struct{}
}

type queryCacheSnapshot struct {
	revision uint64
	result   QueryResult
}

// CacheInvalidationResult contains operational metadata only. It deliberately
// excludes cache keys and content-bearing query or result fields.
type CacheInvalidationResult struct {
	ObservedAt         time.Time     `json:"observed_at"`
	PropagationLatency time.Duration `json:"propagation_latency"`
	RemovedEntries     int           `json:"removed_entries"`
}

// NewQueryCache creates a bounded cache. Capacity is counted in complete query
// results rather than bytes.
func NewQueryCache(capacity int) (*QueryCache, error) {
	return newQueryCache(capacity, time.Now)
}

func newQueryCache(capacity int, now func() time.Time) (*QueryCache, error) {
	if capacity < 1 || capacity > maxQueryCacheCapacity {
		return nil, fmt.Errorf("authorized query cache capacity must be between 1 and %d", maxQueryCacheCapacity)
	}
	if now == nil {
		return nil, fmt.Errorf("authorized query cache clock is required")
	}
	return &QueryCache{
		capacity:    capacity,
		now:         now,
		entries:     make(map[queryCacheKey]queryCacheEntry, capacity),
		invalidated: make(map[protocol.ResourceID]struct{}),
	}, nil
}

func newQueryCacheKey(
	request protocol.QueryRequest,
	retrieverVersion string,
	promptVersion string,
	retrieveLimit int,
	evidenceLimit int,
	expandLimit int,
) queryCacheKey {
	authorization := request.Authorization
	return queryCacheKey{
		questionDigest:     sha256.Sum256([]byte(request.Question)),
		contractVersion:    authorization.Version,
		tenantID:           authorization.TenantID,
		knowledgeBaseID:    authorization.KnowledgeBaseID,
		principalID:        authorization.PrincipalID,
		authorizationModel: authorization.AuthorizationModelID,
		identityWatermark:  authorization.IdentityWatermark,
		aclWatermark:       authorization.ACLWatermark,
		agentID:            authorization.AgentID,
		taskID:             authorization.TaskID,
		consistency:        authorization.Consistency,
		retrieverVersion:   retrieverVersion,
		promptVersion:      promptVersion,
		retrieveLimit:      retrieveLimit,
		evidenceLimit:      evidenceLimit,
		expandLimit:        expandLimit,
	}
}

func (c *QueryCache) initialized() bool {
	return c != nil && c.capacity > 0 && c.now != nil && c.entries != nil && c.invalidated != nil
}

func (c *QueryCache) get(key queryCacheKey) (queryCacheSnapshot, bool) {
	if c == nil {
		return queryCacheSnapshot{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return queryCacheSnapshot{}, false
	}
	entry, ok := c.entries[key]
	if !ok {
		return queryCacheSnapshot{}, false
	}
	return queryCacheSnapshot{revision: entry.revision, result: cloneQueryResult(entry.result)}, true
}

// put returns false when a revocation tombstone prevents this result from
// becoming current. Service uses the result to fail an in-flight query closed.
func (c *QueryCache) put(key queryCacheKey, result QueryResult) bool {
	if c == nil {
		return false
	}
	cloned := cloneQueryResult(result)
	resourceIDs := queryResultResourceIDs(cloned)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return false
	}
	for resourceID := range resourceIDs {
		if _, revoked := c.invalidated[resourceID]; revoked {
			return false
		}
	}
	c.nextRevision++
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.capacity {
		c.evictOldestLocked()
	}
	c.entries[key] = queryCacheEntry{
		revision: c.nextRevision, result: cloned, resourceIDs: resourceIDs,
	}
	return true
}

func (c *QueryCache) deleteIfRevision(key queryCacheKey, revision uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return
	}
	if entry, ok := c.entries[key]; ok && entry.revision == revision {
		delete(c.entries, key)
	}
}

func (c *QueryCache) containsRevision(key queryCacheKey, revision uint64) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return false
	}
	entry, ok := c.entries[key]
	return ok && entry.revision == revision
}

func (c *QueryCache) containsInvalidatedResource(resourceIDs []protocol.ResourceID) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return true
	}
	for _, resourceID := range resourceIDs {
		if _, invalidated := c.invalidated[resourceID]; invalidated {
			return true
		}
	}
	return false
}

// InvalidateResource removes every entry whose evidence, provenance, decision,
// citation, or trace references resourceID. The resource remains invalidated
// for this cache's lifetime so an in-flight query cannot repopulate it after
// the revocation event. The result is safe for operational metrics because it
// contains no cache key or content-bearing value.
func (c *QueryCache) InvalidateResource(resourceID protocol.ResourceID, revokedAt time.Time) (CacheInvalidationResult, error) {
	if err := resourceID.Validate(); err != nil {
		return CacheInvalidationResult{}, fmt.Errorf("invalidate authorized query cache resource: %w", err)
	}
	if revokedAt.IsZero() {
		return CacheInvalidationResult{}, fmt.Errorf("invalidate authorized query cache requires a revocation timestamp")
	}
	if c == nil || !c.initialized() {
		return CacheInvalidationResult{}, fmt.Errorf("authorized query cache is not initialized")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	observedAt := c.now().UTC()
	if observedAt.IsZero() {
		return CacheInvalidationResult{}, fmt.Errorf("authorized query cache clock returned a zero timestamp")
	}
	if c.disabled {
		return CacheInvalidationResult{ObservedAt: observedAt}, nil
	}
	if _, exists := c.invalidated[resourceID]; !exists && len(c.invalidated) >= maxQueryCacheCapacity {
		removed := len(c.entries)
		clear(c.entries)
		clear(c.invalidated)
		c.disabled = true
		latency := observedAt.Sub(revokedAt.UTC())
		if latency < 0 {
			latency = 0
		}
		return CacheInvalidationResult{
			ObservedAt: observedAt, PropagationLatency: latency, RemovedEntries: removed,
		}, nil
	}
	c.invalidated[resourceID] = struct{}{}
	removed := 0
	for key, entry := range c.entries {
		if _, contains := entry.resourceIDs[resourceID]; !contains {
			continue
		}
		delete(c.entries, key)
		removed++
	}
	latency := observedAt.Sub(revokedAt.UTC())
	if latency < 0 {
		latency = 0
	}
	return CacheInvalidationResult{
		ObservedAt: observedAt, PropagationLatency: latency, RemovedEntries: removed,
	}, nil
}

func (c *QueryCache) evictOldestLocked() {
	var oldestKey queryCacheKey
	var oldestRevision uint64
	found := false
	for key, entry := range c.entries {
		if !found || entry.revision < oldestRevision {
			oldestKey = key
			oldestRevision = entry.revision
			found = true
		}
	}
	if found {
		delete(c.entries, oldestKey)
	}
}

func cloneQueryResult(source QueryResult) QueryResult {
	clone := source
	clone.Generation = cloneGeneration(source.Generation)
	clone.Evidence.Items = cloneEvidenceItems(source.Evidence.Items)
	if source.Evidence.Decisions != nil {
		clone.Evidence.Decisions = append([]protocol.AuthorizationDecision(nil), source.Evidence.Decisions...)
	}
	return clone
}

func cloneGeneration(source kag.GenerateResult) kag.GenerateResult {
	clone := source
	if source.Citations != nil {
		clone.Citations = append([]kag.CitationHandle(nil), source.Citations...)
	}
	if source.EvidenceResourceIDs != nil {
		clone.EvidenceResourceIDs = append([]protocol.ResourceID(nil), source.EvidenceResourceIDs...)
	}
	if source.Trace.ResourceIDs != nil {
		clone.Trace.ResourceIDs = append([]protocol.ResourceID(nil), source.Trace.ResourceIDs...)
	}
	return clone
}

func cloneEvidenceItems(source []protocol.EvidenceItem) []protocol.EvidenceItem {
	if source == nil {
		return nil
	}
	clone := make([]protocol.EvidenceItem, len(source))
	for itemIndex, item := range source {
		clone[itemIndex] = item
		if item.Supports == nil {
			continue
		}
		clone[itemIndex].Supports = make([]protocol.ProvenanceSupport, len(item.Supports))
		for supportIndex, support := range item.Supports {
			clone[itemIndex].Supports[supportIndex] = support
			if support.Evidence != nil {
				clone[itemIndex].Supports[supportIndex].Evidence = append(
					[]protocol.ResourceHandle(nil), support.Evidence...,
				)
			}
		}
	}
	return clone
}

func queryResultResourceIDs(result QueryResult) map[protocol.ResourceID]struct{} {
	resourceIDs := make(map[protocol.ResourceID]struct{})
	add := func(resourceID protocol.ResourceID) {
		if resourceID != "" {
			resourceIDs[resourceID] = struct{}{}
		}
	}
	for _, item := range result.Evidence.Items {
		add(item.Resource.ResourceID)
		add(item.Citation.Resource.ResourceID)
		for _, support := range item.Supports {
			add(support.Resource.ResourceID)
			for _, evidence := range support.Evidence {
				add(evidence.ResourceID)
			}
		}
	}
	for _, decision := range result.Evidence.Decisions {
		add(decision.Resource.ResourceID)
		add(decision.AuthorizationResource.ResourceID)
	}
	for _, citation := range result.Generation.Citations {
		add(citation.ResourceID)
	}
	for _, resourceID := range result.Generation.EvidenceResourceIDs {
		add(resourceID)
	}
	for _, resourceID := range result.Generation.Trace.ResourceIDs {
		add(resourceID)
	}
	return resourceIDs
}
