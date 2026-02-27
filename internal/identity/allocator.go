// Package identity implements a deterministic identity allocator that maps
// label sets to 32-bit identity IDs using FNV-1a hashing.
package identity

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/labels"
)

// Allocator manages the mapping between label sets and identity IDs.
// Pods with the same set of labels share the same identity ID.
type Allocator struct {
	mu sync.RWMutex

	logger *zap.Logger

	// idToLabels maps identity IDs to their label sets.
	idToLabels map[uint32]map[string]string

	// refCount tracks how many pods reference each identity.
	refCount map[uint32]int
}

// NewAllocator creates a new identity allocator.
func NewAllocator(logger *zap.Logger) *Allocator {
	return &Allocator{
		logger:     logger,
		idToLabels: make(map[uint32]map[string]string),
		refCount:   make(map[uint32]int),
	}
}

// AllocateIdentity returns a deterministic 32-bit identity ID for the given
// label set. The same set of labels always produces the same ID. The labels
// are stored for reverse lookup. The reference count is incremented.
func (a *Allocator) AllocateIdentity(labels map[string]string) uint32 {
	id := HashLabels(labels)

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.idToLabels[id]; !exists {
		// Store a copy of the labels.
		stored := make(map[string]string, len(labels))
		for k, v := range labels {
			stored[k] = v
		}
		a.idToLabels[id] = stored
		a.logger.Debug("allocated new identity",
			zap.Uint32("identity_id", id),
			zap.Int("label_count", len(labels)),
		)
	}

	a.refCount[id]++
	return id
}

// GetLabels returns the label set for the given identity ID.
func (a *Allocator) GetLabels(identityID uint32) (map[string]string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	labels, ok := a.idToLabels[identityID]
	if !ok {
		return nil, false
	}

	// Return a copy.
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result, true
}

// GetIdentity returns the identity ID for the given label set, if it has been
// previously allocated.
func (a *Allocator) GetIdentity(labels map[string]string) (uint32, bool) {
	id := HashLabels(labels)

	a.mu.RLock()
	defer a.mu.RUnlock()

	_, ok := a.idToLabels[id]
	return id, ok
}

// RemoveIdentity decrements the reference count for an identity. When the
// reference count reaches zero, the identity is removed from the allocator.
func (a *Allocator) RemoveIdentity(identityID uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if count, ok := a.refCount[identityID]; ok {
		if count <= 1 {
			delete(a.idToLabels, identityID)
			delete(a.refCount, identityID)
			a.logger.Debug("removed identity",
				zap.Uint32("identity_id", identityID),
			)
		} else {
			a.refCount[identityID]--
		}
	}
}

// IdentityEntry holds an identity's labels and reference count for listing.
type IdentityEntry struct {
	ID       uint32
	Labels   map[string]string
	RefCount int
}

// ListAll returns all identities with their labels and reference counts.
func (a *Allocator) ListAll() []IdentityEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]IdentityEntry, 0, len(a.idToLabels))
	for id, labels := range a.idToLabels {
		labelsCopy := make(map[string]string, len(labels))
		for k, v := range labels {
			labelsCopy[k] = v
		}
		result = append(result, IdentityEntry{
			ID:       id,
			Labels:   labelsCopy,
			RefCount: a.refCount[id],
		})
	}
	return result
}

// FindMatchingIdentities returns all identity IDs whose labels match the
// given selector. Supports both MatchLabels and MatchExpressions (In, NotIn,
// Exists, DoesNotExist). This enables the policy compiler to match actual
// pod identities rather than hashing selector labels.
func (a *Allocator) FindMatchingIdentities(selector labels.Selector) []uint32 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var matches []uint32
	for id, idLabels := range a.idToLabels {
		if selector.Matches(labels.Set(idLabels)) {
			matches = append(matches, id)
		}
	}
	return matches
}

// Count returns the number of distinct identities currently tracked.
func (a *Allocator) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.idToLabels)
}

// HashLabels computes a deterministic FNV-1a hash from a label set.
// Labels are sorted by key to ensure determinism.
func HashLabels(labels map[string]string) uint32 {
	// Sort keys for determinism.
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical string representation.
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}
	canonical := strings.Join(parts, ",")

	h := fnv.New32a()
	h.Write([]byte(canonical))
	return h.Sum32()
}
