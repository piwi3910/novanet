// Package identity implements a deterministic identity allocator that maps
// label sets to 64-bit identity IDs using FNV-1a hashing with collision
// detection via linear probing.
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
	idToLabels map[uint64]map[string]string

	// refCount tracks how many pods reference each identity.
	refCount map[uint64]int

	// labelsToID provides reverse lookup from canonical label string to ID,
	// enabling collision detection (different labels mapping to the same hash).
	labelsToID map[string]uint64
}

// NewAllocator creates a new identity allocator.
func NewAllocator(logger *zap.Logger) *Allocator {
	return &Allocator{
		logger:     logger,
		idToLabels: make(map[uint64]map[string]string),
		refCount:   make(map[uint64]int),
		labelsToID: make(map[string]uint64),
	}
}

// AllocateIdentity returns a deterministic 64-bit identity ID for the given
// label set. The same set of labels always produces the same ID. If a hash
// collision is detected (different label set maps to the same hash), linear
// probing is used to find the next available slot. The labels are stored for
// reverse lookup. The reference count is incremented.
func (a *Allocator) AllocateIdentity(lbls map[string]string) uint64 {
	canonical := canonicalLabels(lbls)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Fast path: check if we already allocated an ID for this exact label set.
	if existingID, ok := a.labelsToID[canonical]; ok {
		a.refCount[existingID]++
		return existingID
	}

	// Compute the base hash.
	id := hashCanonical(canonical)

	// Linear probing: if this ID is taken by a different label set, increment.
	for {
		storedLabels, occupied := a.idToLabels[id]
		if !occupied {
			break
		}
		// Occupied by a different label set — collision.
		if canonicalLabels(storedLabels) != canonical {
			a.logger.Warn("identity hash collision detected, probing next slot",
				zap.Uint64("colliding_id", id),
				zap.String("existing_labels", canonicalLabels(storedLabels)),
				zap.String("new_labels", canonical),
			)
			id++
			continue
		}
		// Same label set already stored.
		break
	}

	if _, exists := a.idToLabels[id]; !exists {
		stored := make(map[string]string, len(lbls))
		for k, v := range lbls {
			stored[k] = v
		}
		a.idToLabels[id] = stored
		a.labelsToID[canonical] = id
		a.logger.Debug("allocated new identity",
			zap.Uint64("identity_id", id),
			zap.Int("label_count", len(lbls)),
		)
	}

	a.refCount[id]++
	return id
}

// GetLabels returns the label set for the given identity ID.
func (a *Allocator) GetLabels(identityID uint64) (map[string]string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	lbls, ok := a.idToLabels[identityID]
	if !ok {
		return nil, false
	}

	// Return a copy.
	result := make(map[string]string, len(lbls))
	for k, v := range lbls {
		result[k] = v
	}
	return result, true
}

// GetIdentity returns the identity ID for the given label set, if it has been
// previously allocated.
func (a *Allocator) GetIdentity(lbls map[string]string) (uint64, bool) {
	canonical := canonicalLabels(lbls)

	a.mu.RLock()
	defer a.mu.RUnlock()

	id, ok := a.labelsToID[canonical]
	return id, ok
}

// RemoveIdentity decrements the reference count for an identity. When the
// reference count reaches zero, the identity is removed from the allocator.
func (a *Allocator) RemoveIdentity(identityID uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if count, ok := a.refCount[identityID]; ok {
		if count <= 1 {
			if lbls, exists := a.idToLabels[identityID]; exists {
				delete(a.labelsToID, canonicalLabels(lbls))
			}
			delete(a.idToLabels, identityID)
			delete(a.refCount, identityID)
			a.logger.Debug("removed identity",
				zap.Uint64("identity_id", identityID),
			)
		} else {
			a.refCount[identityID]--
		}
	}
}

// Entry holds an identity's labels and reference count for listing.
type Entry struct {
	ID       uint64
	Labels   map[string]string
	RefCount int
}

// ListAll returns all identities with their labels and reference counts.
func (a *Allocator) ListAll() []Entry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]Entry, 0, len(a.idToLabels))
	for id, lbls := range a.idToLabels {
		labelsCopy := make(map[string]string, len(lbls))
		for k, v := range lbls {
			labelsCopy[k] = v
		}
		result = append(result, Entry{
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
func (a *Allocator) FindMatchingIdentities(selector labels.Selector) []uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var matches []uint64
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

// HashLabels computes a deterministic 64-bit FNV-1a hash from a label set.
// Labels are sorted by key to ensure determinism.
func HashLabels(lbls map[string]string) uint64 {
	return hashCanonical(canonicalLabels(lbls))
}

// canonicalLabels builds a deterministic canonical string from a label map.
func canonicalLabels(lbls map[string]string) string {
	keys := make([]string, 0, len(lbls))
	for k := range lbls {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, lbls[k]))
	}
	return strings.Join(parts, ",")
}

// hashCanonical computes a 64-bit FNV-1a hash of a canonical label string.
func hashCanonical(canonical string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(canonical))
	return h.Sum64()
}
