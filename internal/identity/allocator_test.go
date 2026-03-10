package identity

import (
	"sync"
	"testing"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestAllocateIdentityDeterministic(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{
		"app":  "web",
		"tier": "frontend",
	}

	id1 := a.AllocateIdentity(labels)
	id2 := a.AllocateIdentity(labels)

	if id1 != id2 {
		t.Fatalf("expected same identity for same labels, got %d and %d", id1, id2)
	}
}

func TestAllocateIdentityDifferentLabels(t *testing.T) {
	a := NewAllocator(testLogger())

	labels1 := map[string]string{"app": "web"}
	labels2 := map[string]string{"app": "api"}

	id1 := a.AllocateIdentity(labels1)
	id2 := a.AllocateIdentity(labels2)

	if id1 == id2 {
		t.Fatalf("expected different identities for different labels, both got %d", id1)
	}
}

func TestAllocateIdentityOrderIndependent(t *testing.T) {
	a := NewAllocator(testLogger())

	// Allocate with labels in different insertion order.
	labels1 := map[string]string{
		"app":  "web",
		"tier": "frontend",
		"env":  "prod",
	}
	labels2 := map[string]string{
		"env":  "prod",
		"app":  "web",
		"tier": "frontend",
	}

	id1 := a.AllocateIdentity(labels1)
	id2 := a.AllocateIdentity(labels2)

	if id1 != id2 {
		t.Fatalf("expected same identity regardless of label order, got %d and %d", id1, id2)
	}
}

func TestGetLabels(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{
		"app": "web",
		"env": "prod",
	}

	id := a.AllocateIdentity(labels)

	got, ok := a.GetLabels(id)
	if !ok {
		t.Fatal("expected to find labels")
	}

	if len(got) != len(labels) {
		t.Fatalf("expected %d labels, got %d", len(labels), len(got))
	}

	for k, v := range labels {
		if got[k] != v {
			t.Fatalf("expected label %s=%s, got %s=%s", k, v, k, got[k])
		}
	}
}

func TestGetLabelsNotFound(t *testing.T) {
	a := NewAllocator(testLogger())

	_, ok := a.GetLabels(12345)
	if ok {
		t.Fatal("expected not found for unknown identity")
	}
}

func TestGetLabelsReturnsACopy(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{"app": "web"}
	id := a.AllocateIdentity(labels)

	got, ok := a.GetLabels(id)
	if !ok {
		t.Fatal("expected to find labels")
	}

	// Modifying the returned map should not affect the stored labels.
	got["app"] = "modified"

	original, _ := a.GetLabels(id)
	if original["app"] != "web" {
		t.Fatal("modifying returned labels affected stored labels")
	}
}

func TestGetIdentity(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{"app": "web"}
	expectedID := a.AllocateIdentity(labels)

	id, ok := a.GetIdentity(labels)
	if !ok {
		t.Fatal("expected to find identity")
	}
	if id != expectedID {
		t.Fatalf("expected identity %d, got %d", expectedID, id)
	}
}

func TestGetIdentityNotFound(t *testing.T) {
	a := NewAllocator(testLogger())

	_, ok := a.GetIdentity(map[string]string{"app": "nonexistent"})
	if ok {
		t.Fatal("expected not found for unknown labels")
	}
}

func TestRemoveIdentityRefCount(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{"app": "web"}

	// Allocate twice to get refcount 2.
	id := a.AllocateIdentity(labels)
	a.AllocateIdentity(labels)

	if a.Count() != 1 {
		t.Fatalf("expected 1 identity, got %d", a.Count())
	}

	// First remove should decrement refcount, not delete.
	a.RemoveIdentity(id)
	if a.Count() != 1 {
		t.Fatalf("expected 1 identity after first remove, got %d", a.Count())
	}

	// Second remove should actually delete.
	a.RemoveIdentity(id)
	if a.Count() != 0 {
		t.Fatalf("expected 0 identities after second remove, got %d", a.Count())
	}

	// Labels should be gone.
	_, ok := a.GetLabels(id)
	if ok {
		t.Fatal("expected labels to be removed")
	}
}

func TestRemoveIdentityNonExistent(t *testing.T) {
	a := NewAllocator(testLogger())

	// Removing a non-existent identity should not panic.
	a.RemoveIdentity(12345)
}

func TestCount(t *testing.T) {
	a := NewAllocator(testLogger())

	if a.Count() != 0 {
		t.Fatalf("expected 0 identities, got %d", a.Count())
	}

	a.AllocateIdentity(map[string]string{"app": "web"})
	a.AllocateIdentity(map[string]string{"app": "api"})
	a.AllocateIdentity(map[string]string{"app": "db"})

	if a.Count() != 3 {
		t.Fatalf("expected 3 identities, got %d", a.Count())
	}
}

func TestConcurrentAllocations(t *testing.T) {
	a := NewAllocator(testLogger())

	var wg sync.WaitGroup
	results := make(chan uint64, 100)

	// Many goroutines allocating the same identity.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := a.AllocateIdentity(map[string]string{"app": "web"})
			results <- id
		}()
	}

	wg.Wait()
	close(results)

	// All should be the same.
	var first uint64
	firstSet := false
	for id := range results {
		if !firstSet {
			first = id
			firstSet = true
			continue
		}
		if id != first {
			t.Fatalf("expected all concurrent allocations to return same ID, got %d and %d", first, id)
		}
	}
}

func TestHashLabelsEmpty(t *testing.T) {
	// Empty labels should produce a consistent hash.
	id1 := HashLabels(map[string]string{})
	id2 := HashLabels(map[string]string{})
	if id1 != id2 {
		t.Fatalf("expected same hash for empty labels, got %d and %d", id1, id2)
	}
}

func TestHashLabelsNil(t *testing.T) {
	// Nil labels should produce a consistent hash.
	id1 := HashLabels(nil)
	id2 := HashLabels(nil)
	if id1 != id2 {
		t.Fatalf("expected same hash for nil labels, got %d and %d", id1, id2)
	}
}

func TestHashLabelsReturns64Bit(t *testing.T) {
	// Verify that HashLabels returns a 64-bit value and is deterministic.
	labels := map[string]string{
		"app":       "web",
		"component": "frontend",
		"version":   "v2.1.0",
	}
	id := HashLabels(labels)
	if id == 0 {
		t.Fatal("expected non-zero hash")
	}
	id2 := HashLabels(labels)
	if id != id2 {
		t.Fatalf("expected deterministic hash, got %d and %d", id, id2)
	}
}

func TestCollisionDetection(t *testing.T) {
	a := NewAllocator(testLogger())

	labels1 := map[string]string{"app": "web"}
	labels2 := map[string]string{"app": "api"}

	id1 := a.AllocateIdentity(labels1)
	id2 := a.AllocateIdentity(labels2)

	// Both should be allocated with distinct IDs even if hash happens to collide.
	if id1 == id2 {
		t.Fatalf("expected different IDs, both got %d", id1)
	}

	// Verify both can be retrieved.
	got1, ok := a.GetLabels(id1)
	if !ok {
		t.Fatal("expected to find labels for id1")
	}
	if got1["app"] != "web" {
		t.Fatalf("expected app=web for id1, got %s", got1["app"])
	}

	got2, ok := a.GetLabels(id2)
	if !ok {
		t.Fatal("expected to find labels for id2")
	}
	if got2["app"] != "api" {
		t.Fatalf("expected app=api for id2, got %s", got2["app"])
	}
}

func TestGetIdentityAfterRemove(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{"app": "web"}
	id := a.AllocateIdentity(labels)

	a.RemoveIdentity(id)

	_, ok := a.GetIdentity(labels)
	if ok {
		t.Fatal("expected identity to be gone after removal")
	}
}

func TestRemoveIdentityCleansUpLabelsToID(t *testing.T) {
	a := NewAllocator(testLogger())

	labels := map[string]string{"app": "web"}
	id := a.AllocateIdentity(labels)

	a.RemoveIdentity(id)

	// Re-allocate should work and produce the same ID (no stale mapping).
	id2 := a.AllocateIdentity(labels)
	if id != id2 {
		t.Fatalf("expected same ID after re-allocation, got %d and %d", id, id2)
	}
}
