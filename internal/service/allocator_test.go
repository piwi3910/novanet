package service

import "testing"

func TestAllocatorAllocFree(t *testing.T) {
	a := NewSlotAllocator(100)

	offset, err := a.Alloc(3)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 {
		t.Fatalf("expected offset 0, got %d", offset)
	}

	offset2, err := a.Alloc(5)
	if err != nil {
		t.Fatal(err)
	}
	if offset2 != 3 {
		t.Fatalf("expected offset 3, got %d", offset2)
	}

	a.Free(0, 3)

	offset3, err := a.Alloc(2)
	if err != nil {
		t.Fatal(err)
	}
	if offset3 != 0 {
		t.Fatalf("expected reuse at offset 0, got %d", offset3)
	}
}

func TestAllocatorExhaustion(t *testing.T) {
	a := NewSlotAllocator(4)
	_, err := a.Alloc(4)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Alloc(1)
	if err == nil {
		t.Fatal("expected error on exhausted allocator")
	}
}

func TestAllocatorMerge(t *testing.T) {
	a := NewSlotAllocator(10)

	// Allocate 3 separate blocks.
	_, _ = a.Alloc(3) // 0-2
	_, _ = a.Alloc(3) // 3-5
	_, _ = a.Alloc(3) // 6-8

	// Free middle then first — should merge into one free block.
	a.Free(3, 3)
	a.Free(0, 3)

	// Should be able to allocate 6 contiguous slots.
	offset, err := a.Alloc(6)
	if err != nil {
		t.Fatalf("expected merge to allow 6-slot alloc, got error: %v", err)
	}
	if offset != 0 {
		t.Fatalf("expected offset 0 after merge, got %d", offset)
	}
}
