package ipam

import (
	"testing"
)

func TestBitmapSetGetClear(t *testing.T) {
	b := NewBitmap(256)

	// Initially all bits should be unset.
	for i := range 256 {
		if b.Get(i) {
			t.Fatalf("bit %d should be unset initially", i)
		}
	}

	// Set some bits and verify.
	b.Set(0)
	b.Set(42)
	b.Set(255)

	if !b.Get(0) {
		t.Fatal("bit 0 should be set")
	}
	if !b.Get(42) {
		t.Fatal("bit 42 should be set")
	}
	if !b.Get(255) {
		t.Fatal("bit 255 should be set")
	}
	if b.Get(1) {
		t.Fatal("bit 1 should be unset")
	}

	// Clear a bit and verify.
	b.Clear(42)
	if b.Get(42) {
		t.Fatal("bit 42 should be unset after clear")
	}
}

func TestBitmapFindFree(t *testing.T) {
	b := NewBitmap(128)

	// First free should be 0.
	if idx := b.FindFree(); idx != 0 {
		t.Fatalf("expected 0, got %d", idx)
	}

	// Set bits 0-63 and check.
	for i := range 64 {
		b.Set(i)
	}
	if idx := b.FindFree(); idx != 64 {
		t.Fatalf("expected 64, got %d", idx)
	}

	// Set all bits.
	for i := range 128 {
		b.Set(i)
	}
	if idx := b.FindFree(); idx != -1 {
		t.Fatalf("expected -1 (full), got %d", idx)
	}

	// Clear one and find it.
	b.Clear(100)
	if idx := b.FindFree(); idx != 100 {
		t.Fatalf("expected 100, got %d", idx)
	}
}

func TestBitmapSize(t *testing.T) {
	b := NewBitmap(100)
	if b.Size() != 100 {
		t.Fatalf("expected size 100, got %d", b.Size())
	}
}

func TestBitmapSmall(t *testing.T) {
	b := NewBitmap(4)
	b.Set(0)
	b.Set(1)
	b.Set(3)

	if idx := b.FindFree(); idx != 2 {
		t.Fatalf("expected 2, got %d", idx)
	}

	b.Set(2)
	if idx := b.FindFree(); idx != -1 {
		t.Fatalf("expected -1, got %d", idx)
	}
}
