package service

import (
	"errors"
	"sort"
)

// ErrNoFreeSlots is returned when the backend array is full.
var ErrNoFreeSlots = errors.New("no free backend slots available")

// SlotAllocator manages contiguous slot ranges in the flat backend array.
type SlotAllocator struct {
	maxSlots uint32
	free     []slotRange // sorted by offset
}

type slotRange struct {
	offset uint32
	count  uint32
}

// NewSlotAllocator creates a slot allocator for the given capacity.
func NewSlotAllocator(maxSlots uint32) *SlotAllocator {
	return &SlotAllocator{
		maxSlots: maxSlots,
		free:     []slotRange{{offset: 0, count: maxSlots}},
	}
}

// Alloc allocates a contiguous block of count slots. Returns the starting offset.
func (a *SlotAllocator) Alloc(count uint32) (uint32, error) {
	for i, r := range a.free {
		if r.count >= count {
			offset := r.offset
			if r.count == count {
				a.free = append(a.free[:i], a.free[i+1:]...)
			} else {
				a.free[i] = slotRange{offset: r.offset + count, count: r.count - count}
			}
			return offset, nil
		}
	}
	return 0, ErrNoFreeSlots
}

// Free returns a previously allocated block back to the pool.
func (a *SlotAllocator) Free(offset, count uint32) {
	a.free = append(a.free, slotRange{offset: offset, count: count})
	sort.Slice(a.free, func(i, j int) bool { return a.free[i].offset < a.free[j].offset })
	a.merge()
}

func (a *SlotAllocator) merge() {
	merged := make([]slotRange, 0, len(a.free))
	for _, r := range a.free {
		if len(merged) > 0 && merged[len(merged)-1].offset+merged[len(merged)-1].count == r.offset {
			merged[len(merged)-1].count += r.count
		} else {
			merged = append(merged, r)
		}
	}
	a.free = merged
}
