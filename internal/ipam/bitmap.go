package ipam

// Bitmap is a compact bitset backed by []uint64 for efficient IP allocation
// tracking. Each bit represents a single IP address in a pool.
type Bitmap struct {
	words []uint64
	size  int
}

// NewBitmap creates a Bitmap with capacity for size bits.
func NewBitmap(size int) *Bitmap {
	words := (size + 63) / 64
	return &Bitmap{
		words: make([]uint64, words),
		size:  size,
	}
}

// Set marks the bit at idx as allocated.
func (b *Bitmap) Set(idx int) {
	word := idx / 64
	bit := idx % 64
	b.words[word] |= 1 << uint(bit) //nolint:gosec // idx is bounded by pool size
}

// Clear marks the bit at idx as free.
func (b *Bitmap) Clear(idx int) {
	word := idx / 64
	bit := idx % 64
	b.words[word] &^= 1 << uint(bit) //nolint:gosec // idx is bounded by pool size
}

// Get returns true if the bit at idx is set (allocated).
func (b *Bitmap) Get(idx int) bool {
	word := idx / 64
	bit := idx % 64
	return b.words[word]&(1<<uint(bit)) != 0 //nolint:gosec // idx is bounded by pool size
}

// FindFree returns the index of the first unset bit, or -1 if all are set.
func (b *Bitmap) FindFree() int {
	for i, word := range b.words {
		if word == ^uint64(0) {
			continue
		}
		for bit := 0; bit < 64; bit++ {
			idx := i*64 + bit
			if idx >= b.size {
				return -1
			}
			if word&(1<<uint(bit)) == 0 {
				return idx
			}
		}
	}
	return -1
}

// Size returns the total number of bits in the bitmap.
func (b *Bitmap) Size() int {
	return b.size
}
