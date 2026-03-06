package service

import "hash/fnv"

// GenerateMaglevTable generates a Maglev consistent hash lookup table.
// Each entry maps to a backend index (0-based).
func GenerateMaglevTable(backends []string, tableSize int) []uint32 {
	n := len(backends)
	if n == 0 {
		return make([]uint32, tableSize)
	}

	offsets := make([]uint32, n)
	skips := make([]uint32, n)
	for i, b := range backends {
		h := fnv.New64a()
		h.Write([]byte(b))
		hash := h.Sum64()
		offsets[i] = uint32(hash % uint64(tableSize))
		skips[i] = uint32(hash>>32%uint64(tableSize-1)) + 1
	}

	table := make([]uint32, tableSize)
	for i := range table {
		table[i] = ^uint32(0) // sentinel "empty"
	}

	next := make([]uint32, n)
	for i := range next {
		next[i] = offsets[i]
	}

	filled := 0
	for filled < tableSize {
		for i := 0; i < n; i++ {
			pos := next[i]
			for table[pos] != ^uint32(0) {
				pos = (pos + skips[i]) % uint32(tableSize)
			}
			table[pos] = uint32(i)
			next[i] = (pos + skips[i]) % uint32(tableSize)
			filled++
			if filled >= tableSize {
				break
			}
		}
	}

	return table
}
