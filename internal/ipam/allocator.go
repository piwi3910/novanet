// Package ipam provides a bitmap-based IP address management allocator
// for per-node Pod IP allocation within a given PodCIDR.
package ipam

import (
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Allocator manages a pool of IP addresses within a single CIDR.
// It uses a bitmap stored as []uint64 for efficient allocation tracking.
// When stateDir is set, allocations are persisted as files so that the
// bitmap can be rebuilt after an agent restart.
type Allocator struct {
	mu sync.Mutex

	// network is the parsed CIDR network.
	network *net.IPNet
	// baseIP is the network address as a 4-byte IP.
	baseIP net.IP
	// size is the total number of IPs in the CIDR.
	size int
	// bitmap tracks which IPs are allocated. Bit i corresponds to baseIP + i.
	bitmap []uint64
	// used counts the number of currently allocated IPs (including reserved).
	used int
	// prefixLen is the CIDR prefix length.
	prefixLen int
	// stateDir is the directory for persisting IP allocations.
	// Empty string means in-memory only.
	stateDir string
}

// NewAllocator creates a new IPAM allocator for the given PodCIDR.
// The network address (.0) and gateway address (.1) are automatically reserved.
func NewAllocator(podCIDR string) (*Allocator, error) {
	return NewAllocatorWithStateDir(podCIDR, "")
}

// NewAllocatorWithStateDir creates an IPAM allocator that persists allocations
// to the given directory. If stateDir is empty, the allocator is in-memory only.
// On startup, existing files in stateDir are loaded to rebuild the bitmap.
func NewAllocatorWithStateDir(podCIDR, stateDir string) (*Allocator, error) {
	ip, network, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("parsing podCIDR %q: %w", podCIDR, err)
	}

	// Only support IPv4 for now.
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 is supported, got %q", podCIDR)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 is supported, got %d-bit mask", bits)
	}

	size := 1 << (bits - ones)
	if size < 4 {
		return nil, fmt.Errorf("CIDR %q is too small (need at least /30)", podCIDR)
	}

	// Calculate number of uint64 words needed.
	words := (size + 63) / 64

	a := &Allocator{
		network:   network,
		baseIP:    network.IP.To4(),
		size:      size,
		bitmap:    make([]uint64, words),
		prefixLen: ones,
		stateDir:  stateDir,
	}

	// Reserve .0 (network address) and .1 (gateway).
	a.setBit(0)
	a.setBit(1)
	a.used = 2

	// Reserve broadcast address for /24 and larger.
	if size > 2 {
		a.setBit(size - 1)
		a.used = 3
	}

	// Restore allocations from disk.
	if stateDir != "" {
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			return nil, fmt.Errorf("creating state dir %s: %w", stateDir, err)
		}
		if err := a.loadState(); err != nil {
			return nil, fmt.Errorf("loading IPAM state from %s: %w", stateDir, err)
		}
	}

	return a, nil
}

// Allocate returns the next available IP address from the pool.
func (a *Allocator) Allocate() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx := a.findFree()
	if idx < 0 {
		return nil, fmt.Errorf("no free IP addresses in %s", a.network.String())
	}

	a.setBit(idx)
	a.used++

	ip := a.indexToIP(idx)

	if a.stateDir != "" {
		if err := a.saveIP(ip); err != nil {
			// Roll back the allocation on write failure.
			a.clearBit(idx)
			a.used--
			return nil, fmt.Errorf("persisting IP %s: %w", ip, err)
		}
	}

	return ip, nil
}

// AllocateSpecific claims a specific IP address from the pool.
func (a *Allocator) AllocateSpecific(ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	if !a.network.Contains(ip4) {
		return fmt.Errorf("IP %s is not within CIDR %s", ip.String(), a.network.String())
	}

	idx := a.ipToIndex(ip4)
	if idx < 0 || idx >= a.size {
		return fmt.Errorf("IP %s is out of range", ip.String())
	}

	if a.getBit(idx) {
		return fmt.Errorf("IP %s is already allocated", ip.String())
	}

	a.setBit(idx)
	a.used++

	if a.stateDir != "" {
		if err := a.saveIP(ip4); err != nil {
			a.clearBit(idx)
			a.used--
			return fmt.Errorf("persisting IP %s: %w", ip, err)
		}
	}

	return nil
}

// Release frees a previously allocated IP address.
func (a *Allocator) Release(ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	if !a.network.Contains(ip4) {
		return fmt.Errorf("IP %s is not within CIDR %s", ip.String(), a.network.String())
	}

	idx := a.ipToIndex(ip4)
	if idx < 0 || idx >= a.size {
		return fmt.Errorf("IP %s is out of range", ip.String())
	}

	// Prevent releasing reserved addresses.
	if idx == 0 {
		return fmt.Errorf("cannot release network address %s", ip.String())
	}
	if idx == 1 {
		return fmt.Errorf("cannot release gateway address %s", ip.String())
	}
	if idx == a.size-1 {
		return fmt.Errorf("cannot release broadcast address %s", ip.String())
	}

	if !a.getBit(idx) {
		return fmt.Errorf("IP %s is not allocated", ip.String())
	}

	a.clearBit(idx)
	a.used--

	if a.stateDir != "" {
		a.removeIP(ip4)
	}

	return nil
}

// Used returns the number of allocated IPs (including reserved addresses).
func (a *Allocator) Used() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.used
}

// Available returns the number of IPs available for allocation.
// This excludes the reserved .0, .1, and broadcast addresses.
func (a *Allocator) Available() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.size - a.used
}

// Gateway returns the gateway IP (.1 of the CIDR).
func (a *Allocator) Gateway() net.IP {
	return a.indexToIP(1)
}

// PrefixLength returns the CIDR prefix length.
func (a *Allocator) PrefixLength() int {
	return a.prefixLen
}

// CIDR returns the network CIDR string.
func (a *Allocator) CIDR() string {
	return a.network.String()
}

// loadState scans the state directory for IP files and marks them allocated.
func (a *Allocator) loadState() error {
	entries, err := os.ReadDir(a.stateDir)
	if err != nil {
		return fmt.Errorf("reading state dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ip := net.ParseIP(entry.Name())
		if ip == nil {
			continue // Skip non-IP filenames.
		}
		ip4 := ip.To4()
		if ip4 == nil || !a.network.Contains(ip4) {
			continue // Skip IPs outside our CIDR.
		}
		idx := a.ipToIndex(ip4)
		if idx < 0 || idx >= a.size {
			continue
		}
		if !a.getBit(idx) {
			a.setBit(idx)
			a.used++
		}
	}

	return nil
}

// saveIP writes an empty file named after the IP to the state directory.
func (a *Allocator) saveIP(ip net.IP) error {
	path := filepath.Join(a.stateDir, ip.String())
	return os.WriteFile(path, nil, 0o644)
}

// removeIP deletes the file for the given IP from the state directory.
// Errors are logged but not returned since the bitmap is already updated.
func (a *Allocator) removeIP(ip net.IP) {
	path := filepath.Join(a.stateDir, ip.String())
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		// Log to stderr since we don't have a structured logger here.
		// This is best-effort cleanup; the bitmap is already updated.
		fmt.Fprintf(os.Stderr, "ipam: failed to remove state file %s: %v\n", path, err)
	}
}

// findFree returns the index of the first unset bit, or -1 if all are set.
func (a *Allocator) findFree() int {
	for i, word := range a.bitmap {
		if word == ^uint64(0) {
			continue
		}
		// Find the first zero bit in this word.
		for bit := 0; bit < 64; bit++ {
			idx := i*64 + bit
			if idx >= a.size {
				return -1
			}
			if word&(1<<uint(bit)) == 0 {
				return idx
			}
		}
	}
	return -1
}

// setBit sets the bit at the given index.
func (a *Allocator) setBit(idx int) {
	word := idx / 64
	bit := uint(idx % 64)
	a.bitmap[word] |= 1 << bit
}

// clearBit clears the bit at the given index.
func (a *Allocator) clearBit(idx int) {
	word := idx / 64
	bit := uint(idx % 64)
	a.bitmap[word] &^= 1 << bit
}

// getBit returns true if the bit at the given index is set.
func (a *Allocator) getBit(idx int) bool {
	word := idx / 64
	bit := uint(idx % 64)
	return a.bitmap[word]&(1<<bit) != 0
}

// ipToIndex converts an IP address to a bitmap index.
func (a *Allocator) ipToIndex(ip net.IP) int {
	ip4 := ip.To4()
	base := big.NewInt(0).SetBytes(a.baseIP)
	addr := big.NewInt(0).SetBytes(ip4)
	offset := big.NewInt(0).Sub(addr, base)
	return int(offset.Int64())
}

// indexToIP converts a bitmap index to an IP address.
func (a *Allocator) indexToIP(idx int) net.IP {
	base := big.NewInt(0).SetBytes(a.baseIP)
	offset := big.NewInt(int64(idx))
	result := big.NewInt(0).Add(base, offset)

	b := result.Bytes()
	ip := make(net.IP, 4)
	// Pad with leading zeros.
	copy(ip[4-len(b):], b)
	return ip
}
