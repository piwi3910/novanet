// Package ipam provides a bitmap-based IP address management allocator
// for per-node Pod IP allocation within a given PodCIDR.
package ipam

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Sentinel errors for the IPAM allocator.
var (
	ErrIPv4Only         = errors.New("only IPv4 is supported")
	ErrCIDRTooSmall     = errors.New("CIDR is too small (need at least /30)")
	ErrNoFreeAddresses  = errors.New("no free IP addresses")
	ErrIPOutsideCIDR    = errors.New("IP is not within CIDR")
	ErrIPOutOfRange     = errors.New("IP is out of range")
	ErrIPAlreadyAlloc   = errors.New("IP is already allocated")
	ErrIPNotAllocated   = errors.New("IP is not allocated")
	ErrReleaseNetwork   = errors.New("cannot release network address")
	ErrReleaseGateway   = errors.New("cannot release gateway address")
	ErrReleaseBroadcast = errors.New("cannot release broadcast address")
)

// Allocator manages a pool of IP addresses within a single CIDR.
// It uses a Bitmap for efficient allocation tracking.
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
	bitmap *Bitmap
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
		return nil, fmt.Errorf("%w: got %q", ErrIPv4Only, podCIDR)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("%w: got %d-bit mask", ErrIPv4Only, bits)
	}

	size := 1 << (bits - ones)
	if size < 4 {
		return nil, fmt.Errorf("%w: %q", ErrCIDRTooSmall, podCIDR)
	}

	a := &Allocator{
		network:   network,
		baseIP:    network.IP.To4(),
		size:      size,
		bitmap:    NewBitmap(size),
		prefixLen: ones,
		stateDir:  stateDir,
	}

	// Reserve .0 (network address) and .1 (gateway).
	a.bitmap.Set(0)
	a.bitmap.Set(1)
	a.used = 2

	// Reserve broadcast address for /24 and larger.
	if size > 2 {
		a.bitmap.Set(size - 1)
		a.used = 3
	}

	// Restore allocations from disk.
	if stateDir != "" {
		if err := os.MkdirAll(stateDir, 0o750); err != nil {
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

	idx := a.bitmap.FindFree()
	if idx < 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoFreeAddresses, a.network.String())
	}

	a.bitmap.Set(idx)
	a.used++

	ip := a.allocatorIndexToIP(idx)

	if a.stateDir != "" {
		if err := a.saveIP(ip); err != nil {
			// Roll back the allocation on write failure.
			a.bitmap.Clear(idx)
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
		return ErrIPv4Only
	}

	if !a.network.Contains(ip4) {
		return fmt.Errorf("%w: %s in %s", ErrIPOutsideCIDR, ip.String(), a.network.String())
	}

	idx := a.allocatorIPToIndex(ip4)
	if idx < 0 || idx >= a.size {
		return fmt.Errorf("%w: %s", ErrIPOutOfRange, ip.String())
	}

	if a.bitmap.Get(idx) {
		return fmt.Errorf("%w: %s", ErrIPAlreadyAlloc, ip.String())
	}

	a.bitmap.Set(idx)
	a.used++

	if a.stateDir != "" {
		if err := a.saveIP(ip4); err != nil {
			a.bitmap.Clear(idx)
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
		return ErrIPv4Only
	}

	if !a.network.Contains(ip4) {
		return fmt.Errorf("%w: %s in %s", ErrIPOutsideCIDR, ip.String(), a.network.String())
	}

	idx := a.allocatorIPToIndex(ip4)
	if idx < 0 || idx >= a.size {
		return fmt.Errorf("%w: %s", ErrIPOutOfRange, ip.String())
	}

	// Prevent releasing reserved addresses.
	if idx == 0 {
		return fmt.Errorf("%w: %s", ErrReleaseNetwork, ip.String())
	}
	if idx == 1 {
		return fmt.Errorf("%w: %s", ErrReleaseGateway, ip.String())
	}
	if idx == a.size-1 {
		return fmt.Errorf("%w: %s", ErrReleaseBroadcast, ip.String())
	}

	if !a.bitmap.Get(idx) {
		return fmt.Errorf("%w: %s", ErrIPNotAllocated, ip.String())
	}

	a.bitmap.Clear(idx)
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
	return a.allocatorIndexToIP(1)
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
		idx := a.allocatorIPToIndex(ip4)
		if idx < 0 || idx >= a.size {
			continue
		}
		if !a.bitmap.Get(idx) {
			a.bitmap.Set(idx)
			a.used++
		}
	}

	return nil
}

// saveIP writes an empty file named after the IP to the state directory.
func (a *Allocator) saveIP(ip net.IP) error {
	path := filepath.Join(a.stateDir, ip.String())
	return os.WriteFile(path, nil, 0o600)
}

// removeIP deletes the file for the given IP from the state directory.
// Errors are logged but not returned since the bitmap is already updated.
func (a *Allocator) removeIP(ip net.IP) {
	path := filepath.Join(a.stateDir, ip.String())
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		// Log to stderr since we don't have a structured logger here.
		// This is best-effort cleanup; the bitmap is already updated.
		_, _ = fmt.Fprintf(os.Stderr, "ipam: failed to remove state file %s: %v\n", path, err)
	}
}

// allocatorIPToIndex converts an IP address to a bitmap index for this allocator.
func (a *Allocator) allocatorIPToIndex(ip net.IP) int {
	return ipToIndex(a.baseIP, ip.To4())
}

// allocatorIndexToIP converts a bitmap index to an IP address for this allocator.
func (a *Allocator) allocatorIndexToIP(idx int) net.IP {
	return indexToIP(a.baseIP, idx)
}
