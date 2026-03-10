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
	ErrCIDRTooSmall     = errors.New("CIDR is too small (need at least /30 for IPv4 or /127 for IPv6)")
	ErrNoFreeAddresses  = errors.New("no free IP addresses")
	ErrIPOutsideCIDR    = errors.New("IP is not within CIDR")
	ErrIPOutOfRange     = errors.New("IP is out of range")
	ErrIPAlreadyAlloc   = errors.New("IP is already allocated")
	ErrIPNotAllocated   = errors.New("IP is not allocated")
	ErrReleaseNetwork   = errors.New("cannot release network address")
	ErrReleaseGateway   = errors.New("cannot release gateway address")
	ErrReleaseBroadcast = errors.New("cannot release broadcast address")
	ErrCIDRTooLarge     = errors.New("CIDR too large")
)

// Allocator manages a pool of IP addresses within a single CIDR.
// It uses a Bitmap for efficient allocation tracking.
// When stateDir is set, allocations are persisted as files so that the
// bitmap can be rebuilt after an agent restart.
// Supports both IPv4 and IPv6 CIDRs. The maximum subnet size is capped
// at maxCIDRSize to prevent excessive memory usage.
type Allocator struct {
	mu sync.RWMutex

	// network is the parsed CIDR network.
	network *net.IPNet
	// baseIP is the network address (4-byte for IPv4, 16-byte for IPv6).
	baseIP net.IP
	// size is the total number of IPs in the CIDR.
	size int
	// bitmap tracks which IPs are allocated. Bit i corresponds to baseIP + i.
	bitmap *Bitmap
	// used counts the number of currently allocated IPs (including reserved).
	used int
	// prefixLen is the CIDR prefix length.
	prefixLen int
	// ipLen is 4 for IPv4 or 16 for IPv6.
	ipLen int
	// isIPv4 is true for IPv4 CIDRs, false for IPv6.
	isIPv4 bool
	// stateDir is the directory for persisting IP allocations.
	// Empty string means in-memory only.
	stateDir string
}

// NewAllocator creates a new IPAM allocator for the given PodCIDR.
// For IPv4, the network address (.0), gateway address (.1), and broadcast
// address are automatically reserved.
// For IPv6, only the network address (::0) is reserved.
func NewAllocator(podCIDR string) (*Allocator, error) {
	return NewAllocatorWithStateDir(podCIDR, "")
}

// NewAllocatorWithStateDir creates an IPAM allocator that persists allocations
// to the given directory. If stateDir is empty, the allocator is in-memory only.
// On startup, existing files in stateDir are loaded to rebuild the bitmap.
// Supports both IPv4 and IPv6 CIDRs with a maximum of 20 host bits
// (up to 1M addresses).
func NewAllocatorWithStateDir(podCIDR, stateDir string) (*Allocator, error) {
	_, network, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("parsing podCIDR %q: %w", podCIDR, err)
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits > 20 {
		return nil, fmt.Errorf("%w: %s has %d host bits (max 20, %d addresses)", ErrCIDRTooLarge, podCIDR, hostBits, maxCIDRSize)
	}

	size := 1 << hostBits
	isIPv4 := bits == 32

	if isIPv4 && size < 4 {
		return nil, fmt.Errorf("%w: %q", ErrCIDRTooSmall, podCIDR)
	}
	if !isIPv4 && size < 2 {
		return nil, fmt.Errorf("%w: %q", ErrCIDRTooSmall, podCIDR)
	}

	var baseIP net.IP
	ipLen := 4
	if !isIPv4 {
		baseIP = network.IP.To16()
		ipLen = 16
	} else {
		baseIP = network.IP.To4()
	}

	a := &Allocator{
		network:   network,
		baseIP:    baseIP,
		size:      size,
		bitmap:    NewBitmap(size),
		prefixLen: ones,
		ipLen:     ipLen,
		isIPv4:    isIPv4,
		stateDir:  stateDir,
	}

	if isIPv4 {
		// Reserve .0 (network address) and .1 (gateway).
		a.bitmap.Set(0)
		a.bitmap.Set(1)
		a.used = 2

		// Reserve broadcast address for /24 and larger.
		if size > 2 {
			a.bitmap.Set(size - 1)
			a.used = 3
		}
	} else {
		// For IPv6, reserve ::0 (subnet-router anycast address).
		a.bitmap.Set(0)
		a.used = 1
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

	ipNorm := normalizeIP(ip)

	if !a.network.Contains(ipNorm) {
		return fmt.Errorf("%w: %s in %s", ErrIPOutsideCIDR, ip.String(), a.network.String())
	}

	idx := a.allocatorIPToIndex(ipNorm)
	if idx < 0 || idx >= a.size {
		return fmt.Errorf("%w: %s", ErrIPOutOfRange, ip.String())
	}

	if a.bitmap.Get(idx) {
		return fmt.Errorf("%w: %s", ErrIPAlreadyAlloc, ip.String())
	}

	a.bitmap.Set(idx)
	a.used++

	if a.stateDir != "" {
		if err := a.saveIP(ipNorm); err != nil {
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

	ipNorm := normalizeIP(ip)

	if !a.network.Contains(ipNorm) {
		return fmt.Errorf("%w: %s in %s", ErrIPOutsideCIDR, ip.String(), a.network.String())
	}

	idx := a.allocatorIPToIndex(ipNorm)
	if idx < 0 || idx >= a.size {
		return fmt.Errorf("%w: %s", ErrIPOutOfRange, ip.String())
	}

	// Prevent releasing reserved addresses.
	// Both IPv4 and IPv6 reserve index 0 (network/anycast address).
	if idx == 0 {
		return fmt.Errorf("%w: %s", ErrReleaseNetwork, ip.String())
	}
	if a.isIPv4 {
		if idx == 1 {
			return fmt.Errorf("%w: %s", ErrReleaseGateway, ip.String())
		}
		if idx == a.size-1 {
			return fmt.Errorf("%w: %s", ErrReleaseBroadcast, ip.String())
		}
	}

	if !a.bitmap.Get(idx) {
		return fmt.Errorf("%w: %s", ErrIPNotAllocated, ip.String())
	}

	a.bitmap.Clear(idx)
	a.used--

	if a.stateDir != "" {
		a.removeIP(ipNorm)
	}

	return nil
}

// Used returns the number of allocated IPs (including reserved addresses).
func (a *Allocator) Used() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.used
}

// Available returns the number of IPs available for allocation.
// This excludes reserved addresses.
func (a *Allocator) Available() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.size - a.used
}

// Gateway returns the gateway IP (.1 of the CIDR for IPv4, ::1 for IPv6).
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
		ipNorm := normalizeIP(ip)
		if !a.network.Contains(ipNorm) {
			continue // Skip IPs outside our CIDR.
		}
		idx := a.allocatorIPToIndex(ipNorm)
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
	return ipToIndex(a.baseIP, ip, a.ipLen)
}

// allocatorIndexToIP converts a bitmap index to an IP address for this allocator.
func (a *Allocator) allocatorIndexToIP(idx int) net.IP {
	return indexToIP(a.baseIP, idx, a.ipLen)
}
