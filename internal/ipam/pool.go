package ipam

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// ErrInvalidIPAddress is returned when an IP address string cannot be parsed.
var ErrInvalidIPAddress = errors.New("invalid IP address")

// maxCIDRSize caps the bitmap size for both IPv4 and IPv6 CIDRs.
// A /108 IPv6 gives 1M addresses; a /12 IPv4 gives 1M addresses.
const maxCIDRSize = 1 << 20

// Pool manages a set of IP addresses from one or more CIDRs and/or explicit
// addresses. It uses Bitmap-based tracking for CIDR ranges and a map for
// discrete addresses. All operations are thread-safe.
type Pool struct {
	mu sync.RWMutex

	name       string
	poolType   PoolType
	autoAssign bool
	owner      string

	// CIDR-based ranges.
	ranges []cidrRange

	// Discrete addresses (for non-CIDR pools).
	discreteAddrs map[string]bool // IP string → allocated?

	// All allocations tracked by IP string.
	allocations map[string]AllocationInfo
}

// cidrRange tracks a single CIDR within a pool.
type cidrRange struct {
	network   *net.IPNet
	baseIP    net.IP // 4-byte for IPv4, 16-byte for IPv6
	size      int
	bitmap    *Bitmap
	prefixLen int
	ipLen     int // 4 for IPv4, 16 for IPv6
}

// NewPool creates a pool from the given configuration.
func NewPool(cfg PoolConfig) (*Pool, error) {
	p := &Pool{
		name:          cfg.Name,
		poolType:      cfg.Type,
		autoAssign:    cfg.AutoAssign,
		owner:         cfg.Owner,
		discreteAddrs: make(map[string]bool),
		allocations:   make(map[string]AllocationInfo),
	}

	for _, cidr := range cfg.CIDRs {
		cr, err := parseCIDRRange(cidr)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
		}
		p.ranges = append(p.ranges, cr)
	}

	for _, addr := range cfg.Addresses {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidIPAddress, addr)
		}
		p.discreteAddrs[ip.String()] = false
	}

	return p, nil
}

// parseCIDRRange parses a CIDR string into a cidrRange with bitmap.
// Supports both IPv4 and IPv6 CIDRs. The maximum subnet size is capped
// at maxCIDRSize to prevent excessive memory usage.
func parseCIDRRange(cidr string) (cidrRange, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidrRange{}, err
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits > 20 {
		return cidrRange{}, fmt.Errorf("%w: %s has %d host bits (max 20, %d addresses)", ErrCIDRTooLarge, cidr, hostBits, maxCIDRSize)
	}
	size := 1 << hostBits

	// Normalize base IP to the correct length.
	var baseIP net.IP
	ipLen := 4
	if bits == 128 {
		baseIP = network.IP.To16()
		ipLen = 16
	} else {
		baseIP = network.IP.To4()
	}

	cr := cidrRange{
		network:   network,
		baseIP:    baseIP,
		size:      size,
		bitmap:    NewBitmap(size),
		prefixLen: ones,
		ipLen:     ipLen,
	}

	return cr, nil
}

// Name returns the pool name.
func (p *Pool) Name() string { return p.name }

// Type returns the pool type.
func (p *Pool) Type() PoolType { return p.poolType }

// AutoAssign returns whether automatic allocation is enabled.
func (p *Pool) AutoAssign() bool { return p.autoAssign }

// Owner returns the pool owner.
func (p *Pool) Owner() string { return p.owner }

// Allocate returns the next available IP from the pool.
func (p *Pool) Allocate(owner, resource string) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try CIDR ranges first.
	for i := range p.ranges {
		cr := &p.ranges[i]
		idx := cr.bitmap.FindFree()
		if idx < 0 {
			continue
		}
		cr.bitmap.Set(idx)
		ip := indexToIP(cr.baseIP, idx, cr.ipLen)
		p.allocations[ip.String()] = AllocationInfo{
			IP:        ip,
			Owner:     owner,
			Resource:  resource,
			Timestamp: time.Now(),
		}
		return ip, nil
	}

	// Try discrete addresses.
	for addr, allocated := range p.discreteAddrs {
		if !allocated {
			p.discreteAddrs[addr] = true
			ip := net.ParseIP(addr)
			p.allocations[addr] = AllocationInfo{
				IP:        ip,
				Owner:     owner,
				Resource:  resource,
				Timestamp: time.Now(),
			}
			return ip, nil
		}
	}

	return nil, fmt.Errorf("%w: pool %s", ErrNoFreeAddresses, p.name)
}

// AllocateSpecific claims a specific IP from the pool.
func (p *Pool) AllocateSpecific(ip net.IP, owner, resource string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipNorm := normalizeIP(ip)
	ipStr := ipNorm.String()

	// Check discrete addresses.
	if allocated, ok := p.discreteAddrs[ipStr]; ok {
		if allocated {
			return fmt.Errorf("%w: %s", ErrIPAlreadyAlloc, ipStr)
		}
		p.discreteAddrs[ipStr] = true
		p.allocations[ipStr] = AllocationInfo{
			IP:        ipNorm,
			Owner:     owner,
			Resource:  resource,
			Timestamp: time.Now(),
		}
		return nil
	}

	// Check CIDR ranges.
	for i := range p.ranges {
		cr := &p.ranges[i]
		if !cr.network.Contains(ipNorm) {
			continue
		}
		idx := ipToIndex(cr.baseIP, ipNorm, cr.ipLen)
		if idx < 0 || idx >= cr.size {
			return fmt.Errorf("%w: %s", ErrIPOutOfRange, ipStr)
		}
		if cr.bitmap.Get(idx) {
			return fmt.Errorf("%w: %s", ErrIPAlreadyAlloc, ipStr)
		}
		cr.bitmap.Set(idx)
		p.allocations[ipStr] = AllocationInfo{
			IP:        ipNorm,
			Owner:     owner,
			Resource:  resource,
			Timestamp: time.Now(),
		}
		return nil
	}

	return fmt.Errorf("%w: %s in pool %s", ErrIPOutsideCIDR, ipStr, p.name)
}

// Release frees a previously allocated IP.
func (p *Pool) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipNorm := normalizeIP(ip)
	ipStr := ipNorm.String()

	if _, ok := p.allocations[ipStr]; !ok {
		return fmt.Errorf("%w: %s", ErrIPNotAllocated, ipStr)
	}

	// Release from discrete addresses.
	if _, ok := p.discreteAddrs[ipStr]; ok {
		p.discreteAddrs[ipStr] = false
		delete(p.allocations, ipStr)
		return nil
	}

	// Release from CIDR ranges.
	for i := range p.ranges {
		cr := &p.ranges[i]
		if !cr.network.Contains(ipNorm) {
			continue
		}
		idx := ipToIndex(cr.baseIP, ipNorm, cr.ipLen)
		if idx >= 0 && idx < cr.size {
			cr.bitmap.Clear(idx)
			delete(p.allocations, ipStr)
			return nil
		}
	}

	// Allocation existed but IP not found in any range — clean up anyway.
	delete(p.allocations, ipStr)
	return nil
}

// IsAvailable checks if the given IP is valid and available in this pool.
func (p *Pool) IsAvailable(ip net.IP) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ipNorm := normalizeIP(ip)
	ipStr := ipNorm.String()

	// Check discrete addresses.
	if allocated, ok := p.discreteAddrs[ipStr]; ok {
		return !allocated
	}

	// Check CIDR ranges.
	for i := range p.ranges {
		cr := &p.ranges[i]
		if !cr.network.Contains(ipNorm) {
			continue
		}
		idx := ipToIndex(cr.baseIP, ipNorm, cr.ipLen)
		if idx >= 0 && idx < cr.size {
			return !cr.bitmap.Get(idx)
		}
	}

	return false
}

// Contains checks if the given IP belongs to this pool (regardless of allocation state).
func (p *Pool) Contains(ip net.IP) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ipNorm := normalizeIP(ip)
	ipStr := ipNorm.String()

	if _, ok := p.discreteAddrs[ipStr]; ok {
		return true
	}
	for i := range p.ranges {
		if p.ranges[i].network.Contains(ipNorm) {
			return true
		}
	}
	return false
}

// Status returns the current pool status.
func (p *Pool) Status() PoolStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := len(p.discreteAddrs)
	for _, cr := range p.ranges {
		total += cr.size
	}

	allocated := len(p.allocations)
	allocs := make([]AllocationInfo, 0, allocated)
	for _, a := range p.allocations {
		allocs = append(allocs, a)
	}

	return PoolStatus{
		Name:        p.name,
		Type:        p.poolType,
		Allocated:   allocated,
		Total:       total,
		Available:   total - allocated,
		Allocations: allocs,
	}
}

// normalizeIP returns ip.To4() if it's an IPv4 address, otherwise ip.To16().
func normalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

// indexToIP converts a bitmap index to an IP address relative to a base IP.
// ipLen must be 4 (IPv4) or 16 (IPv6).
func indexToIP(baseIP net.IP, idx int, ipLen int) net.IP {
	base := new(big.Int).SetBytes(baseIP)
	offset := big.NewInt(int64(idx))
	result := new(big.Int).Add(base, offset)

	b := result.Bytes()
	ip := make(net.IP, ipLen)
	// Right-align the bytes in the IP slice.
	copy(ip[ipLen-len(b):], b)
	return ip
}

// ipToIndex converts an IP address to a bitmap index relative to a base IP.
// ipLen must be 4 (IPv4) or 16 (IPv6).
func ipToIndex(baseIP, ip net.IP, ipLen int) int {
	// Normalize both to the correct length.
	var baseBytes, ipBytes []byte
	if ipLen == 4 {
		baseBytes = baseIP.To4()
		ipBytes = ip.To4()
	} else {
		baseBytes = baseIP.To16()
		ipBytes = ip.To16()
	}
	if baseBytes == nil || ipBytes == nil {
		return -1
	}
	base := new(big.Int).SetBytes(baseBytes)
	addr := new(big.Int).SetBytes(ipBytes)
	offset := new(big.Int).Sub(addr, base)
	return int(offset.Int64())
}
