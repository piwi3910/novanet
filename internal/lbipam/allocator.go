// Package lbipam provides IP address management for Kubernetes Services
// of type LoadBalancer. It allocates IPs from configured address pools
// and tracks which service owns each allocation.
package lbipam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sync"

	"go.uber.org/zap"
)

// Sentinel errors for the LB-IPAM allocator.
var (
	ErrNoPoolSpace     = errors.New("no pool has available addresses")
	ErrPoolNotFound    = errors.New("pool not found")
	ErrPoolExists      = errors.New("pool already exists")
	ErrInvalidCIDR     = errors.New("invalid CIDR notation")
	ErrIPAlreadyInUse  = errors.New("IP already allocated")
	ErrIPNotAllocated  = errors.New("IP is not allocated")
	ErrPoolExhausted   = errors.New("pool exhausted")
	ErrAlreadyAssigned = errors.New("service already has an allocation")
)

// lbBitmap is a bitmap for tracking allocated IP addresses. It uses
// math/bits.TrailingZeros64 for O(1) free-bit lookup per 64-bit word,
// giving O(N/64) worst-case allocation for an N-address pool.
type lbBitmap struct {
	words []uint64
	size  int // total number of bits
}

// newLBBitmap creates a bitmap with the given number of bits, all clear.
func newLBBitmap(size int) *lbBitmap {
	nwords := (size + 63) / 64
	return &lbBitmap{
		words: make([]uint64, nwords),
		size:  size,
	}
}

// set marks bit idx as allocated. idx must be non-negative.
func (b *lbBitmap) set(idx int) {
	shift := uint64(idx % 64) //nolint:gosec // idx is always in [0, size)
	b.words[idx/64] |= 1 << shift
}

// clear marks bit idx as free. idx must be non-negative.
func (b *lbBitmap) clear(idx int) {
	shift := uint64(idx % 64) //nolint:gosec // idx is always in [0, size)
	b.words[idx/64] &^= 1 << shift
}

// findFree returns the index of the first unset bit, or -1 if all bits are set.
// Uses TrailingZeros64 on the complement of each word for fast scanning.
func (b *lbBitmap) findFree() int {
	for i, w := range b.words {
		inv := ^w
		if inv == 0 {
			continue // all 64 bits allocated
		}
		bit := bits.TrailingZeros64(inv)
		idx := i*64 + bit
		if idx >= b.size {
			return -1
		}
		return idx
	}
	return -1
}

// Pool represents a named block of IP addresses available for allocation
// to LoadBalancer Services.
type Pool struct {
	Name string
	CIDR net.IPNet
	used map[string]string // IP string -> service key (namespace/name)

	// bm tracks allocated offsets within the pool for O(1) free-address lookup.
	bm *lbBitmap
	// poolSize is the total number of host addresses in this pool's CIDR.
	poolSize int
	// baseIP is the starting (network) address of the pool.
	baseIP net.IP
}

// Allocator manages multiple IP pools and allocates addresses to Services.
type Allocator struct {
	mu     sync.RWMutex
	pools  []*Pool
	logger *zap.Logger
}

// NewAllocator creates a new LB-IPAM allocator.
func NewAllocator(logger *zap.Logger) *Allocator {
	return &Allocator{
		pools:  make([]*Pool, 0),
		logger: logger,
	}
}

// AddPool registers a new IP pool with the given name and CIDR range.
func (a *Allocator) AddPool(name, cidr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, p := range a.pools {
		if p.Name == name {
			return fmt.Errorf("%w: %s", ErrPoolExists, name)
		}
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidCIDR, err.Error())
	}

	size := poolSize(ipNet)
	sizeInt := int(size) //nolint:gosec // pool sizes are bounded by CIDR prefix length (max 2^63)
	a.pools = append(a.pools, &Pool{
		Name:     name,
		CIDR:     *ipNet,
		used:     make(map[string]string),
		bm:       newLBBitmap(sizeInt),
		poolSize: sizeInt,
		baseIP:   cloneIP(ipNet.IP),
	})

	a.logger.Info("added LB-IPAM pool", zap.String("name", name), zap.String("cidr", cidr))
	return nil
}

// RemovePool removes a pool by name, releasing all its allocations.
func (a *Allocator) RemovePool(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, p := range a.pools {
		if p.Name == name {
			a.pools = append(a.pools[:i], a.pools[i+1:]...)
			a.logger.Info("removed LB-IPAM pool", zap.String("name", name))
			return
		}
	}
}

// Allocate assigns an IP from the first pool with available space.
func (a *Allocator) Allocate(serviceKey string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, pool := range a.pools {
		ip, err := a.allocateFromPoolLocked(pool, serviceKey)
		if err == nil {
			return ip, nil
		}
		// If pool is exhausted, try next pool.
		if !errors.Is(err, ErrPoolExhausted) {
			return nil, err
		}
	}
	return nil, ErrNoPoolSpace
}

// AllocateFromPool assigns an IP from the specified pool.
func (a *Allocator) AllocateFromPool(poolName, serviceKey string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, pool := range a.pools {
		if pool.Name == poolName {
			return a.allocateFromPoolLocked(pool, serviceKey)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrPoolNotFound, poolName)
}

// allocateFromPoolLocked finds the next free IP in a pool using the bitmap
// and assigns it. Caller must hold a.mu.
func (a *Allocator) allocateFromPoolLocked(pool *Pool, serviceKey string) (net.IP, error) {
	idx := pool.bm.findFree()
	if idx < 0 {
		return nil, ErrPoolExhausted
	}

	candidate := addToIP(pool.baseIP, uint64(idx)) //nolint:gosec // idx is non-negative from findFree
	key := candidate.String()

	pool.bm.set(idx)
	pool.used[key] = serviceKey

	a.logger.Info("allocated LB IP",
		zap.String("ip", key),
		zap.String("pool", pool.Name),
		zap.String("service", serviceKey),
	)
	return candidate, nil
}

// Release frees a previously allocated IP address.
func (a *Allocator) Release(ip net.IP) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := ip.String()
	for _, pool := range a.pools {
		if _, ok := pool.used[key]; ok {
			delete(pool.used, key)
			if offset := ipToOffset(pool.baseIP, ip); offset >= 0 && offset < pool.poolSize {
				pool.bm.clear(offset)
			}
			a.logger.Info("released LB IP",
				zap.String("ip", key),
				zap.String("pool", pool.Name),
			)
			return true
		}
	}
	return false
}

// ipToOffset computes the offset of ip from base. Returns -1 if the IPs
// have different address families.
func ipToOffset(base, ip net.IP) int {
	b := base.To16()
	i := ip.To16()
	if b == nil || i == nil {
		return -1
	}
	baseVal := binary.BigEndian.Uint64(b[8:16])
	ipVal := binary.BigEndian.Uint64(i[8:16])
	if ipVal < baseVal {
		return -1
	}
	return int(ipVal - baseVal) //nolint:gosec // offset is bounded by pool size
}

// GetServiceForIP returns the service key that owns the given IP.
func (a *Allocator) GetServiceForIP(ip net.IP) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	key := ip.String()
	for _, pool := range a.pools {
		if svc, ok := pool.used[key]; ok {
			return svc, true
		}
	}
	return "", false
}

// ListAllocations returns a snapshot of all current allocations
// as a map of IP string to service key.
func (a *Allocator) ListAllocations() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]string)
	for _, pool := range a.pools {
		for ip, svc := range pool.used {
			result[ip] = svc
		}
	}
	return result
}

// poolSize returns the number of host addresses in a CIDR block.
func poolSize(cidr *net.IPNet) uint64 {
	ones, bits := cidr.Mask.Size()
	hostBits := bits - ones
	if hostBits < 0 || hostBits > 63 {
		return 0
	}
	return 1 << uint64(hostBits)
}

// cloneIP returns a copy of an IP address.
func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// addToIP adds an offset to a base IP address.
func addToIP(base net.IP, offset uint64) net.IP {
	ip := cloneIP(base).To16()
	if ip == nil {
		return nil
	}
	// Treat the last 8 bytes as a uint64 and add the offset.
	val := binary.BigEndian.Uint64(ip[8:16])
	val += offset
	result := make(net.IP, 16)
	copy(result[:8], ip[:8])
	binary.BigEndian.PutUint64(result[8:16], val)
	// Return as 4-byte IPv4 if the original was IPv4.
	if base.To4() != nil {
		return result.To4()
	}
	return result
}
