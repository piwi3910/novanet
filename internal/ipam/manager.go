package ipam

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"
)

var (
	// ErrPoolAlreadyRegistered is returned when trying to register a pool that already exists.
	ErrPoolAlreadyRegistered = errors.New("pool already registered")
	// ErrPoolNotFound is returned when a pool is not found by name.
	ErrPoolNotFound = errors.New("pool not found")
)

// Manager is the central IPAM manager that routes allocation requests to the
// appropriate pool based on name or type.
type Manager struct {
	mu     sync.RWMutex
	pools  map[string]*Pool // name → pool
	logger *zap.Logger
}

// NewManager creates a new IPAM manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		pools:  make(map[string]*Pool),
		logger: logger,
	}
}

// RegisterPool registers a pool with the manager. Returns an error if a pool
// with the same name already exists.
func (m *Manager) RegisterPool(cfg PoolConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pools[cfg.Name]; exists {
		return fmt.Errorf("%w: %s", ErrPoolAlreadyRegistered, cfg.Name)
	}

	pool, err := NewPool(cfg)
	if err != nil {
		return fmt.Errorf("creating pool %q: %w", cfg.Name, err)
	}

	m.pools[cfg.Name] = pool
	m.logger.Info("registered IP pool",
		zap.String("pool", cfg.Name),
		zap.String("type", string(cfg.Type)),
		zap.Int("cidrs", len(cfg.CIDRs)),
		zap.Int("addresses", len(cfg.Addresses)),
	)
	return nil
}

// UpdatePool updates an existing pool's configuration. If the pool does not
// exist, it creates it.
func (m *Manager) UpdatePool(cfg PoolConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, err := NewPool(cfg)
	if err != nil {
		return fmt.Errorf("creating pool %q: %w", cfg.Name, err)
	}

	m.pools[cfg.Name] = pool
	m.logger.Info("updated IP pool",
		zap.String("pool", cfg.Name),
		zap.String("type", string(cfg.Type)),
	)
	return nil
}

// UnregisterPool removes a pool from the manager.
func (m *Manager) UnregisterPool(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pools, name)
	m.logger.Info("unregistered IP pool", zap.String("pool", name))
}

// Allocate assigns the next available IP from the named pool.
func (m *Manager) Allocate(poolName, owner, resource string) (net.IP, error) {
	pool, err := m.getPool(poolName)
	if err != nil {
		return nil, err
	}
	return pool.Allocate(owner, resource)
}

// AllocateByType assigns the next available IP from the first pool of the
// given type that has availability and autoAssign enabled.
func (m *Manager) AllocateByType(poolType PoolType, owner, resource string) (net.IP, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.pools {
		if pool.Type() != poolType || !pool.AutoAssign() {
			continue
		}
		ip, err := pool.Allocate(owner, resource)
		if err != nil {
			continue // Pool exhausted, try next.
		}
		return ip, pool.Name(), nil
	}

	return nil, "", fmt.Errorf("%w: no pool of type %s with available addresses", ErrNoFreeAddresses, poolType)
}

// AllocateSpecific claims a specific IP from the named pool.
func (m *Manager) AllocateSpecific(poolName string, ip net.IP, owner, resource string) error {
	pool, err := m.getPool(poolName)
	if err != nil {
		return err
	}
	return pool.AllocateSpecific(ip, owner, resource)
}

// Release frees a previously allocated IP from the named pool.
func (m *Manager) Release(poolName string, ip net.IP) error {
	pool, err := m.getPool(poolName)
	if err != nil {
		return err
	}
	return pool.Release(ip)
}

// Validate checks if an IP is valid and available in the named pool.
func (m *Manager) Validate(poolName string, ip net.IP) (bool, error) {
	pool, err := m.getPool(poolName)
	if err != nil {
		return false, err
	}
	return pool.IsAvailable(ip), nil
}

// GetPool returns the status of the named pool.
func (m *Manager) GetPool(name string) (PoolStatus, error) {
	pool, err := m.getPool(name)
	if err != nil {
		return PoolStatus{}, err
	}
	return pool.Status(), nil
}

// ListPools returns status of all pools, optionally filtered by type.
func (m *Manager) ListPools(filterType *PoolType) []PoolStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []PoolStatus
	for _, pool := range m.pools {
		if filterType != nil && pool.Type() != *filterType {
			continue
		}
		result = append(result, pool.Status())
	}
	return result
}

// ListAllocations returns all allocations across pools, with optional filters.
func (m *Manager) ListAllocations(filterPool, filterOwner string, filterType *PoolType) []AllocationInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []AllocationInfo
	for _, pool := range m.pools {
		if filterPool != "" && pool.Name() != filterPool {
			continue
		}
		if filterType != nil && pool.Type() != *filterType {
			continue
		}
		status := pool.Status()
		for _, a := range status.Allocations {
			if filterOwner != "" && a.Owner != filterOwner {
				continue
			}
			result = append(result, a)
		}
	}
	return result
}

// FindPoolForIP finds which pool (if any) contains the given IP.
func (m *Manager) FindPoolForIP(ip net.IP) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, pool := range m.pools {
		if pool.Contains(ip) {
			return name, true
		}
	}
	return "", false
}

// getPool returns the pool with the given name, or an error if not found.
func (m *Manager) getPool(name string) (*Pool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrPoolNotFound, name)
	}
	return pool, nil
}
