// Package ipam provides IP address management for the Nova ecosystem.
package ipam

import (
	"net"
	"time"
)

// PoolType identifies the purpose of an IP pool.
type PoolType string

// Pool type constants.
const (
	PoolTypeLoadBalancerVIP  PoolType = "LoadBalancerVIP"
	PoolTypeIngressIP        PoolType = "IngressIP"
	PoolTypePodCIDR          PoolType = "PodCIDR"
	PoolTypeServiceClusterIP PoolType = "ServiceClusterIP"
	PoolTypeCustom           PoolType = "Custom"
)

// AllocationState represents the state of an IP allocation.
type AllocationState string

// Allocation state constants.
const (
	AllocationStateBound    AllocationState = "Bound"
	AllocationStateReleased AllocationState = "Released"
	AllocationStateConflict AllocationState = "Conflict"
)

// PoolConfig holds the configuration for creating or updating a pool.
type PoolConfig struct {
	Name       string
	Type       PoolType
	CIDRs      []string
	Addresses  []string
	AutoAssign bool
	Owner      string
}

// AllocationInfo tracks a single IP allocation within a pool.
type AllocationInfo struct {
	IP        net.IP
	Owner     string
	Resource  string
	Timestamp time.Time
}

// PoolStatus holds the current status of a pool.
type PoolStatus struct {
	Name        string
	Type        PoolType
	Allocated   int
	Total       int
	Available   int
	Allocations []AllocationInfo
}
