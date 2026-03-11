package constants

import "time"

// Scope constants matching eBPF SVC_SCOPE_*.
const (
	ScopeClusterIP    uint32 = 0
	ScopeNodePort     uint32 = 1
	ScopeExternalIP   uint32 = 2
	ScopeLoadBalancer uint32 = 3
)

// Algorithm constants matching eBPF LB_ALG_*.
const (
	AlgRandom     uint32 = 0
	AlgRoundRobin uint32 = 1
	AlgMaglev     uint32 = 2
)

// DefaultResyncPeriod is the standard resync interval for Kubernetes informers.
const DefaultResyncPeriod = 30 * time.Second
