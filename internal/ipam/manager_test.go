package ipam

import (
	"net"
	"testing"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func TestManagerRegisterAndAllocate(t *testing.T) {
	mgr := NewManager(testLogger())

	err := mgr.RegisterPool(PoolConfig{
		Name:       "lb-vips",
		Type:       PoolTypeLoadBalancerVIP,
		CIDRs:      []string{"10.10.0.0/28"},
		AutoAssign: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Duplicate registration should fail.
	err = mgr.RegisterPool(PoolConfig{
		Name:  "lb-vips",
		Type:  PoolTypeLoadBalancerVIP,
		CIDRs: []string{"10.10.0.0/28"},
	})
	if err == nil {
		t.Fatal("expected error on duplicate registration")
	}

	// Allocate from named pool.
	ip, err := mgr.Allocate("lb-vips", "novaedge", "svc/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}

	// Release.
	err = mgr.Release("lb-vips", ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerAllocateByType(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:       "ingress-1",
		Type:       PoolTypeIngressIP,
		CIDRs:      []string{"10.20.0.0/28"},
		AutoAssign: true,
	})

	ip, poolName, err := mgr.AllocateByType(PoolTypeIngressIP, "novaedge", "ingress/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if poolName != "ingress-1" {
		t.Fatalf("expected pool ingress-1, got %s", poolName)
	}
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}

	// Non-existent type should fail.
	_, _, err = mgr.AllocateByType(PoolTypePodCIDR, "test", "res")
	if err == nil {
		t.Fatal("expected error for non-existent pool type")
	}
}

func TestManagerAllocateSpecific(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:  "specific-pool",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.30.0.0/24"},
	})

	ip := net.ParseIP("10.30.0.100")
	err := mgr.AllocateSpecific("specific-pool", ip, "test", "res")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Pool not found.
	err = mgr.AllocateSpecific("nonexistent", ip, "test", "res")
	if err == nil {
		t.Fatal("expected error for nonexistent pool")
	}
}

func TestManagerValidate(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:  "validate-pool",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.40.0.0/28"},
	})

	ip := net.ParseIP("10.40.0.5")
	avail, err := mgr.Validate("validate-pool", ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !avail {
		t.Fatal("expected IP to be available")
	}

	_ = mgr.AllocateSpecific("validate-pool", ip, "test", "res")
	avail, err = mgr.Validate("validate-pool", ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if avail {
		t.Fatal("expected IP to be unavailable")
	}
}

func TestManagerListPools(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:  "pool-a",
		Type:  PoolTypeLoadBalancerVIP,
		CIDRs: []string{"10.50.0.0/28"},
	})
	_ = mgr.RegisterPool(PoolConfig{
		Name:  "pool-b",
		Type:  PoolTypePodCIDR,
		CIDRs: []string{"10.51.0.0/28"},
	})

	// List all.
	all := mgr.ListPools(nil)
	if len(all) != 2 {
		t.Fatalf("expected 2 pools, got %d", len(all))
	}

	// Filter by type.
	lbType := PoolTypeLoadBalancerVIP
	lbPools := mgr.ListPools(&lbType)
	if len(lbPools) != 1 {
		t.Fatalf("expected 1 LB pool, got %d", len(lbPools))
	}
}

func TestManagerFindPoolForIP(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:  "find-pool",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.60.0.0/24"},
	})

	poolName, found := mgr.FindPoolForIP(net.ParseIP("10.60.0.50"))
	if !found {
		t.Fatal("expected to find pool")
	}
	if poolName != "find-pool" {
		t.Fatalf("expected find-pool, got %s", poolName)
	}

	_, found = mgr.FindPoolForIP(net.ParseIP("10.61.0.1"))
	if found {
		t.Fatal("expected to not find pool")
	}
}

func TestManagerUnregisterPool(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:  "temp-pool",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.70.0.0/28"},
	})

	mgr.UnregisterPool("temp-pool")

	_, err := mgr.GetPool("temp-pool")
	if err == nil {
		t.Fatal("expected error after unregister")
	}
}

func TestManagerUpdatePool(t *testing.T) {
	mgr := NewManager(testLogger())

	_ = mgr.RegisterPool(PoolConfig{
		Name:  "update-pool",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.80.0.0/28"},
	})

	// Update should succeed (replaces the pool).
	err := mgr.UpdatePool(PoolConfig{
		Name:  "update-pool",
		Type:  PoolTypeLoadBalancerVIP,
		CIDRs: []string{"10.80.0.0/24"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, _ := mgr.GetPool("update-pool")
	if status.Type != PoolTypeLoadBalancerVIP {
		t.Fatalf("expected LB type, got %s", status.Type)
	}
	if status.Total != 256 {
		t.Fatalf("expected 256 total, got %d", status.Total)
	}
}
