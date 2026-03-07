package ipam

import (
	"net"
	"testing"
)

func TestPoolCIDRAllocate(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:       "test-pool",
		Type:       PoolTypeLoadBalancerVIP,
		CIDRs:      []string{"192.168.1.0/28"},
		AutoAssign: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate first IP — should be .0 since LB pools don't reserve.
	ip1, err := p.Allocate("novaedge", "svc/my-lb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := net.ParseIP("192.168.1.0").To4()
	if !ip1.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected, ip1)
	}

	// Status should show 1 allocated.
	status := p.Status()
	if status.Allocated != 1 {
		t.Fatalf("expected 1 allocated, got %d", status.Allocated)
	}
	if status.Total != 16 {
		t.Fatalf("expected 16 total, got %d", status.Total)
	}
}

func TestPoolDiscreteAllocate(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:       "discrete-pool",
		Type:       PoolTypeCustom,
		Addresses:  []string{"10.0.0.100", "10.0.0.101", "10.0.0.102"},
		AutoAssign: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status := p.Status()
	if status.Total != 3 {
		t.Fatalf("expected 3 total, got %d", status.Total)
	}

	// Allocate all three.
	for i := range 3 {
		_, err := p.Allocate("owner", "res")
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
	}

	// Pool should be exhausted.
	_, err = p.Allocate("owner", "res")
	if err == nil {
		t.Fatal("expected error on exhausted discrete pool")
	}
}

func TestPoolAllocateSpecific(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:  "specific-pool",
		Type:  PoolTypeIngressIP,
		CIDRs: []string{"10.0.0.0/24"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := net.ParseIP("10.0.0.50")
	err = p.AllocateSpecific(ip, "test", "res")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Double allocate should fail.
	err = p.AllocateSpecific(ip, "test", "res")
	if err == nil {
		t.Fatal("expected error on double allocation")
	}

	// Outside CIDR should fail.
	err = p.AllocateSpecific(net.ParseIP("10.0.1.1"), "test", "res")
	if err == nil {
		t.Fatal("expected error for IP outside CIDR")
	}
}

func TestPoolRelease(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:  "release-pool",
		Type:  PoolTypePodCIDR,
		CIDRs: []string{"10.0.0.0/28"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip, err := p.Allocate("test", "res")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = p.Release(ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Double release should fail.
	err = p.Release(ip)
	if err == nil {
		t.Fatal("expected error on double release")
	}
}

func TestPoolIsAvailable(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:  "avail-pool",
		Type:  PoolTypeCustom,
		CIDRs: []string{"172.16.0.0/30"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := net.ParseIP("172.16.0.1")
	if !p.IsAvailable(ip) {
		t.Fatal("expected IP to be available")
	}

	_ = p.AllocateSpecific(ip, "test", "res")
	if p.IsAvailable(ip) {
		t.Fatal("expected IP to be unavailable after allocation")
	}
}

func TestPoolContains(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:      "contains-pool",
		Type:      PoolTypeCustom,
		CIDRs:     []string{"10.0.0.0/24"},
		Addresses: []string{"192.168.1.100"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.Contains(net.ParseIP("10.0.0.50")) {
		t.Fatal("expected CIDR IP to be contained")
	}
	if !p.Contains(net.ParseIP("192.168.1.100")) {
		t.Fatal("expected discrete IP to be contained")
	}
	if p.Contains(net.ParseIP("10.0.1.1")) {
		t.Fatal("expected IP outside pool to not be contained")
	}
}
