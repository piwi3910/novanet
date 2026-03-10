package ipam

import (
	"net"
	"sync"
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

func TestPoolIPv6CIDRAllocate(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:       "ipv6-pool",
		Type:       PoolTypeLoadBalancerVIP,
		CIDRs:      []string{"fd00::/120"},
		AutoAssign: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate first IP.
	ip1, err := p.Allocate("owner", "res")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := net.ParseIP("fd00::")
	if !ip1.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected, ip1)
	}

	status := p.Status()
	if status.Allocated != 1 {
		t.Fatalf("expected 1 allocated, got %d", status.Allocated)
	}
	if status.Total != 256 {
		t.Fatalf("expected 256 total, got %d", status.Total)
	}
}

func TestPoolIPv6AllocateSpecific(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:  "ipv6-specific",
		Type:  PoolTypeIngressIP,
		CIDRs: []string{"fd00::/120"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := net.ParseIP("fd00::50")
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
	err = p.AllocateSpecific(net.ParseIP("fd01::1"), "test", "res")
	if err == nil {
		t.Fatal("expected error for IP outside CIDR")
	}
}

func TestPoolIPv6Release(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:  "ipv6-release",
		Type:  PoolTypePodCIDR,
		CIDRs: []string{"fd00::/120"},
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

func TestPoolIPv6Contains(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:  "ipv6-contains",
		Type:  PoolTypeCustom,
		CIDRs: []string{"fd00::/120"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.Contains(net.ParseIP("fd00::50")) {
		t.Fatal("expected IPv6 CIDR IP to be contained")
	}
	if p.Contains(net.ParseIP("fd01::1")) {
		t.Fatal("expected IP outside pool to not be contained")
	}
}

func TestPoolDualStack(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:       "dual-stack",
		Type:       PoolTypeCustom,
		CIDRs:      []string{"10.0.0.0/28", "fd00::/120"},
		AutoAssign: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status := p.Status()
	// 16 (IPv4 /28) + 256 (IPv6 /120) = 272 total.
	if status.Total != 272 {
		t.Fatalf("expected 272 total, got %d", status.Total)
	}

	if !p.Contains(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected IPv4 IP to be contained")
	}
	if !p.Contains(net.ParseIP("fd00::50")) {
		t.Fatal("expected IPv6 IP to be contained")
	}
}

func TestPoolDiscreteIPv6(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:      "ipv6-discrete",
		Type:      PoolTypeCustom,
		Addresses: []string{"fd00::1", "fd00::2", "fd00::3"},
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
		t.Fatal("expected error on exhausted IPv6 discrete pool")
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

func TestPoolConcurrentAccess(t *testing.T) {
	p, err := NewPool(PoolConfig{
		Name:       "race-pool",
		Type:       PoolTypeCustom,
		CIDRs:      []string{"10.0.0.0/24"},
		Addresses:  []string{"192.168.1.100", "192.168.1.101"},
		AutoAssign: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup

	// Concurrently allocate IPs.
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Allocate("owner", "res")
		}()
	}

	// Concurrently read with Contains, IsAvailable, and Status.
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Contains(net.ParseIP("10.0.0.50"))
			p.IsAvailable(net.ParseIP("10.0.0.51"))
			p.Status()
		}()
	}

	// Concurrently allocate specific IPs.
	specificIPs := []string{
		"10.0.0.200", "10.0.0.201", "10.0.0.202", "10.0.0.203", "10.0.0.204",
		"10.0.0.205", "10.0.0.206", "10.0.0.207", "10.0.0.208", "10.0.0.209",
	}
	for _, ipStr := range specificIPs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.AllocateSpecific(net.ParseIP(ipStr), "owner", "res")
		}()
	}

	wg.Wait()

	// Verify status is consistent.
	status := p.Status()
	if status.Allocated < 0 || status.Allocated > status.Total {
		t.Fatalf("inconsistent status: allocated=%d total=%d", status.Allocated, status.Total)
	}
}
