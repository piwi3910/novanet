package ipam

import (
	"net"
	"sync"
	"testing"
)

func TestNewAllocator(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{name: "valid /24", cidr: "10.244.1.0/24", wantErr: false},
		{name: "valid /25", cidr: "10.244.1.0/25", wantErr: false},
		{name: "valid /30", cidr: "10.244.1.0/30", wantErr: false},
		{name: "too small /31", cidr: "10.244.1.0/31", wantErr: true},
		{name: "invalid CIDR", cidr: "not-a-cidr", wantErr: true},
		{name: "IPv6 too large", cidr: "fd00::/64", wantErr: true},
		{name: "valid IPv6 /120", cidr: "fd00::/120", wantErr: false},
		{name: "valid IPv6 /112", cidr: "fd00::/112", wantErr: false},
		{name: "IPv6 too small /128", cidr: "fd00::/128", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAllocator(tt.cidr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for CIDR %s", tt.cidr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if a == nil {
				t.Fatal("allocator is nil")
			}
		})
	}
}

func TestAllocatorReservations(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// .0 (network), .1 (gateway), .255 (broadcast) are reserved.
	if a.Used() != 3 {
		t.Fatalf("expected 3 reserved IPs, got %d", a.Used())
	}

	// 256 total - 3 reserved = 253 available.
	if a.Available() != 253 {
		t.Fatalf("expected 253 available IPs, got %d", a.Available())
	}
}

func TestAllocateSequential(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First allocation should be .2 (since .0 and .1 are reserved).
	ip1, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := net.ParseIP("10.244.1.2").To4()
	if !ip1.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected, ip1)
	}

	// Second allocation should be .3.
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected2 := net.ParseIP("10.244.1.3").To4()
	if !ip2.Equal(expected2) {
		t.Fatalf("expected %s, got %s", expected2, ip2)
	}
}

func TestAllocateAllIPs(t *testing.T) {
	// Use a /28 (16 IPs: .0, .1 reserved, .15 broadcast = 13 allocatable).
	a, err := NewAllocator("10.244.1.0/28")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate all available IPs.
	available := a.Available()
	for i := 0; i < available; i++ {
		_, err := a.Allocate()
		if err != nil {
			t.Fatalf("unexpected error on allocation %d: %v", i, err)
		}
	}

	// Pool should be exhausted.
	if a.Available() != 0 {
		t.Fatalf("expected 0 available, got %d", a.Available())
	}

	// Next allocation should fail.
	_, err = a.Allocate()
	if err == nil {
		t.Fatal("expected error on exhausted pool")
	}
}

func TestAllocateSpecific(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate a specific IP.
	ip := net.ParseIP("10.244.1.100")
	err = a.AllocateSpecific(ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocating same IP again should fail.
	err = a.AllocateSpecific(ip)
	if err == nil {
		t.Fatal("expected error on double allocation")
	}

	// Allocating IP outside CIDR should fail.
	err = a.AllocateSpecific(net.ParseIP("10.244.2.1"))
	if err == nil {
		t.Fatal("expected error for IP outside CIDR")
	}
}

func TestAllocateSpecificReserved(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Attempting to allocate reserved .0 should fail.
	err = a.AllocateSpecific(net.ParseIP("10.244.1.0"))
	if err == nil {
		t.Fatal("expected error for network address")
	}

	// Attempting to allocate reserved .1 should fail.
	err = a.AllocateSpecific(net.ParseIP("10.244.1.1"))
	if err == nil {
		t.Fatal("expected error for gateway address")
	}

	// Attempting to allocate broadcast should fail.
	err = a.AllocateSpecific(net.ParseIP("10.244.1.255"))
	if err == nil {
		t.Fatal("expected error for broadcast address")
	}
}

func TestRelease(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	usedBefore := a.Used()
	err = a.Release(ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.Used() != usedBefore-1 {
		t.Fatalf("expected %d used after release, got %d", usedBefore-1, a.Used())
	}

	// Releasing same IP again should fail.
	err = a.Release(ip)
	if err == nil {
		t.Fatal("expected error on double release")
	}
}

func TestReleaseReserved(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cannot release .0.
	err = a.Release(net.ParseIP("10.244.1.0"))
	if err == nil {
		t.Fatal("expected error releasing network address")
	}

	// Cannot release .1.
	err = a.Release(net.ParseIP("10.244.1.1"))
	if err == nil {
		t.Fatal("expected error releasing gateway address")
	}

	// Cannot release broadcast.
	err = a.Release(net.ParseIP("10.244.1.255"))
	if err == nil {
		t.Fatal("expected error releasing broadcast address")
	}
}

func TestReleaseOutsideCIDR(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = a.Release(net.ParseIP("10.244.2.1"))
	if err == nil {
		t.Fatal("expected error for IP outside CIDR")
	}
}

func TestGateway(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gw := a.Gateway()
	expected := net.ParseIP("10.244.1.1").To4()
	if !gw.Equal(expected) {
		t.Fatalf("expected gateway %s, got %s", expected, gw)
	}
}

func TestPrefixLength(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.PrefixLength() != 24 {
		t.Fatalf("expected prefix length 24, got %d", a.PrefixLength())
	}
}

func TestCIDR(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.CIDR() != "10.244.1.0/24" {
		t.Fatalf("expected CIDR 10.244.1.0/24, got %s", a.CIDR())
	}
}

func TestAllocateAfterRelease(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate .2
	ip1, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate .3
	_, err = a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Release .2
	err = a.Release(ip1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Next allocation should reuse .2.
	ip3, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ip3.Equal(ip1) {
		t.Fatalf("expected reuse of %s, got %s", ip1, ip3)
	}
}

func TestConcurrentAccess(t *testing.T) {
	a, err := NewAllocator("10.244.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	allocated := make(chan net.IP, 253)

	// Concurrently allocate IPs.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := a.Allocate()
			if err != nil {
				return
			}
			allocated <- ip
		}()
	}

	// Concurrently read Used() and Available().
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Used()
			_ = a.Available()
		}()
	}

	wg.Wait()
	close(allocated)

	// Check for duplicate IPs.
	seen := make(map[string]bool)
	for ip := range allocated {
		s := ip.String()
		if seen[s] {
			t.Fatalf("duplicate IP allocated: %s", s)
		}
		seen[s] = true
	}
}

func TestStateDirPersistence(t *testing.T) {
	stateDir := t.TempDir()

	// Create allocator with state dir and allocate some IPs.
	a, err := NewAllocatorWithStateDir("10.244.1.0/24", stateDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip1, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	usedAfterAlloc := a.Used()

	// Create a new allocator with the same state dir — should restore allocations.
	a2, err := NewAllocatorWithStateDir("10.244.1.0/24", stateDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a2.Used() != usedAfterAlloc {
		t.Fatalf("expected %d used after restore, got %d", usedAfterAlloc, a2.Used())
	}

	// The restored IPs should be marked as allocated.
	err = a2.AllocateSpecific(ip1)
	if err == nil {
		t.Fatal("expected error: restored IP1 should already be allocated")
	}
	err = a2.AllocateSpecific(ip2)
	if err == nil {
		t.Fatal("expected error: restored IP2 should already be allocated")
	}
}

func TestStateDirRelease(t *testing.T) {
	stateDir := t.TempDir()

	a, err := NewAllocatorWithStateDir("10.244.1.0/24", stateDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Release the IP.
	err = a.Release(ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// New allocator should NOT see the released IP as allocated.
	a2, err := NewAllocatorWithStateDir("10.244.1.0/24", stateDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be able to allocate the same IP again.
	err = a2.AllocateSpecific(ip)
	if err != nil {
		t.Fatalf("released IP should be available after restart: %v", err)
	}
}

func TestIPv6AllocatorReservations(t *testing.T) {
	// /120 = 256 addresses. Only ::0 is reserved for IPv6 (no gateway/broadcast).
	a, err := NewAllocator("fd00::/120")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only ::0 (subnet-router anycast) is reserved.
	if a.Used() != 1 {
		t.Fatalf("expected 1 reserved IP for IPv6, got %d", a.Used())
	}

	// 256 - 1 = 255 available.
	if a.Available() != 255 {
		t.Fatalf("expected 255 available IPs, got %d", a.Available())
	}
}

func TestIPv6AllocateSequential(t *testing.T) {
	a, err := NewAllocator("fd00::/120")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First allocation should be ::1 (since ::0 is reserved).
	ip1, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := net.ParseIP("fd00::1")
	if !ip1.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected, ip1)
	}

	// Second allocation should be ::2.
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected2 := net.ParseIP("fd00::2")
	if !ip2.Equal(expected2) {
		t.Fatalf("expected %s, got %s", expected2, ip2)
	}
}

func TestIPv6AllocateSpecific(t *testing.T) {
	a, err := NewAllocator("fd00::/120")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := net.ParseIP("fd00::50")
	err = a.AllocateSpecific(ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Double allocate should fail.
	err = a.AllocateSpecific(ip)
	if err == nil {
		t.Fatal("expected error on double allocation")
	}

	// Outside CIDR should fail.
	err = a.AllocateSpecific(net.ParseIP("fd01::1"))
	if err == nil {
		t.Fatal("expected error for IP outside CIDR")
	}
}

func TestIPv6Release(t *testing.T) {
	a, err := NewAllocator("fd00::/120")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	usedBefore := a.Used()
	err = a.Release(ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.Used() != usedBefore-1 {
		t.Fatalf("expected %d used after release, got %d", usedBefore-1, a.Used())
	}

	// Cannot release ::0 (reserved subnet-router anycast).
	err = a.Release(net.ParseIP("fd00::"))
	if err == nil {
		t.Fatal("expected error releasing network address")
	}
}

func TestIPv6Gateway(t *testing.T) {
	a, err := NewAllocator("fd00::/120")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gw := a.Gateway()
	expected := net.ParseIP("fd00::1")
	if !gw.Equal(expected) {
		t.Fatalf("expected gateway %s, got %s", expected, gw)
	}
}

func TestIPv6StateDirPersistence(t *testing.T) {
	stateDir := t.TempDir()

	a, err := NewAllocatorWithStateDir("fd00::/120", stateDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip1, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	usedAfterAlloc := a.Used()

	// Recreate allocator — should restore allocations.
	a2, err := NewAllocatorWithStateDir("fd00::/120", stateDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a2.Used() != usedAfterAlloc {
		t.Fatalf("expected %d used after restore, got %d", usedAfterAlloc, a2.Used())
	}

	// Restored IPs should be allocated.
	err = a2.AllocateSpecific(ip1)
	if err == nil {
		t.Fatal("expected error: restored IP1 should already be allocated")
	}
	err = a2.AllocateSpecific(ip2)
	if err == nil {
		t.Fatal("expected error: restored IP2 should already be allocated")
	}
}

func TestSmallCIDR(t *testing.T) {
	// /30 has 4 IPs: .0 (network), .1 (gateway), .2 (usable), .3 (broadcast).
	a, err := NewAllocator("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only 1 allocatable.
	if a.Available() != 1 {
		t.Fatalf("expected 1 available, got %d", a.Available())
	}

	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := net.ParseIP("10.0.0.2").To4()
	if !ip.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected, ip)
	}

	// Should be exhausted now.
	_, err = a.Allocate()
	if err == nil {
		t.Fatal("expected error on exhausted pool")
	}
}
