package ipam

import (
	"context"
	"testing"

	pb "github.com/azrtydxb/novanet/api/v1"
)

func TestGRPCAllocateByName(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:       "grpc-pool",
		Type:       PoolTypeLoadBalancerVIP,
		CIDRs:      []string{"10.100.0.0/28"},
		AutoAssign: true,
	})

	srv := NewGRPCServer(mgr, testLogger())

	resp, err := srv.Allocate(context.Background(), &pb.AllocateRequest{
		PoolName: "grpc-pool",
		Owner:    "test-client",
		Resource: "svc/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Ip == "" {
		t.Fatal("expected non-empty IP")
	}
	if resp.PoolName != "grpc-pool" {
		t.Fatalf("expected pool grpc-pool, got %s", resp.PoolName)
	}
}

func TestGRPCAllocateByType(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:       "type-pool",
		Type:       PoolTypeIngressIP,
		CIDRs:      []string{"10.101.0.0/28"},
		AutoAssign: true,
	})

	srv := NewGRPCServer(mgr, testLogger())

	resp, err := srv.Allocate(context.Background(), &pb.AllocateRequest{
		PoolType: string(PoolTypeIngressIP),
		Owner:    "test-client",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.PoolName != "type-pool" {
		t.Fatalf("expected type-pool, got %s", resp.PoolName)
	}
}

func TestGRPCAllocateSpecific(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:  "specific-grpc",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.102.0.0/24"},
	})

	srv := NewGRPCServer(mgr, testLogger())

	_, err := srv.AllocateSpecific(context.Background(), &pb.AllocateSpecificRequest{
		PoolName: "specific-grpc",
		Ip:       "10.102.0.50",
		Owner:    "test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Double allocate should fail.
	_, err = srv.AllocateSpecific(context.Background(), &pb.AllocateSpecificRequest{
		PoolName: "specific-grpc",
		Ip:       "10.102.0.50",
		Owner:    "test",
	})
	if err == nil {
		t.Fatal("expected error on double allocation")
	}
}

func TestGRPCRelease(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:       "release-grpc",
		Type:       PoolTypeCustom,
		CIDRs:      []string{"10.103.0.0/28"},
		AutoAssign: true,
	})

	srv := NewGRPCServer(mgr, testLogger())

	allocResp, _ := srv.Allocate(context.Background(), &pb.AllocateRequest{
		PoolName: "release-grpc",
		Owner:    "test",
	})

	_, err := srv.Release(context.Background(), &pb.ReleaseRequest{
		PoolName: "release-grpc",
		Ip:       allocResp.Ip,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGRPCValidate(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:  "validate-grpc",
		Type:  PoolTypeCustom,
		CIDRs: []string{"10.104.0.0/28"},
	})

	srv := NewGRPCServer(mgr, testLogger())

	resp, err := srv.Validate(context.Background(), &pb.ValidateRequest{
		PoolName: "validate-grpc",
		Ip:       "10.104.0.5",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid || !resp.Available {
		t.Fatal("expected valid and available")
	}
}

func TestGRPCGetPool(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:       "getpool-grpc",
		Type:       PoolTypeLoadBalancerVIP,
		CIDRs:      []string{"10.105.0.0/28"},
		AutoAssign: true,
	})

	srv := NewGRPCServer(mgr, testLogger())

	resp, err := srv.GetPool(context.Background(), &pb.GetPoolRequest{
		Name: "getpool-grpc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Total != 16 {
		t.Fatalf("expected 16 total, got %d", resp.Total)
	}
	if resp.Type != string(PoolTypeLoadBalancerVIP) {
		t.Fatalf("expected LB type, got %s", resp.Type)
	}
}

func TestGRPCListPools(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:  "list-a",
		Type:  PoolTypeLoadBalancerVIP,
		CIDRs: []string{"10.106.0.0/28"},
	})
	_ = mgr.RegisterPool(PoolConfig{
		Name:  "list-b",
		Type:  PoolTypePodCIDR,
		CIDRs: []string{"10.107.0.0/28"},
	})

	srv := NewGRPCServer(mgr, testLogger())

	resp, err := srv.ListIPPools(context.Background(), &pb.ListIPPoolsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Pools) != 2 {
		t.Fatalf("expected 2 pools, got %d", len(resp.Pools))
	}

	// Filter by type.
	resp, err = srv.ListIPPools(context.Background(), &pb.ListIPPoolsRequest{
		TypeFilter: string(PoolTypeLoadBalancerVIP),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(resp.Pools))
	}
}

func TestGRPCListAllocations(t *testing.T) {
	mgr := NewManager(testLogger())
	_ = mgr.RegisterPool(PoolConfig{
		Name:       "alloc-list",
		Type:       PoolTypeCustom,
		CIDRs:      []string{"10.108.0.0/28"},
		AutoAssign: true,
	})

	srv := NewGRPCServer(mgr, testLogger())

	// Allocate some IPs.
	_, _ = srv.Allocate(context.Background(), &pb.AllocateRequest{
		PoolName: "alloc-list",
		Owner:    "owner-a",
	})
	_, _ = srv.Allocate(context.Background(), &pb.AllocateRequest{
		PoolName: "alloc-list",
		Owner:    "owner-b",
	})

	resp, err := srv.ListIPAllocations(context.Background(), &pb.ListIPAllocationsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Allocations) != 2 {
		t.Fatalf("expected 2 allocations, got %d", len(resp.Allocations))
	}

	// Filter by owner.
	resp, err = srv.ListIPAllocations(context.Background(), &pb.ListIPAllocationsRequest{
		OwnerFilter: "owner-a",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Allocations) != 1 {
		t.Fatalf("expected 1 allocation, got %d", len(resp.Allocations))
	}
}

func TestGRPCErrorCases(t *testing.T) {
	mgr := NewManager(testLogger())
	srv := NewGRPCServer(mgr, testLogger())

	// Missing pool name and type.
	_, err := srv.Allocate(context.Background(), &pb.AllocateRequest{})
	if err == nil {
		t.Fatal("expected error for missing pool_name and pool_type")
	}

	// Missing pool_name for AllocateSpecific.
	_, err = srv.AllocateSpecific(context.Background(), &pb.AllocateSpecificRequest{
		Ip: "10.0.0.1",
	})
	if err == nil {
		t.Fatal("expected error for missing pool_name")
	}

	// Invalid IP.
	_, err = srv.AllocateSpecific(context.Background(), &pb.AllocateSpecificRequest{
		PoolName: "test",
		Ip:       "not-an-ip",
	})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}

	// Missing pool_name for Release.
	_, err = srv.Release(context.Background(), &pb.ReleaseRequest{
		Ip: "10.0.0.1",
	})
	if err == nil {
		t.Fatal("expected error for missing pool_name")
	}

	// Missing pool_name for Validate.
	_, err = srv.Validate(context.Background(), &pb.ValidateRequest{
		Ip: "10.0.0.1",
	})
	if err == nil {
		t.Fatal("expected error for missing pool_name")
	}

	// Pool not found.
	_, err = srv.GetPool(context.Background(), &pb.GetPoolRequest{
		Name: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent pool")
	}
}
