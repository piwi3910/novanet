package tunnel

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	"github.com/azrtydxb/novanet/internal/dataplane"

	pb "github.com/azrtydxb/novanet/api/v1"
)

// requireRoot skips the test when the process lacks CAP_NET_ADMIN.
// Checking os.Getuid() alone is insufficient because CI containers often
// run as root but without network administration capabilities.
func requireRoot(t *testing.T) {
	t.Helper()
	// Try creating a dummy bridge interface — a write operation that requires
	// CAP_NET_ADMIN. LinkList() is read-only and may succeed without it.
	dummy := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "novanet_captest"}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Skipf("requires CAP_NET_ADMIN for netlink operations: %v", err)
	}
	_ = netlink.LinkDel(dummy)
}

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

// mockDPClient implements dataplane.ClientInterface for testing.
type mockDPClient struct {
	mu                sync.Mutex
	upsertTunnelCalls int
	deleteTunnelCalls int
}

func (m *mockDPClient) Connect(ctx context.Context) error                                { return nil }
func (m *mockDPClient) UpsertEndpoint(ctx context.Context, ep *dataplane.Endpoint) error { return nil }
func (m *mockDPClient) DeleteEndpoint(ctx context.Context, ip string) error              { return nil }
func (m *mockDPClient) UpsertPolicy(ctx context.Context, rule *dataplane.PolicyRule) error {
	return nil
}
func (m *mockDPClient) DeletePolicy(ctx context.Context, rule *dataplane.PolicyRule) error {
	return nil
}
func (m *mockDPClient) SyncPolicies(ctx context.Context, rules []*dataplane.PolicyRule) (*dataplane.SyncResult, error) {
	return &dataplane.SyncResult{}, nil
}
func (m *mockDPClient) UpdateConfig(ctx context.Context, entries map[uint32]uint64) error { return nil }
func (m *mockDPClient) AttachProgram(ctx context.Context, iface string, attachType dataplane.AttachType) error {
	return nil
}
func (m *mockDPClient) DetachProgram(ctx context.Context, iface string, attachType dataplane.AttachType) error {
	return nil
}
func (m *mockDPClient) StreamFlows(ctx context.Context, identityFilter uint32) (<-chan *dataplane.FlowEvent, error) {
	return nil, nil
}
func (m *mockDPClient) GetStatus(ctx context.Context) (*dataplane.Status, error) {
	return &dataplane.Status{}, nil
}
func (m *mockDPClient) Close() error { return nil }
func (m *mockDPClient) UpsertSockmapEndpoint(_ context.Context, _ string, _ uint32) error {
	return nil
}
func (m *mockDPClient) DeleteSockmapEndpoint(_ context.Context, _ string, _ uint32) error {
	return nil
}
func (m *mockDPClient) GetSockmapStats(_ context.Context) (*dataplane.SockmapStats, error) {
	return &dataplane.SockmapStats{}, nil
}
func (m *mockDPClient) UpsertMeshService(_ context.Context, _ string, _, _ uint32) error {
	return nil
}
func (m *mockDPClient) DeleteMeshService(_ context.Context, _ string, _ uint32) error {
	return nil
}
func (m *mockDPClient) ListMeshServices(_ context.Context) ([]*dataplane.MeshServiceEntry, error) {
	return nil, nil
}
func (m *mockDPClient) UpdateRateLimitConfig(_ context.Context, _, _ uint32, _ uint64) error {
	return nil
}
func (m *mockDPClient) GetRateLimitStats(_ context.Context) (*dataplane.RateLimitStats, error) {
	return &dataplane.RateLimitStats{}, nil
}
func (m *mockDPClient) GetBackendHealthStats(_ context.Context, _ string, _ uint32) ([]*dataplane.BackendHealthInfo, error) {
	return nil, nil
}

func (m *mockDPClient) UpsertBackends(_ context.Context, _ []*dataplane.Backend) error { return nil }
func (m *mockDPClient) UpsertServiceEntry(_ context.Context, _ *dataplane.ServiceConfig) error {
	return nil
}

func (m *mockDPClient) UpsertTunnel(ctx context.Context, nodeIP string, ifindex, vni uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertTunnelCalls++
	return nil
}

func (m *mockDPClient) DeleteTunnel(ctx context.Context, nodeIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteTunnelCalls++
	return nil
}

// Unused but needed to show pb import is valid.
var _ = pb.PolicyAction_POLICY_ACTION_ALLOW

func testManager(protocol string) (*Manager, *mockDPClient) {
	dp := &mockDPClient{}
	m := NewManager(protocol, net.ParseIP("10.0.0.1"), 100, dp, testLogger())
	return m, dp
}

func TestNewManager(t *testing.T) {
	m, _ := testManager("geneve")
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.Protocol() != "geneve" {
		t.Fatalf("expected protocol geneve, got %s", m.Protocol())
	}
}

func TestAddGeneveTunnel(t *testing.T) {
	requireRoot(t)
	m, dp := testManager("geneve")

	err := m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Count() != 1 {
		t.Fatalf("expected 1 tunnel, got %d", m.Count())
	}

	info, ok := m.GetTunnel("node-2")
	if !ok {
		t.Fatal("expected to find tunnel")
	}
	if info.NodeName != "node-2" {
		t.Fatalf("expected node-2, got %s", info.NodeName)
	}
	if info.NodeIP != "10.0.0.2" {
		t.Fatalf("expected IP 10.0.0.2, got %s", info.NodeIP)
	}
	if info.Ifindex <= 0 {
		t.Fatalf("expected positive ifindex, got %d", info.Ifindex)
	}

	dp.mu.Lock()
	if dp.upsertTunnelCalls != 1 {
		t.Fatalf("expected 1 upsert call, got %d", dp.upsertTunnelCalls)
	}
	dp.mu.Unlock()
}

func TestAddVxlanTunnel(t *testing.T) {
	requireRoot(t)
	m, _ := testManager("vxlan")

	err := m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Count() != 1 {
		t.Fatalf("expected 1 tunnel, got %d", m.Count())
	}
}

func TestAddTunnelUnsupportedProtocol(t *testing.T) {
	m := NewManager("wireguard", net.ParseIP("10.0.0.1"), 100, nil, testLogger())

	err := m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestAddTunnelUpdate(t *testing.T) {
	requireRoot(t)
	m, dp := testManager("geneve")

	_ = m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	_ = m.AddTunnel(context.Background(), "node-2", "10.0.0.3", "10.244.2.0/24") // Update with new IP.

	if m.Count() != 1 {
		t.Fatalf("expected 1 tunnel after update, got %d", m.Count())
	}

	info, _ := m.GetTunnel("node-2")
	if info.NodeIP != "10.0.0.3" {
		t.Fatalf("expected updated IP 10.0.0.3, got %s", info.NodeIP)
	}

	dp.mu.Lock()
	// One delete for the old, two upserts total.
	if dp.deleteTunnelCalls != 1 {
		t.Fatalf("expected 1 delete call for update, got %d", dp.deleteTunnelCalls)
	}
	if dp.upsertTunnelCalls != 2 {
		t.Fatalf("expected 2 upsert calls, got %d", dp.upsertTunnelCalls)
	}
	dp.mu.Unlock()
}

func TestRemoveTunnel(t *testing.T) {
	requireRoot(t)
	m, dp := testManager("geneve")

	_ = m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	err := m.RemoveTunnel(context.Background(), "node-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Count() != 0 {
		t.Fatalf("expected 0 tunnels, got %d", m.Count())
	}

	dp.mu.Lock()
	if dp.deleteTunnelCalls != 1 {
		t.Fatalf("expected 1 delete call, got %d", dp.deleteTunnelCalls)
	}
	dp.mu.Unlock()
}

func TestRemoveNonExistentTunnel(t *testing.T) {
	m, _ := testManager("geneve")

	err := m.RemoveTunnel(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetTunnelNotFound(t *testing.T) {
	m, _ := testManager("geneve")

	_, ok := m.GetTunnel("nonexistent")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestGetTunnelReturnsCopy(t *testing.T) {
	requireRoot(t)
	m, _ := testManager("geneve")
	_ = m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")

	info, _ := m.GetTunnel("node-2")
	info.NodeIP = "modified"

	original, _ := m.GetTunnel("node-2")
	if original.NodeIP != "10.0.0.2" {
		t.Fatal("modifying returned tunnel affected stored tunnel")
	}
}

func TestListTunnels(t *testing.T) {
	requireRoot(t)
	m, _ := testManager("geneve")

	_ = m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	_ = m.AddTunnel(context.Background(), "node-3", "10.0.0.3", "10.244.3.0/24")
	_ = m.AddTunnel(context.Background(), "node-4", "10.0.0.4", "10.244.4.0/24")

	tunnels := m.ListTunnels()
	if len(tunnels) != 3 {
		t.Fatalf("expected 3 tunnels, got %d", len(tunnels))
	}
}

func TestListTunnelsEmpty(t *testing.T) {
	m, _ := testManager("geneve")

	tunnels := m.ListTunnels()
	if len(tunnels) != 0 {
		t.Fatalf("expected 0 tunnels, got %d", len(tunnels))
	}
}

func TestConcurrentAccess(t *testing.T) {
	requireRoot(t)
	m, _ := testManager("geneve")

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			name := "node-" + string(rune('a'+i%26))
			_ = m.AddTunnel(context.Background(), name, "10.0.0."+string(rune('1'+i%9)), "10.244.0.0/24")
		})
	}

	for range 20 {
		wg.Go(func() {
			m.ListTunnels()
		})
	}

	wg.Wait()
}

func TestAddTunnelWithNilDPClient(t *testing.T) {
	requireRoot(t)
	m := NewManager("geneve", net.ParseIP("10.0.0.1"), 100, nil, testLogger())

	err := m.AddTunnel(context.Background(), "node-2", "10.0.0.2", "10.244.2.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Count() != 1 {
		t.Fatalf("expected 1 tunnel, got %d", m.Count())
	}
}
