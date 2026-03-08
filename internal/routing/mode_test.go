package routing

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/node"
	"github.com/azrtydxb/novanet/internal/tunnel"
)

const (
	testOverlayMode = "overlay"
	testGeneveProto = "geneve"
)

// requireRoot skips the test when the process lacks CAP_NET_ADMIN.
func requireRoot(t *testing.T) {
	t.Helper()
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

func testOverlayConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.RoutingMode = testOverlayMode
	cfg.TunnelProtocol = testGeneveProto
	return cfg
}

func testNativeConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.RoutingMode = "native"
	cfg.Routing.Protocol = "bgp"
	cfg.Routing.FRRSocketDir = "/run/frr"
	return cfg
}

func TestNewModeManager(t *testing.T) {
	cfg := testOverlayConfig()
	tunnelMgr := tunnel.NewManager("geneve", net.ParseIP("10.0.0.1"), 100, nil, testLogger())
	nodeReg := node.NewRegistry(testLogger())

	m := NewModeManager(cfg, tunnelMgr, nil, nodeReg, testLogger())
	if m == nil {
		t.Fatal("expected non-nil mode manager")
	}
	if m.Mode() != testOverlayMode {
		t.Fatalf("expected overlay mode, got %s", m.Mode())
	}
}

func TestOverlayModeStart(t *testing.T) {
	cfg := testOverlayConfig()
	tunnelMgr := tunnel.NewManager("geneve", net.ParseIP("10.0.0.1"), 100, nil, testLogger())
	nodeReg := node.NewRegistry(testLogger())

	m := NewModeManager(cfg, tunnelMgr, nil, nodeReg, testLogger())

	ctx := t.Context()

	err := m.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOverlayModeCreatesInitialTunnels(t *testing.T) {
	requireRoot(t)
	cfg := testOverlayConfig()
	tunnelMgr := tunnel.NewManager("geneve", net.ParseIP("10.0.0.1"), 100, nil, testLogger())
	nodeReg := node.NewRegistry(testLogger())

	// Add nodes before starting.
	nodeReg.AddNode("node-2", "10.0.0.2", "10.244.2.0/24")
	nodeReg.AddNode("node-3", "10.0.0.3", "10.244.3.0/24")

	m := NewModeManager(cfg, tunnelMgr, nil, nodeReg, testLogger())

	ctx := t.Context()

	err := m.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tunnels should be created for existing nodes.
	if tunnelMgr.Count() != 2 {
		t.Fatalf("expected 2 tunnels, got %d", tunnelMgr.Count())
	}
}

func TestOverlayModeReactsToNodeChanges(t *testing.T) {
	requireRoot(t)
	cfg := testOverlayConfig()
	tunnelMgr := tunnel.NewManager("geneve", net.ParseIP("10.0.0.1"), 100, nil, testLogger())
	nodeReg := node.NewRegistry(testLogger())

	m := NewModeManager(cfg, tunnelMgr, nil, nodeReg, testLogger())

	ctx := t.Context()

	err := m.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Add a node after starting.
	nodeReg.AddNode("node-2", "10.0.0.2", "10.244.2.0/24")

	// Give time for callback to fire.
	time.Sleep(50 * time.Millisecond)

	if tunnelMgr.Count() != 1 {
		t.Fatalf("expected 1 tunnel after node add, got %d", tunnelMgr.Count())
	}

	// Remove the node.
	nodeReg.RemoveNode("node-2")

	time.Sleep(50 * time.Millisecond)

	if tunnelMgr.Count() != 0 {
		t.Fatalf("expected 0 tunnels after node remove, got %d", tunnelMgr.Count())
	}
}

func TestOverlayModeStop(t *testing.T) {
	requireRoot(t)
	cfg := testOverlayConfig()
	tunnelMgr := tunnel.NewManager("geneve", net.ParseIP("10.0.0.1"), 100, nil, testLogger())
	nodeReg := node.NewRegistry(testLogger())

	nodeReg.AddNode("node-2", "10.0.0.2", "10.244.2.0/24")

	m := NewModeManager(cfg, tunnelMgr, nil, nodeReg, testLogger())

	ctx := t.Context()

	_ = m.Start(ctx)

	err := m.Stop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All tunnels should be removed.
	if tunnelMgr.Count() != 0 {
		t.Fatalf("expected 0 tunnels after stop, got %d", tunnelMgr.Count())
	}
}

func TestNativeModeRequiresManager(t *testing.T) {
	cfg := testNativeConfig()
	nodeReg := node.NewRegistry(testLogger())

	m := NewModeManager(cfg, nil, nil, nodeReg, testLogger())

	ctx := t.Context()

	err := m.Start(ctx)
	if err == nil {
		t.Fatal("expected error when routing manager is nil")
	}
}

func TestUnknownMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RoutingMode = "unknown"
	nodeReg := node.NewRegistry(testLogger())

	m := NewModeManager(cfg, nil, nil, nodeReg, testLogger())

	ctx := t.Context()

	err := m.Start(ctx)
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}
