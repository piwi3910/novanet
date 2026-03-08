// Package routing manages the routing mode (overlay or native) and
// orchestrates tunnels or integrated FRR routing accordingly.
package routing

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/node"
	"github.com/azrtydxb/novanet/internal/tunnel"
)

// Sentinel errors for routing mode operations.
var (
	ErrUnsupportedMode    = errors.New("unsupported routing mode")
	ErrRoutingMgrRequired = errors.New("routing manager is required for native routing mode")
)

// ModeManager orchestrates the networking mode — either overlay (tunnel-based)
// or native (FRR-based routing).
//
// NOTE: This is not yet wired into main.go; the agent currently manages overlay
// and native routing inline. ModeManager is the intended replacement — once
// wired in, the inline routing logic in main.go should be removed.
type ModeManager struct {
	mu sync.RWMutex

	cfg          *config.Config
	tunnelMgr    *tunnel.Manager
	routingMgr   *Manager
	nodeRegistry *node.Registry
	logger       *zap.Logger

	mode   string // "overlay" or "native"
	cancel context.CancelFunc
}

// NewModeManager creates a new routing mode manager.
func NewModeManager(
	cfg *config.Config,
	tunnelMgr *tunnel.Manager,
	routingMgr *Manager,
	nodeRegistry *node.Registry,
	logger *zap.Logger,
) *ModeManager {
	return &ModeManager{
		cfg:          cfg,
		tunnelMgr:    tunnelMgr,
		routingMgr:   routingMgr,
		nodeRegistry: nodeRegistry,
		logger:       logger,
		mode:         cfg.RoutingMode,
	}
}

// Mode returns the current routing mode.
func (m *ModeManager) Mode() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode
}

// Start begins the routing mode manager. In overlay mode, it watches the
// node registry and creates/removes tunnels. In native mode, it connects
// to NovaRoute and advertises the PodCIDR.
func (m *ModeManager) Start(ctx context.Context) error {
	m.mu.Lock()
	routeCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.mu.Unlock()

	switch m.mode {
	case "overlay":
		return m.startOverlay(routeCtx)
	case "native":
		return m.startNative(routeCtx)
	default:
		cancel()
		return fmt.Errorf("%w: %s", ErrUnsupportedMode, m.mode)
	}
}

// Stop gracefully shuts down the routing mode manager.
func (m *ModeManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancelFn := m.cancel
	m.cancel = nil
	m.mu.Unlock()

	if cancelFn != nil {
		cancelFn()
	}

	switch m.mode {
	case "overlay":
		return m.stopOverlay(ctx)
	case "native":
		return m.stopNative(ctx)
	}

	return nil
}

// startOverlay sets up overlay mode by watching node changes and creating tunnels.
func (m *ModeManager) startOverlay(ctx context.Context) error {
	m.logger.Info("starting overlay routing mode",
		zap.String("tunnel_protocol", m.cfg.TunnelProtocol),
	)

	// Register a callback on the node registry to create/remove tunnels.
	m.nodeRegistry.OnNodeChange(func(event string, nodeInfo *node.Info) {
		// Don't process events after we've been stopped.
		select {
		case <-ctx.Done():
			return
		default:
		}

		switch event {
		case "add":
			m.logger.Info("node added, creating tunnel",
				zap.String("node", nodeInfo.Name),
				zap.String("node_ip", nodeInfo.IP),
			)
			if err := m.tunnelMgr.AddTunnel(ctx, nodeInfo.Name, nodeInfo.IP, nodeInfo.PodCIDR); err != nil {
				m.logger.Error("failed to create tunnel",
					zap.Error(err),
					zap.String("node", nodeInfo.Name),
				)
			}

		case "update":
			m.logger.Info("node updated, updating tunnel",
				zap.String("node", nodeInfo.Name),
				zap.String("node_ip", nodeInfo.IP),
			)
			// AddTunnel handles re-creation.
			if err := m.tunnelMgr.AddTunnel(ctx, nodeInfo.Name, nodeInfo.IP, nodeInfo.PodCIDR); err != nil {
				m.logger.Error("failed to update tunnel",
					zap.Error(err),
					zap.String("node", nodeInfo.Name),
				)
			}

		case "delete":
			m.logger.Info("node removed, removing tunnel",
				zap.String("node", nodeInfo.Name),
			)
			if err := m.tunnelMgr.RemoveTunnel(ctx, nodeInfo.Name); err != nil {
				m.logger.Error("failed to remove tunnel",
					zap.Error(err),
					zap.String("node", nodeInfo.Name),
				)
			}
		}
	})

	// Create tunnels for already-known nodes.
	for _, nodeInfo := range m.nodeRegistry.ListNodes() {
		if err := m.tunnelMgr.AddTunnel(ctx, nodeInfo.Name, nodeInfo.IP, nodeInfo.PodCIDR); err != nil {
			m.logger.Error("failed to create initial tunnel",
				zap.Error(err),
				zap.String("node", nodeInfo.Name),
			)
		}
	}

	return nil
}

// stopOverlay removes all tunnels.
func (m *ModeManager) stopOverlay(ctx context.Context) error {
	m.logger.Info("stopping overlay routing mode")

	tunnels := m.tunnelMgr.ListTunnels()
	for _, t := range tunnels {
		if err := m.tunnelMgr.RemoveTunnel(ctx, t.NodeName); err != nil {
			m.logger.Error("failed to remove tunnel during shutdown",
				zap.Error(err),
				zap.String("node", t.NodeName),
			)
		}
	}

	return nil
}

// startNative sets up native routing mode using the integrated FRR routing
// manager and advertises the ClusterCIDR.
func (m *ModeManager) startNative(ctx context.Context) error {
	m.logger.Info("starting native routing mode",
		zap.String("protocol", m.cfg.Routing.Protocol),
	)

	if m.routingMgr == nil {
		return ErrRoutingMgrRequired
	}

	// Wait for FRR sidecar daemons.
	if err := m.routingMgr.WaitForFRR(ctx); err != nil {
		return fmt.Errorf("waiting for FRR: %w", err)
	}

	// Start the reconciliation loop.
	m.routingMgr.Start(ctx)

	// Advertise ClusterCIDR.
	if err := m.routingMgr.AdvertisePrefix(m.cfg.ClusterCIDR); err != nil {
		return fmt.Errorf("advertising ClusterCIDR: %w", err)
	}

	m.logger.Info("native routing mode initialized",
		zap.String("advertised_prefix", m.cfg.ClusterCIDR),
	)

	return nil
}

// stopNative withdraws routes and shuts down the routing manager.
func (m *ModeManager) stopNative(_ context.Context) error {
	m.logger.Info("stopping native routing mode")

	if m.routingMgr == nil {
		return nil
	}

	// Withdraw the ClusterCIDR.
	if err := m.routingMgr.WithdrawPrefix(m.cfg.ClusterCIDR); err != nil {
		m.logger.Error("failed to withdraw prefix during shutdown",
			zap.Error(err),
		)
	}

	// Shut down the routing manager.
	m.routingMgr.Shutdown()

	return nil
}
