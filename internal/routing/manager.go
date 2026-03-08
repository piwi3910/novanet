// Package routing provides an integrated routing manager that replaces the
// former NovaRoute gRPC client. It manages BGP/BFD/OSPF routing via FRR
// directly in-process using an intent store and reconciler.
package routing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/azrtydxb/novanet/internal/routing/frr"
	"github.com/azrtydxb/novanet/internal/routing/intent"
	"github.com/azrtydxb/novanet/internal/routing/reconciler"
	rtypes "github.com/azrtydxb/novanet/internal/routing/types"
	"go.uber.org/zap"
)

// ManagerConfig holds configuration for the routing manager.
type ManagerConfig struct {
	// FRRSocketDir is the directory where FRR VTY sockets are located.
	FRRSocketDir string
	// ReconcileInterval is the periodic reconciliation interval.
	ReconcileInterval time.Duration
}

// Manager provides the routing control interface, replacing the former
// NovaRoute gRPC client. It manages intents and reconciles them to FRR
// configuration via the vtysh client.
type Manager struct {
	logger *zap.Logger

	store      *intent.Store
	rec        *reconciler.Reconciler
	frrClient  *frr.Client
	owner      string
	reconcileI time.Duration

	cancel context.CancelFunc
	done   chan struct{}
}

// NewManager creates a new routing manager.
func NewManager(cfg ManagerConfig, owner string, logger *zap.Logger) *Manager {
	if cfg.FRRSocketDir == "" {
		cfg.FRRSocketDir = "/run/frr"
	}
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = 30 * time.Second
	}

	store := intent.NewStore(logger)
	frrClient := frr.NewClient(cfg.FRRSocketDir, logger)
	rec := reconciler.NewReconciler(store, frrClient, logger, nil)

	return &Manager{
		logger:     logger.With(zap.String("component", "routing")),
		store:      store,
		rec:        rec,
		frrClient:  frrClient,
		owner:      owner,
		reconcileI: cfg.ReconcileInterval,
		done:       make(chan struct{}),
	}
}

// Start begins the periodic reconciliation loop. The FRR client connects
// lazily on first vtysh command, so no explicit connect is needed.
func (m *Manager) Start(ctx context.Context) {
	childCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	go func() {
		defer close(m.done)
		m.rec.RunLoop(childCtx, m.reconcileI)
	}()

	m.logger.Info("routing manager started",
		zap.Duration("reconcile_interval", m.reconcileI))
}

// ErrFRRNotReady is returned when FRR daemons are not available after retries.
var ErrFRRNotReady = errors.New("FRR daemons not ready")

// WaitForFRR blocks until FRR daemon sockets are available, with retries.
func (m *Manager) WaitForFRR(ctx context.Context) error {
	const maxRetries = 30
	delay := time.Second

	for attempt := 1; ; attempt++ {
		if m.frrClient.IsReady() {
			m.logger.Info("FRR daemons ready")
			return nil
		}

		if attempt >= maxRetries {
			return fmt.Errorf("%w after %d attempts", ErrFRRNotReady, attempt)
		}

		m.logger.Info("waiting for FRR daemons...", zap.Int("attempt", attempt))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// ConfigureBGP sets the BGP global configuration (AS number and router ID).
func (m *Manager) ConfigureBGP(localAS uint32, routerID string) {
	m.rec.UpdateBGPGlobal(localAS, routerID)
	m.rec.TriggerReconcile()
	m.logger.Info("BGP configured",
		zap.Uint32("local_as", localAS),
		zap.String("router_id", routerID))
}

// BFDOptions holds BFD configuration for a BGP peer.
type BFDOptions struct {
	Enabled          bool
	MinRxMs          uint32
	MinTxMs          uint32
	DetectMultiplier uint32
}

// ApplyPeer adds or updates a BGP peer with optional BFD configuration.
func (m *Manager) ApplyPeer(neighborAddr string, remoteAS uint32, bfd *BFDOptions) error {
	peer := intent.PeerIntent{
		Owner:           m.owner,
		NeighborAddress: neighborAddr,
		RemoteAS:        remoteAS,
		PeerType:        rtypes.PeerTypeExternal,
		AddressFamilies: []rtypes.AddressFamily{rtypes.AddressFamilyIPv4Unicast},
	}
	if bfd != nil && bfd.Enabled {
		peer.BFDEnabled = true
		peer.BFDMinRxMs = bfd.MinRxMs
		peer.BFDMinTxMs = bfd.MinTxMs
		peer.BFDDetectMultiplier = bfd.DetectMultiplier
	}

	if err := m.store.SetPeerIntent(m.owner, &peer); err != nil {
		return fmt.Errorf("setting peer intent for %s: %w", neighborAddr, err)
	}
	m.rec.TriggerReconcile()

	m.logger.Info("applied BGP peer",
		zap.String("neighbor", neighborAddr),
		zap.Uint32("remote_as", remoteAS),
		zap.Bool("bfd", bfd != nil && bfd.Enabled))
	return nil
}

// AdvertisePrefix advertises a route prefix via BGP.
func (m *Manager) AdvertisePrefix(prefix string) error {
	pfx := intent.PrefixIntent{
		Owner:    m.owner,
		Prefix:   prefix,
		Protocol: rtypes.ProtocolBGP,
	}

	if err := m.store.SetPrefixIntent(m.owner, &pfx); err != nil {
		return fmt.Errorf("setting prefix intent for %s: %w", prefix, err)
	}
	m.rec.TriggerReconcile()

	m.logger.Info("advertised prefix", zap.String("prefix", prefix))
	return nil
}

// WithdrawPrefix withdraws a previously advertised prefix.
func (m *Manager) WithdrawPrefix(prefix string) error {
	if err := m.store.RemovePrefixIntent(m.owner, prefix, "bgp"); err != nil {
		m.logger.Debug("prefix not found for withdrawal (may already be removed)",
			zap.String("prefix", prefix), zap.Error(err))
		return nil
	}
	m.rec.TriggerReconcile()

	m.logger.Info("withdrew prefix", zap.String("prefix", prefix))
	return nil
}

// Store returns the underlying intent store for direct access (e.g. by CLI).
func (m *Manager) Store() *intent.Store {
	return m.store
}

// FRRClient returns the underlying FRR client for direct vtysh queries (e.g. by CLI).
func (m *Manager) FRRClient() *frr.Client {
	return m.frrClient
}

// Shutdown stops the reconciler and disconnects from FRR.
func (m *Manager) Shutdown() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
	_ = m.frrClient.Close()
	m.logger.Info("routing manager stopped")
}
