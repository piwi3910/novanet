package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/dataplane"
	"github.com/azrtydxb/novanet/internal/ebpfservices"
	"github.com/azrtydxb/novanet/internal/grpcauth"
	"github.com/azrtydxb/novanet/internal/ipam"
	"github.com/azrtydxb/novanet/internal/routing"
	"github.com/azrtydxb/novanet/internal/tunnel"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// StartGRPCServer creates a Unix socket listener and gRPC server.
func StartGRPCServer(logger *zap.Logger, socketPath, name string, register func(*grpc.Server)) (net.Listener, *grpc.Server, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating directory %s: %w", dir, err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("failed to remove stale socket", zap.String("socket", socketPath), zap.Error(err))
	}
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("listening on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		logger.Warn("failed to chmod socket", zap.String("socket", socketPath), zap.Error(err))
	}
	// Only allow root (UID 0) to connect to gRPC Unix sockets.
	srv := grpcauth.NewAuthenticatedServer(logger, []uint32{0})
	register(srv)
	logger.Info("gRPC server created", zap.String("name", name), zap.String("socket", socketPath))
	return lis, srv, nil
}

// StartCNIServer starts the CNI gRPC server and returns the server handle.
func StartCNIServer(logger *zap.Logger, cfg *config.Config, agentSrv *Server) *grpc.Server {
	cniListener, cniGRPC, err := StartGRPCServer(logger, cfg.CNISocket, "CNI", func(s *grpc.Server) {
		pb.RegisterAgentControlServer(s, agentSrv)
	})
	if err != nil {
		logger.Fatal("failed to start CNI gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("CNI gRPC server listening", zap.String("socket", cfg.CNISocket))
		if err := cniGRPC.Serve(cniListener); err != nil {
			logger.Error("CNI gRPC server error", zap.Error(err))
		}
	}()
	return cniGRPC
}

// StartAgentGRPCServer starts the agent gRPC server for novanetctl.
func StartAgentGRPCServer(logger *zap.Logger, cfg *config.Config, agentSrv *Server) *grpc.Server {
	agentListener, agentGRPC, err := StartGRPCServer(logger, cfg.ListenSocket, "agent", func(s *grpc.Server) {
		pb.RegisterAgentControlServer(s, agentSrv)
	})
	if err != nil {
		logger.Fatal("failed to start agent gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("agent gRPC server listening", zap.String("socket", cfg.ListenSocket))
		if err := agentGRPC.Serve(agentListener); err != nil {
			logger.Error("agent gRPC server error", zap.Error(err))
		}
	}()
	return agentGRPC
}

// StartIPAMServer starts the shared IPAM gRPC server.
func StartIPAMServer(logger *zap.Logger, ipamMgr *ipam.Manager) *grpc.Server {
	const ipamSocket = "/run/novanet/ipam.sock"
	ipamSrv := ipam.NewGRPCServer(ipamMgr, logger)
	ipamListener, ipamGRPC, err := StartGRPCServer(logger, ipamSocket, "IPAM", func(s *grpc.Server) {
		pb.RegisterIPAMServiceServer(s, ipamSrv)
	})
	if err != nil {
		logger.Fatal("failed to start IPAM gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("IPAM gRPC server listening", zap.String("socket", ipamSocket))
		if err := ipamGRPC.Serve(ipamListener); err != nil {
			logger.Error("IPAM gRPC server error", zap.Error(err))
		}
	}()
	return ipamGRPC
}

// StartEBPFServicesServer starts the EBPFServices gRPC server if enabled.
func StartEBPFServicesServer(logger *zap.Logger, cfg *config.Config, dpConnected bool, resolver ebpfservices.EndpointResolver) *grpc.Server {
	if !cfg.EBPFServices.Enabled {
		logger.Info("EBPFServices gRPC server disabled")
		return nil
	}
	var dpClient dataplane.ClientInterface
	if dpConnected {
		client, err := dataplane.NewClient(cfg.DataplaneSocket, logger.Named("ebpf-dp"))
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if connErr := client.Connect(ctx); connErr != nil {
				logger.Warn("EBPFServices: failed to connect dataplane client", zap.Error(connErr))
			} else {
				dpClient = client
			}
		} else {
			logger.Warn("EBPFServices: failed to create dataplane client", zap.Error(err))
		}
	}
	ebpfSrv := ebpfservices.NewServer(logger, dpClient, resolver)
	ebpfListener, ebpfGRPC, err := StartGRPCServer(logger, cfg.EBPFServices.SocketPath, "EBPFServices", func(s *grpc.Server) {
		pb.RegisterEBPFServicesServer(s, ebpfSrv)
	})
	if err != nil {
		logger.Fatal("failed to start EBPFServices gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("EBPFServices gRPC server listening", zap.String("socket", cfg.EBPFServices.SocketPath))
		if err := ebpfGRPC.Serve(ebpfListener); err != nil {
			logger.Error("EBPFServices gRPC server error", zap.Error(err))
		}
	}()
	return ebpfGRPC
}

// StartMetricsServer starts the Prometheus metrics and health check HTTP server.
func StartMetricsServer(logger *zap.Logger, cfg *config.Config, agentSrv *Server) *http.Server {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !agentSrv.DpConnected.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"not ready","reason":"dataplane not connected","version":"%s"}`, Version)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, Version)
	})
	metricsServer := &http.Server{Addr: cfg.MetricsAddress, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("metrics server listening", zap.String("address", cfg.MetricsAddress))
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()
	return metricsServer
}

// WaitForSignal blocks until a SIGTERM or SIGINT signal is received.
func WaitForSignal(logger *zap.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("received signal, starting graceful shutdown", zap.String("signal", sig.String()))
}

// GracefulShutdown performs an orderly shutdown of all agent components.
func GracefulShutdown(s *ShutdownState) {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()
	s.Cancel()
	s.BgWg.Wait()
	s.Logger.Info("background goroutines stopped")
	ShutdownRouting(s.Logger, s.NrClient, s.PodCIDR)
	s.CniGRPC.GracefulStop()
	s.Logger.Info("CNI gRPC server stopped")
	s.AgentGRPC.GracefulStop()
	s.Logger.Info("agent gRPC server stopped")
	if s.IpamGRPC != nil {
		s.IpamGRPC.GracefulStop()
		s.Logger.Info("IPAM gRPC server stopped")
	}
	if s.EbpfServicesGRPC != nil {
		s.EbpfServicesGRPC.GracefulStop()
		s.Logger.Info("EBPFServices gRPC server stopped")
	}
	if err := s.MetricsServer.Shutdown(shutdownCtx); err != nil {
		s.Logger.Error("metrics server shutdown error", zap.Error(err))
	}
	s.Logger.Info("metrics server stopped")
	if s.XdpMgr != nil {
		s.XdpMgr.DetachAll()
		s.Logger.Info("XDP programs detached")
	}
	if s.WgManager != nil {
		if err := s.WgManager.Close(); err != nil {
			s.Logger.Error("failed to close WireGuard interface", zap.Error(err))
		} else {
			s.Logger.Info("WireGuard interface removed")
		}
	}
	if s.DpConn != nil {
		_ = s.DpConn.Close()
		s.Logger.Info("dataplane connection closed")
	}
	s.Logger.Info("novanet-agent shutdown complete")
}

// ShutdownRouting withdraws the PodCIDR prefix and shuts down the routing manager.
func ShutdownRouting(logger *zap.Logger, routingMgr *routing.Manager, podCIDR string) {
	if routingMgr == nil {
		return
	}
	logger.Info("withdrawing PodCIDR", zap.String("pod_cidr", podCIDR))
	if err := routingMgr.WithdrawPrefix(podCIDR); err != nil {
		logger.Error("failed to withdraw prefix", zap.Error(err))
	}
	routingMgr.Shutdown()
	if err := tunnel.RemoveBlackholeRoute(podCIDR); err != nil {
		logger.Debug("failed to remove blackhole route", zap.Error(err))
	}
	logger.Info("routing manager stopped")
}
