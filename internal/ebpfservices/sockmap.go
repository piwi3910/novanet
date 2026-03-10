package ebpfservices

import (
	"context"

	pb "github.com/azrtydxb/novanet/api/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// resolvePodIP validates the namespace/name fields, checks that the resolver
// and dataplane are available, and returns the resolved pod IP.
func (s *Server) resolvePodIP(namespace, name string) (string, error) {
	if namespace == "" {
		return "", status.Errorf(codes.InvalidArgument, "pod_namespace is required")
	}
	if name == "" {
		return "", status.Errorf(codes.InvalidArgument, "pod_name is required")
	}
	if s.resolver == nil {
		return "", status.Errorf(codes.Unavailable, "endpoint resolver not configured")
	}
	if s.dataplane == nil {
		return "", status.Errorf(codes.Unavailable, "dataplane not connected")
	}

	podIP, found := s.resolver.LookupEndpoint(namespace, name)
	if !found {
		return "", status.Errorf(codes.NotFound, "endpoint %s/%s not found", namespace, name)
	}
	return podIP, nil
}

// EnableSockmap enables sockmap-based acceleration for a pod.
// It resolves the pod IP from the endpoint store and registers it
// in the dataplane's SOCKMAP eBPF map.
func (s *Server) EnableSockmap(ctx context.Context, req *pb.EnableSockmapRequest) (*pb.EnableSockmapResponse, error) {
	podIP, err := s.resolvePodIP(req.PodNamespace, req.PodName)
	if err != nil {
		return nil, err
	}

	if err := s.dataplane.UpsertSockmapEndpoint(ctx, podIP, 0); err != nil {
		s.logger.Error("failed to upsert sockmap endpoint",
			zap.String("namespace", req.PodNamespace),
			zap.String("name", req.PodName),
			zap.String("ip", podIP),
			zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to enable sockmap: %v", err)
	}

	s.logger.Info("EnableSockmap completed",
		zap.String("namespace", req.PodNamespace),
		zap.String("name", req.PodName),
		zap.String("ip", podIP))
	return &pb.EnableSockmapResponse{}, nil
}

// DisableSockmap disables sockmap-based acceleration for a pod.
// It resolves the pod IP from the endpoint store and removes it
// from the dataplane's SOCKMAP eBPF map.
func (s *Server) DisableSockmap(ctx context.Context, req *pb.DisableSockmapRequest) (*pb.DisableSockmapResponse, error) {
	podIP, err := s.resolvePodIP(req.PodNamespace, req.PodName)
	if err != nil {
		return nil, err
	}

	if err := s.dataplane.DeleteSockmapEndpoint(ctx, podIP, 0); err != nil {
		s.logger.Error("failed to delete sockmap endpoint",
			zap.String("namespace", req.PodNamespace),
			zap.String("name", req.PodName),
			zap.String("ip", podIP),
			zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to disable sockmap: %v", err)
	}

	s.logger.Info("DisableSockmap completed",
		zap.String("namespace", req.PodNamespace),
		zap.String("name", req.PodName),
		zap.String("ip", podIP))
	return &pb.DisableSockmapResponse{}, nil
}

// GetSockmapStats returns sockmap statistics from the dataplane.
func (s *Server) GetSockmapStats(ctx context.Context, _ *pb.GetSockmapStatsRequest) (*pb.GetSockmapStatsResponse, error) {
	if s.dataplane == nil {
		return nil, status.Errorf(codes.Unavailable, "dataplane not connected")
	}
	stats, err := s.dataplane.GetSockmapStats(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get sockmap stats: %v", err)
	}
	return &pb.GetSockmapStatsResponse{
		Redirected:    stats.Redirected,
		Fallback:      stats.Fallback,
		ActiveSockets: stats.ActiveEndpoints,
	}, nil
}
