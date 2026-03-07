package ipam

import (
	"context"
	"fmt"
	"net"

	pb "github.com/azrtydxb/novanet/api/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// GRPCServer implements the IPAMService gRPC API backed by the IPAM Manager.
type GRPCServer struct {
	pb.UnimplementedIPAMServiceServer

	manager *Manager
	logger  *zap.Logger
}

// NewGRPCServer creates a new IPAM gRPC server.
func NewGRPCServer(manager *Manager, logger *zap.Logger) *GRPCServer {
	return &GRPCServer{
		manager: manager,
		logger:  logger,
	}
}

// Allocate requests the next available IP from a pool.
func (s *GRPCServer) Allocate(_ context.Context, req *pb.AllocateRequest) (*pb.AllocateResponse, error) {
	if req.PoolName != "" {
		ip, err := s.manager.Allocate(req.PoolName, req.Owner, req.Resource)
		if err != nil {
			s.logger.Warn("IPAM Allocate failed",
				zap.String("pool", req.PoolName),
				zap.String("owner", req.Owner),
				zap.Error(err),
			)
			return nil, grpcstatus.Errorf(codes.ResourceExhausted, "allocation failed: %v", err)
		}
		s.logger.Info("IPAM Allocate",
			zap.String("pool", req.PoolName),
			zap.String("ip", ip.String()),
			zap.String("owner", req.Owner),
		)
		return &pb.AllocateResponse{
			Ip:       ip.String(),
			PoolName: req.PoolName,
		}, nil
	}

	if req.PoolType != "" {
		poolType := PoolType(req.PoolType)
		ip, poolName, err := s.manager.AllocateByType(poolType, req.Owner, req.Resource)
		if err != nil {
			return nil, grpcstatus.Errorf(codes.ResourceExhausted, "allocation by type failed: %v", err)
		}
		s.logger.Info("IPAM AllocateByType",
			zap.String("pool", poolName),
			zap.String("type", req.PoolType),
			zap.String("ip", ip.String()),
			zap.String("owner", req.Owner),
		)
		return &pb.AllocateResponse{
			Ip:       ip.String(),
			PoolName: poolName,
		}, nil
	}

	return nil, grpcstatus.Error(codes.InvalidArgument, "pool_name or pool_type required")
}

// AllocateSpecific claims a specific IP from a pool.
func (s *GRPCServer) AllocateSpecific(_ context.Context, req *pb.AllocateSpecificRequest) (*pb.AllocateSpecificResponse, error) {
	if req.PoolName == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "pool_name required")
	}

	ip := net.ParseIP(req.Ip)
	if ip == nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "invalid IP address: %s", req.Ip)
	}

	if err := s.manager.AllocateSpecific(req.PoolName, ip, req.Owner, req.Resource); err != nil {
		s.logger.Warn("IPAM AllocateSpecific failed",
			zap.String("pool", req.PoolName),
			zap.String("ip", req.Ip),
			zap.Error(err),
		)
		return nil, grpcstatus.Errorf(codes.AlreadyExists, "specific allocation failed: %v", err)
	}

	s.logger.Info("IPAM AllocateSpecific",
		zap.String("pool", req.PoolName),
		zap.String("ip", req.Ip),
		zap.String("owner", req.Owner),
	)
	return &pb.AllocateSpecificResponse{}, nil
}

// Release frees a previously allocated IP.
func (s *GRPCServer) Release(_ context.Context, req *pb.ReleaseRequest) (*pb.ReleaseResponse, error) {
	if req.PoolName == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "pool_name required")
	}

	ip := net.ParseIP(req.Ip)
	if ip == nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "invalid IP address: %s", req.Ip)
	}

	if err := s.manager.Release(req.PoolName, ip); err != nil {
		s.logger.Warn("IPAM Release failed",
			zap.String("pool", req.PoolName),
			zap.String("ip", req.Ip),
			zap.Error(err),
		)
		return nil, grpcstatus.Errorf(codes.NotFound, "release failed: %v", err)
	}

	s.logger.Info("IPAM Release",
		zap.String("pool", req.PoolName),
		zap.String("ip", req.Ip),
	)
	return &pb.ReleaseResponse{}, nil
}

// Validate checks if an IP is valid and available in a pool.
func (s *GRPCServer) Validate(_ context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	if req.PoolName == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "pool_name required")
	}

	ip := net.ParseIP(req.Ip)
	if ip == nil {
		return &pb.ValidateResponse{Valid: false, Available: false}, nil
	}

	available, err := s.manager.Validate(req.PoolName, ip)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "pool validation failed: %v", err)
	}

	return &pb.ValidateResponse{Valid: true, Available: available}, nil
}

// GetPool returns pool status and allocation info.
func (s *GRPCServer) GetPool(_ context.Context, req *pb.GetPoolRequest) (*pb.GetPoolResponse, error) {
	status, err := s.manager.GetPool(req.Name)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "pool not found: %v", err)
	}

	resp := &pb.GetPoolResponse{
		Name:      status.Name,
		Type:      string(status.Type),
		Allocated: int32(status.Allocated), //nolint:gosec // bounded by pool size
		Total:     int32(status.Total),     //nolint:gosec // bounded by pool size
		Available: int32(status.Available), //nolint:gosec // bounded by pool size
	}

	for _, a := range status.Allocations {
		resp.Allocations = append(resp.Allocations, &pb.IPAllocationInfo{
			Ip:            a.IP.String(),
			Owner:         a.Owner,
			Resource:      a.Resource,
			TimestampUnix: a.Timestamp.Unix(),
		})
	}

	return resp, nil
}

// ListIPPools lists all pools with optional type filter.
func (s *GRPCServer) ListIPPools(_ context.Context, req *pb.ListIPPoolsRequest) (*pb.ListIPPoolsResponse, error) {
	var filterType *PoolType
	if req.TypeFilter != "" {
		t := PoolType(req.TypeFilter)
		filterType = &t
	}

	pools := s.manager.ListPools(filterType)
	resp := &pb.ListIPPoolsResponse{}
	for _, p := range pools {
		resp.Pools = append(resp.Pools, &pb.PoolInfo{
			Name:      p.Name,
			Type:      string(p.Type),
			Allocated: int32(p.Allocated), //nolint:gosec // bounded by pool size
			Total:     int32(p.Total),     //nolint:gosec // bounded by pool size
			Available: int32(p.Available), //nolint:gosec // bounded by pool size
		})
	}

	return resp, nil
}

// ListIPAllocations lists allocations with filters.
func (s *GRPCServer) ListIPAllocations(_ context.Context, req *pb.ListIPAllocationsRequest) (*pb.ListIPAllocationsResponse, error) {
	var filterType *PoolType
	if req.TypeFilter != "" {
		t := PoolType(req.TypeFilter)
		filterType = &t
	}

	allocs := s.manager.ListAllocations(req.PoolFilter, req.OwnerFilter, filterType)
	resp := &pb.ListIPAllocationsResponse{}
	for _, a := range allocs {
		resp.Allocations = append(resp.Allocations, &pb.IPAllocationInfo{
			Ip:            a.IP.String(),
			Owner:         a.Owner,
			Resource:      a.Resource,
			TimestampUnix: a.Timestamp.Unix(),
		})
	}

	return resp, nil
}

// WatchPools is a server-streaming RPC for pool change events.
// This is a placeholder — real implementation would use an event channel
// from the manager notifying on pool changes.
func (s *GRPCServer) WatchPools(_ *pb.WatchPoolsRequest, stream pb.IPAMService_WatchPoolsServer) error {
	// Block until the client disconnects. Real implementation would
	// subscribe to manager events and send PoolEvent messages.
	s.logger.Info("WatchPools stream opened")
	<-stream.Context().Done()
	return fmt.Errorf("stream closed: %w", stream.Context().Err())
}
