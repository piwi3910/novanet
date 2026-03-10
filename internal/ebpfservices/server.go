// Package ebpfservices implements the EBPFServices gRPC server for managing
// kernel-level eBPF operations including sockmap acceleration, mesh traffic
// redirection, rate limiting, and backend health monitoring.
package ebpfservices

import (
	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/dataplane"
	"go.uber.org/zap"
)

// EndpointResolver looks up pod IPs from the agent's endpoint store.
type EndpointResolver interface {
	// LookupEndpoint returns the pod IP for the given namespace/name.
	// Returns empty string and false if the endpoint is not found.
	LookupEndpoint(namespace, name string) (ip string, found bool)
}

// Server implements the EBPFServices gRPC service.
type Server struct {
	pb.UnimplementedEBPFServicesServer
	logger    *zap.Logger
	dataplane dataplane.ClientInterface
	resolver  EndpointResolver
}

// NewServer creates a new EBPFServices server.
// The dataplane client may be nil if the dataplane is not connected;
// RPCs that require it will return codes.Unavailable.
// The resolver may be nil; RPCs that require endpoint lookup will return
// codes.Unavailable.
func NewServer(logger *zap.Logger, dp dataplane.ClientInterface, resolver EndpointResolver) *Server {
	return &Server{logger: logger, dataplane: dp, resolver: resolver}
}
