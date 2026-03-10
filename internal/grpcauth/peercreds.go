// Package grpcauth provides gRPC interceptors that authenticate Unix socket
// connections by checking SO_PEERCRED peer credentials.
package grpcauth

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// uidKey is the context key used to store the authenticated peer UID.
type uidKey struct{}

// PeerUID extracts the authenticated peer UID from the context, if present.
func PeerUID(ctx context.Context) (uint32, bool) {
	v, ok := ctx.Value(uidKey{}).(uint32)
	return v, ok
}

// NewAuthenticatedServer creates a gRPC server with Unix peer credential
// interceptors that restrict connections to the given set of allowed UIDs.
// On non-Linux platforms the interceptors log a warning and allow all
// connections (graceful degradation).
func NewAuthenticatedServer(logger *zap.Logger, allowedUIDs []uint32, opts ...grpc.ServerOption) *grpc.Server {
	uidSet := make(map[uint32]struct{}, len(allowedUIDs))
	for _, uid := range allowedUIDs {
		uidSet[uid] = struct{}{}
	}

	unary, stream := buildInterceptors(logger, uidSet)

	// Apply caller opts first, then auth interceptors last so they cannot
	// be overridden by a stray grpc.UnaryInterceptor in opts.
	combined := make([]grpc.ServerOption, 0, len(opts)+3)
	combined = append(combined, opts...)
	combined = append(combined, TransportCredentials())
	combined = append(combined, grpc.UnaryInterceptor(unary), grpc.StreamInterceptor(stream))

	return grpc.NewServer(combined...)
}
