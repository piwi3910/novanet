//go:build !linux

package grpcauth

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// TransportCredentials returns a no-op ServerOption on non-Linux platforms.
func TransportCredentials() grpc.ServerOption {
	return grpc.EmptyServerOption{}
}

// buildInterceptors returns pass-through interceptors on non-Linux platforms.
// A warning is logged since peer credential checking is not available.
func buildInterceptors(logger *zap.Logger, _ map[uint32]struct{}) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	logger.Warn("Unix peer credential authentication not available on this platform; allowing all connections")

	unary := func(
		ctx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		return handler(ctx, req)
	}

	stream := func(
		srv interface{},
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		return handler(srv, ss)
	}

	return unary, stream
}
