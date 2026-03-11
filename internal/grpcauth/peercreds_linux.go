//go:build linux

package grpcauth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	// errNotUnixConn is returned when a connection is not a Unix socket.
	errNotUnixConn = errors.New("not a unix connection")
	// errFDOverflow is returned when a file descriptor value overflows int.
	errFDOverflow = errors.New("file descriptor overflows int")
)

// unixCreds stores the peer credentials obtained via SO_PEERCRED.
type unixCreds struct {
	uid uint32
	gid uint32
	pid int32
}

func (u *unixCreds) AuthType() string { return "unix-peercred" }

// extractUID pulls the UID from the peer info's AuthInfo.
func extractUID(p *peer.Peer) (uint32, bool) {
	if p.AuthInfo == nil {
		return 0, false
	}
	if uc, ok := p.AuthInfo.(*unixCreds); ok {
		return uc.uid, true
	}
	return 0, false
}

// peerCredFromConn extracts peer credentials from a Unix socket connection
// using the SO_PEERCRED socket option.
func peerCredFromConn(conn net.Conn) (*unixCreds, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errNotUnixConn
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("getting syscall conn: %w", err)
	}

	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			credErr = errFDOverflow
			return
		}
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // overflow checked above
	})
	if err != nil {
		return nil, fmt.Errorf("raw control: %w", err)
	}
	if credErr != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED: %w", credErr)
	}

	return &unixCreds{uid: cred.Uid, gid: cred.Gid, pid: cred.Pid}, nil
}

// peerCredTransportCreds implements credentials.TransportCredentials.
// It performs the SO_PEERCRED lookup during the server handshake and stores the
// result in AuthInfo so interceptors can access it.
type peerCredTransportCreds struct{}

func (peerCredTransportCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, nil, nil
}

func (peerCredTransportCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, err := peerCredFromConn(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("SO_PEERCRED handshake failed: %w", err)
	}
	return conn, uc, nil
}

func (peerCredTransportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peercred"}
}

func (peerCredTransportCreds) Clone() credentials.TransportCredentials {
	return peerCredTransportCreds{}
}

func (peerCredTransportCreds) OverrideServerName(_ string) error { return nil }

// TransportCredentials returns a grpc.ServerOption that attaches Unix peer
// credentials to every inbound connection via SO_PEERCRED.
func TransportCredentials() grpc.ServerOption {
	return grpc.Creds(peerCredTransportCreds{})
}

// checkPeer validates the peer UID from a Unix socket connection against the
// allowed set. It returns the UID on success.
func checkPeer(ctx context.Context, allowedUIDs map[uint32]struct{}) (uint32, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "no peer info in context")
	}

	uid, ok := extractUID(p)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "unable to extract peer credentials")
	}

	if _, allowed := allowedUIDs[uid]; !allowed {
		return 0, status.Error(codes.PermissionDenied,
			fmt.Sprintf("peer UID %d is not in the allowed set", uid))
	}

	return uid, nil
}

// buildInterceptors returns the unary and stream interceptors for Linux.
func buildInterceptors(logger *zap.Logger, allowedUIDs map[uint32]struct{}) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	logger.Info("Unix peer credential authentication enabled",
		zap.Int("allowed_uids", len(allowedUIDs)))

	unary := func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		uid, err := checkPeer(ctx, allowedUIDs)
		if err != nil {
			logger.Warn("gRPC auth rejected",
				zap.String("method", info.FullMethod),
				zap.Error(err))
			return nil, err
		}
		ctx = context.WithValue(ctx, uidKey{}, uid)
		return handler(ctx, req)
	}

	stream := func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		uid, err := checkPeer(ss.Context(), allowedUIDs)
		if err != nil {
			logger.Warn("gRPC auth rejected (stream)",
				zap.String("method", info.FullMethod),
				zap.Error(err))
			return err
		}
		wrapped := &uidStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), uidKey{}, uid)}
		return handler(srv, wrapped)
	}

	return unary, stream
}

// uidStream wraps a grpc.ServerStream to override Context().
type uidStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *uidStream) Context() context.Context { return s.ctx }
