//go:build linux

package grpcauth

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// TestAuthenticatedServer_AllowsCurrentUID verifies that a server configured
// to allow the current process UID accepts connections from this process.
func TestAuthenticatedServer_AllowsCurrentUID(t *testing.T) {
	logger := zaptest.NewLogger(t)
	uid := uint32(os.Getuid()) //nolint:gosec // UID is always non-negative

	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")

	srv := NewAuthenticatedServer(logger, []uint32{uid})
	healthpb.RegisterHealthServer(srv, health.NewServer())

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("close: %v", closeErr)
		}
	}()

	client := healthpb.NewHealthClient(conn)
	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("unexpected health status: %v", resp.Status)
	}
}

// TestAuthenticatedServer_RejectsWrongUID verifies that a server configured
// to allow only UID 99999 rejects connections from the current process.
func TestAuthenticatedServer_RejectsWrongUID(t *testing.T) {
	logger := zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel))

	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")

	// Allow only a UID that is definitely not the current user.
	srv := NewAuthenticatedServer(logger, []uint32{99999})
	healthpb.RegisterHealthServer(srv, health.NewServer())

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("close: %v", closeErr)
		}
	}()

	client := healthpb.NewHealthClient(conn)
	_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err == nil {
		t.Fatal("expected error for unauthorized UID")
	}
	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if s.Code() != codes.PermissionDenied && s.Code() != codes.Unauthenticated {
		t.Fatalf("expected PermissionDenied or Unauthenticated, got %v", s.Code())
	}
}

// TestCheckPeer_NoPeerInfo verifies rejection when no peer info is in context.
func TestCheckPeer_NoPeerInfo(t *testing.T) {
	allowed := map[uint32]struct{}{0: {}}
	_, err := checkPeer(context.Background(), allowed)
	if err == nil {
		t.Fatal("expected error for missing peer info")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

// TestCheckPeer_NilAuthInfo verifies rejection when peer has no AuthInfo.
func TestCheckPeer_NilAuthInfo(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	allowed := map[uint32]struct{}{0: {}}
	_, err := checkPeer(ctx, allowed)
	if err == nil {
		t.Fatal("expected error for nil AuthInfo")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

// TestCheckPeer_AllowedUID verifies acceptance when UID matches.
func TestCheckPeer_AllowedUID(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: &unixCreds{uid: 0, gid: 0, pid: 1},
	})
	allowed := map[uint32]struct{}{0: {}}
	uid, err := checkPeer(ctx, allowed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != 0 {
		t.Fatalf("expected UID 0, got %d", uid)
	}
}

// TestCheckPeer_DeniedUID verifies rejection when UID is not allowed.
func TestCheckPeer_DeniedUID(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: &unixCreds{uid: 1000, gid: 1000, pid: 42},
	})
	allowed := map[uint32]struct{}{0: {}}
	_, err := checkPeer(ctx, allowed)
	if err == nil {
		t.Fatal("expected error for denied UID")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestPeerCredFromConn verifies SO_PEERCRED extraction on a real Unix socket pair.
func TestPeerCredFromConn(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "cred.sock")

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if closeErr := lis.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	}()

	done := make(chan *unixCreds, 1)
	go func() {
		conn, acceptErr := lis.Accept()
		if acceptErr != nil {
			t.Errorf("accept: %v", acceptErr)
			done <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		uc, credErr := peerCredFromConn(conn)
		if credErr != nil {
			t.Errorf("peerCredFromConn: %v", credErr)
			done <- nil
			return
		}
		done <- uc
	}()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	uc := <-done
	if uc == nil {
		t.Fatal("failed to get peer credentials")
	}
	if uc.uid != uint32(os.Getuid()) { //nolint:gosec // UID is always non-negative
		t.Fatalf("expected UID %d, got %d", os.Getuid(), uc.uid)
	}
}
