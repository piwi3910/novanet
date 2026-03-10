package grpcauth

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestPeerUID_NotSet(t *testing.T) {
	_, ok := PeerUID(context.Background())
	if ok {
		t.Fatal("expected PeerUID to return false for empty context")
	}
}

func TestPeerUID_Set(t *testing.T) {
	ctx := context.WithValue(context.Background(), uidKey{}, uint32(1000))
	uid, ok := PeerUID(ctx)
	if !ok {
		t.Fatal("expected PeerUID to return true")
	}
	if uid != 1000 {
		t.Fatalf("expected UID 1000, got %d", uid)
	}
}

// TestNewAuthenticatedServer_Serves verifies that the server can be created
// and serves RPCs (on non-Linux the interceptors are pass-through).
func TestNewAuthenticatedServer_Serves(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sockPath := shortSocketPath(t)

	srv := NewAuthenticatedServer(logger, []uint32{0})
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

// shortSocketPath returns a Unix socket path short enough for all platforms.
// macOS has a 104-byte limit on socket paths, so t.TempDir() paths may be
// too long. On macOS we use /tmp; on Linux t.TempDir() is fine.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		dir, err := os.MkdirTemp("/tmp", "ga-")
		if err != nil {
			t.Fatalf("mktempdir: %v", err)
		}
		t.Cleanup(func() {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				t.Logf("cleanup: %v", rmErr)
			}
		})
		return filepath.Join(dir, "t.sock")
	}
	return filepath.Join(t.TempDir(), "t.sock")
}
