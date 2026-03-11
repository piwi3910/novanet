package ebpfservices

import (
	"context"
	"errors"
	"testing"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/dataplane"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

// mockResolver implements EndpointResolver for testing.
type mockResolver struct {
	endpoints map[string]string // key: "namespace/name", value: IP
}

func (m *mockResolver) LookupEndpoint(namespace, name string) (string, bool) {
	ip, ok := m.endpoints[namespace+"/"+name]
	return ip, ok
}

// mockDataplane implements dataplane.ClientInterface for testing.
type mockDataplane struct {
	sockmapStats     *dataplane.SockmapStats
	sockmapStatsErr  error
	meshEntries      []*dataplane.MeshServiceEntry
	meshEntriesErr   error
	rateLimitStats   *dataplane.RateLimitStats
	rateLimitErr     error
	healthStats      []*dataplane.BackendHealthInfo
	healthStatsErr   error
	upsertSockmapErr error
	deleteSockmapErr error
	lastSockmapIP    string
	lastSockmapPort  uint32
	upsertMeshErr    error
	deleteMeshErr    error
	updateRLErr      error
	lastMeshIP       string
	lastMeshPort     uint32
	lastMeshRedirect uint32
	lastRLRate       uint32
	lastRLBurst      uint32
	lastRLWindowNs   uint64
}

func (m *mockDataplane) Connect(_ context.Context) error                               { return nil }
func (m *mockDataplane) UpsertEndpoint(_ context.Context, _ *dataplane.Endpoint) error { return nil }
func (m *mockDataplane) DeleteEndpoint(_ context.Context, _ string) error              { return nil }
func (m *mockDataplane) UpsertPolicy(_ context.Context, _ *dataplane.PolicyRule) error { return nil }
func (m *mockDataplane) DeletePolicy(_ context.Context, _ *dataplane.PolicyRule) error { return nil }
func (m *mockDataplane) UpsertTunnel(_ context.Context, _ string, _, _ uint32) error   { return nil }
func (m *mockDataplane) DeleteTunnel(_ context.Context, _ string) error                { return nil }
func (m *mockDataplane) UpdateConfig(_ context.Context, _ map[uint32]uint64) error     { return nil }
func (m *mockDataplane) AttachProgram(_ context.Context, _ string, _ dataplane.AttachType) error {
	return nil
}
func (m *mockDataplane) DetachProgram(_ context.Context, _ string, _ dataplane.AttachType) error {
	return nil
}
func (m *mockDataplane) StreamFlows(_ context.Context, _ uint32) (<-chan *dataplane.FlowEvent, error) {
	return nil, nil
}
func (m *mockDataplane) GetStatus(_ context.Context) (*dataplane.Status, error) { return nil, nil }
func (m *mockDataplane) UpsertSockmapEndpoint(_ context.Context, ip string, port uint32) error {
	m.lastSockmapIP = ip
	m.lastSockmapPort = port
	return m.upsertSockmapErr
}
func (m *mockDataplane) DeleteSockmapEndpoint(_ context.Context, ip string, port uint32) error {
	m.lastSockmapIP = ip
	m.lastSockmapPort = port
	return m.deleteSockmapErr
}
func (m *mockDataplane) Close() error { return nil }

func (m *mockDataplane) SyncPolicies(_ context.Context, _ []*dataplane.PolicyRule) (*dataplane.SyncResult, error) {
	return &dataplane.SyncResult{}, nil
}

func (m *mockDataplane) GetSockmapStats(_ context.Context) (*dataplane.SockmapStats, error) {
	return m.sockmapStats, m.sockmapStatsErr
}

func (m *mockDataplane) UpsertMeshService(_ context.Context, ip string, port, redirectPort uint32) error {
	m.lastMeshIP = ip
	m.lastMeshPort = port
	m.lastMeshRedirect = redirectPort
	return m.upsertMeshErr
}

func (m *mockDataplane) DeleteMeshService(_ context.Context, ip string, port uint32) error {
	m.lastMeshIP = ip
	m.lastMeshPort = port
	return m.deleteMeshErr
}

func (m *mockDataplane) ListMeshServices(_ context.Context) ([]*dataplane.MeshServiceEntry, error) {
	return m.meshEntries, m.meshEntriesErr
}

func (m *mockDataplane) UpdateRateLimitConfig(_ context.Context, rate, burst uint32, windowNs uint64) error {
	m.lastRLRate = rate
	m.lastRLBurst = burst
	m.lastRLWindowNs = windowNs
	return m.updateRLErr
}

func (m *mockDataplane) GetRateLimitStats(_ context.Context) (*dataplane.RateLimitStats, error) {
	return m.rateLimitStats, m.rateLimitErr
}

func (m *mockDataplane) GetBackendHealthStats(_ context.Context, _ string, _ uint32) ([]*dataplane.BackendHealthInfo, error) {
	return m.healthStats, m.healthStatsErr
}

func (m *mockDataplane) UpsertBackends(_ context.Context, _ []*dataplane.Backend) error { return nil }
func (m *mockDataplane) UpsertServiceEntry(_ context.Context, _ *dataplane.ServiceConfig) error {
	return nil
}
func (m *mockDataplane) UpsertEgressPolicy(_ context.Context, _ *dataplane.EgressPolicy) error {
	return nil
}
func (m *mockDataplane) DeleteEgressPolicy(_ context.Context, _ uint32, _ string, _ uint32) error {
	return nil
}

// Verify the mock satisfies the interface at compile time.
var _ dataplane.ClientInterface = (*mockDataplane)(nil)

func TestNewServer(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestServerImplementsInterface(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	var _ pb.EBPFServicesServer = s
}

// --- Sockmap tests ---

func TestEnableSockmap_Success(t *testing.T) {
	mock := &mockDataplane{}
	resolver := &mockResolver{endpoints: map[string]string{
		"default/test-pod": "10.0.0.5",
	}}
	s := NewServer(testLogger(), mock, resolver)
	resp, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastSockmapIP != "10.0.0.5" {
		t.Errorf("expected sockmap IP 10.0.0.5, got %s", mock.lastSockmapIP)
	}
	if mock.lastSockmapPort != 0 {
		t.Errorf("expected sockmap port 0, got %d", mock.lastSockmapPort)
	}
}

func TestEnableSockmap_NotFound(t *testing.T) {
	resolver := &mockResolver{endpoints: map[string]string{}}
	s := NewServer(testLogger(), &mockDataplane{}, resolver)
	_, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodNamespace: "default",
		PodName:      "missing-pod",
	})
	assertGRPCCode(t, err, codes.NotFound)
}

func TestEnableSockmap_MissingNamespace(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodName: "test-pod",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestEnableSockmap_MissingPodName(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodNamespace: "default",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestEnableSockmap_NilResolver(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestEnableSockmap_NilDataplane(t *testing.T) {
	resolver := &mockResolver{endpoints: map[string]string{
		"default/test-pod": "10.0.0.5",
	}}
	s := NewServer(testLogger(), nil, resolver)
	_, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestEnableSockmap_DataplaneError(t *testing.T) {
	mock := &mockDataplane{upsertSockmapErr: errors.New("map full")}
	resolver := &mockResolver{endpoints: map[string]string{
		"default/test-pod": "10.0.0.5",
	}}
	s := NewServer(testLogger(), mock, resolver)
	_, err := s.EnableSockmap(context.Background(), &pb.EnableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	assertGRPCCode(t, err, codes.Internal)
}

func TestDisableSockmap_Success(t *testing.T) {
	mock := &mockDataplane{}
	resolver := &mockResolver{endpoints: map[string]string{
		"default/test-pod": "10.0.0.5",
	}}
	s := NewServer(testLogger(), mock, resolver)
	resp, err := s.DisableSockmap(context.Background(), &pb.DisableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastSockmapIP != "10.0.0.5" {
		t.Errorf("expected sockmap IP 10.0.0.5, got %s", mock.lastSockmapIP)
	}
	if mock.lastSockmapPort != 0 {
		t.Errorf("expected sockmap port 0, got %d", mock.lastSockmapPort)
	}
}

func TestDisableSockmap_NotFound(t *testing.T) {
	resolver := &mockResolver{endpoints: map[string]string{}}
	s := NewServer(testLogger(), &mockDataplane{}, resolver)
	_, err := s.DisableSockmap(context.Background(), &pb.DisableSockmapRequest{
		PodNamespace: "default",
		PodName:      "missing-pod",
	})
	assertGRPCCode(t, err, codes.NotFound)
}

func TestDisableSockmap_NilResolver(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.DisableSockmap(context.Background(), &pb.DisableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestDisableSockmap_NilDataplane(t *testing.T) {
	resolver := &mockResolver{endpoints: map[string]string{
		"default/test-pod": "10.0.0.5",
	}}
	s := NewServer(testLogger(), nil, resolver)
	_, err := s.DisableSockmap(context.Background(), &pb.DisableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestDisableSockmap_DataplaneError(t *testing.T) {
	mock := &mockDataplane{deleteSockmapErr: errors.New("map error")}
	resolver := &mockResolver{endpoints: map[string]string{
		"default/test-pod": "10.0.0.5",
	}}
	s := NewServer(testLogger(), mock, resolver)
	_, err := s.DisableSockmap(context.Background(), &pb.DisableSockmapRequest{
		PodNamespace: "default",
		PodName:      "test-pod",
	})
	assertGRPCCode(t, err, codes.Internal)
}

func TestGetSockmapStats_Success(t *testing.T) {
	mock := &mockDataplane{
		sockmapStats: &dataplane.SockmapStats{
			Redirected:      100,
			Fallback:        5,
			ActiveEndpoints: 10,
		},
	}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.GetSockmapStats(context.Background(), &pb.GetSockmapStatsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Redirected != 100 {
		t.Errorf("expected redirected=100, got %d", resp.Redirected)
	}
	if resp.Fallback != 5 {
		t.Errorf("expected fallback=5, got %d", resp.Fallback)
	}
	if resp.ActiveSockets != 10 {
		t.Errorf("expected active_sockets=10, got %d", resp.ActiveSockets)
	}
}

func TestGetSockmapStats_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.GetSockmapStats(context.Background(), &pb.GetSockmapStatsRequest{})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestGetSockmapStats_DataplaneError(t *testing.T) {
	mock := &mockDataplane{
		sockmapStatsErr: errors.New("map read failed"),
	}
	s := NewServer(testLogger(), mock, nil)
	_, err := s.GetSockmapStats(context.Background(), &pb.GetSockmapStatsRequest{})
	assertGRPCCode(t, err, codes.Internal)
}

// --- Mesh redirect tests ---

func TestAddMeshRedirect_Success(t *testing.T) {
	mock := &mockDataplane{}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:           "10.0.0.1",
		Port:         80,
		RedirectPort: 15001,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastMeshIP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", mock.lastMeshIP)
	}
	if mock.lastMeshPort != 80 {
		t.Errorf("expected port 80, got %d", mock.lastMeshPort)
	}
	if mock.lastMeshRedirect != 15001 {
		t.Errorf("expected redirect_port 15001, got %d", mock.lastMeshRedirect)
	}
}

func TestAddMeshRedirect_EmptyIP(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Port:         80,
		RedirectPort: 15001,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAddMeshRedirect_InvalidIP(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:           "not-an-ip",
		Port:         80,
		RedirectPort: 15001,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAddMeshRedirect_ZeroPort(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:           "10.0.0.1",
		RedirectPort: 15001,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAddMeshRedirect_ZeroRedirectPort(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:   "10.0.0.1",
		Port: 80,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestAddMeshRedirect_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:           "10.0.0.1",
		Port:         80,
		RedirectPort: 15001,
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestAddMeshRedirect_IPv6(t *testing.T) {
	mock := &mockDataplane{}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:           "fd00::1",
		Port:         443,
		RedirectPort: 15001,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastMeshIP != "fd00::1" {
		t.Errorf("expected IP fd00::1, got %s", mock.lastMeshIP)
	}
}

func TestAddMeshRedirect_DataplaneError(t *testing.T) {
	mock := &mockDataplane{upsertMeshErr: errors.New("map full")}
	s := NewServer(testLogger(), mock, nil)
	_, err := s.AddMeshRedirect(context.Background(), &pb.AddMeshRedirectRequest{
		Ip:           "10.0.0.1",
		Port:         80,
		RedirectPort: 15001,
	})
	assertGRPCCode(t, err, codes.Internal)
}

func TestRemoveMeshRedirect_Success(t *testing.T) {
	mock := &mockDataplane{}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.RemoveMeshRedirect(context.Background(), &pb.RemoveMeshRedirectRequest{
		Ip:   "10.0.0.1",
		Port: 80,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastMeshIP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", mock.lastMeshIP)
	}
}

func TestRemoveMeshRedirect_EmptyIP(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.RemoveMeshRedirect(context.Background(), &pb.RemoveMeshRedirectRequest{
		Port: 80,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestRemoveMeshRedirect_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.RemoveMeshRedirect(context.Background(), &pb.RemoveMeshRedirectRequest{
		Ip:   "10.0.0.1",
		Port: 80,
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestListMeshRedirects_Success(t *testing.T) {
	mock := &mockDataplane{
		meshEntries: []*dataplane.MeshServiceEntry{
			{IP: "10.0.0.1", Port: 80, RedirectPort: 15001},
			{IP: "10.0.0.2", Port: 443, RedirectPort: 15002},
		},
	}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.ListMeshRedirects(context.Background(), &pb.ListMeshRedirectsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}
	if resp.Entries[0].Ip != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", resp.Entries[0].Ip)
	}
	if resp.Entries[1].RedirectPort != 15002 {
		t.Errorf("expected redirect_port 15002, got %d", resp.Entries[1].RedirectPort)
	}
}

func TestListMeshRedirects_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.ListMeshRedirects(context.Background(), &pb.ListMeshRedirectsRequest{})
	assertGRPCCode(t, err, codes.Unavailable)
}

// --- Rate limit tests ---

func TestConfigureRateLimit_Success(t *testing.T) {
	mock := &mockDataplane{}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Cidr:  "10.0.0.0/8",
		Rate:  1000,
		Burst: 2000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastRLRate != 1000 {
		t.Errorf("expected rate 1000, got %d", mock.lastRLRate)
	}
	if mock.lastRLBurst != 2000 {
		t.Errorf("expected burst 2000, got %d", mock.lastRLBurst)
	}
	if mock.lastRLWindowNs != 1_000_000_000 {
		t.Errorf("expected windowNs 1000000000, got %d", mock.lastRLWindowNs)
	}
}

func TestConfigureRateLimit_EmptyCIDR(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Rate:  1000,
		Burst: 2000,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigureRateLimit_InvalidCIDR(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Cidr:  "not-a-cidr",
		Rate:  1000,
		Burst: 2000,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigureRateLimit_ZeroRate(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Cidr:  "10.0.0.0/8",
		Burst: 2000,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigureRateLimit_ZeroBurst(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Cidr: "10.0.0.0/8",
		Rate: 1000,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigureRateLimit_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Cidr:  "10.0.0.0/8",
		Rate:  1000,
		Burst: 2000,
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestConfigureRateLimit_IPv6(t *testing.T) {
	mock := &mockDataplane{}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.ConfigureRateLimit(context.Background(), &pb.ConfigureRateLimitRequest{
		Cidr:  "fd00::/64",
		Rate:  500,
		Burst: 1000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestRemoveRateLimit_Success(t *testing.T) {
	mock := &mockDataplane{}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.RemoveRateLimit(context.Background(), &pb.RemoveRateLimitRequest{
		Cidr: "10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if mock.lastRLRate != 0 {
		t.Errorf("expected rate 0, got %d", mock.lastRLRate)
	}
}

func TestRemoveRateLimit_EmptyCIDR(t *testing.T) {
	s := NewServer(testLogger(), &mockDataplane{}, nil)
	_, err := s.RemoveRateLimit(context.Background(), &pb.RemoveRateLimitRequest{})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestRemoveRateLimit_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.RemoveRateLimit(context.Background(), &pb.RemoveRateLimitRequest{
		Cidr: "10.0.0.0/8",
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestGetRateLimitStats_Success(t *testing.T) {
	mock := &mockDataplane{
		rateLimitStats: &dataplane.RateLimitStats{
			Allowed: 9000,
			Denied:  100,
		},
	}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.GetRateLimitStats(context.Background(), &pb.GetRateLimitStatsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed != 9000 {
		t.Errorf("expected allowed=9000, got %d", resp.Allowed)
	}
	if resp.Denied != 100 {
		t.Errorf("expected denied=100, got %d", resp.Denied)
	}
}

func TestGetRateLimitStats_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.GetRateLimitStats(context.Background(), &pb.GetRateLimitStatsRequest{})
	assertGRPCCode(t, err, codes.Unavailable)
}

// --- Health tests ---

func TestGetBackendHealth_Success(t *testing.T) {
	mock := &mockDataplane{
		healthStats: []*dataplane.BackendHealthInfo{
			{
				IP:           "10.0.0.5",
				Port:         8080,
				TotalConns:   1000,
				FailedConns:  10,
				TimeoutConns: 5,
				SuccessConns: 985,
				AvgRTTNs:     1500000,
				FailureRate:  0.01,
			},
		},
	}
	s := NewServer(testLogger(), mock, nil)
	resp, err := s.GetBackendHealth(context.Background(), &pb.GetBackendHealthRequest{
		Ip:   "10.0.0.5",
		Port: 8080,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(resp.Backends))
	}
	b := resp.Backends[0]
	if b.Ip != "10.0.0.5" {
		t.Errorf("expected IP 10.0.0.5, got %s", b.Ip)
	}
	if b.TotalConns != 1000 {
		t.Errorf("expected total_conns=1000, got %d", b.TotalConns)
	}
	if b.FailureRate != 0.01 {
		t.Errorf("expected failure_rate=0.01, got %f", b.FailureRate)
	}
}

func TestGetBackendHealth_NilDataplane(t *testing.T) {
	s := NewServer(testLogger(), nil, nil)
	_, err := s.GetBackendHealth(context.Background(), &pb.GetBackendHealthRequest{})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestGetBackendHealth_DataplaneError(t *testing.T) {
	mock := &mockDataplane{
		healthStatsErr: errors.New("map read failed"),
	}
	s := NewServer(testLogger(), mock, nil)
	_, err := s.GetBackendHealth(context.Background(), &pb.GetBackendHealthRequest{})
	assertGRPCCode(t, err, codes.Internal)
}

// --- helpers ---

func assertGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != want {
		t.Fatalf("expected code %v, got %v: %s", want, st.Code(), st.Message())
	}
}
