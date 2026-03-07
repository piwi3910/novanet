package service

import (
	"context"
	"sync"
	"testing"

	pb "github.com/azrtydxb/novanet/api/v1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// mockDPClient implements DataplaneServiceClient for testing.
type mockDPClient struct {
	mu       sync.Mutex
	services []*pb.UpsertServiceRequest
	backends []*pb.UpsertBackendsRequest
	deletes  []*pb.DeleteServiceRequest
	maglev   []*pb.UpsertMaglevTableRequest
}

func (m *mockDPClient) UpsertService(_ context.Context, req *pb.UpsertServiceRequest) (*pb.UpsertServiceResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services = append(m.services, req)
	return &pb.UpsertServiceResponse{}, nil
}

func (m *mockDPClient) DeleteService(_ context.Context, req *pb.DeleteServiceRequest) (*pb.DeleteServiceResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes = append(m.deletes, req)
	return &pb.DeleteServiceResponse{}, nil
}

func (m *mockDPClient) UpsertBackends(_ context.Context, req *pb.UpsertBackendsRequest) (*pb.UpsertBackendsResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backends = append(m.backends, req)
	return &pb.UpsertBackendsResponse{}, nil
}

func (m *mockDPClient) UpsertMaglevTable(_ context.Context, req *pb.UpsertMaglevTableRequest) (*pb.UpsertMaglevTableResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maglev = append(m.maglev, req)
	return &pb.UpsertMaglevTableResponse{}, nil
}

func TestIPToU32(t *testing.T) {
	tests := []struct {
		ip   string
		want uint32
	}{
		{"10.43.0.1", 0x0A2B0001},
		{"192.168.1.1", 0xC0A80101},
		{"0.0.0.0", 0},
		{"invalid", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := ipToU32(tt.ip)
		if got != tt.want {
			t.Errorf("ipToU32(%q) = 0x%X, want 0x%X", tt.ip, got, tt.want)
		}
	}
}

func TestProtocolToNumber(t *testing.T) {
	if protocolToNumber(corev1.ProtocolTCP) != 6 {
		t.Error("TCP should be 6")
	}
	if protocolToNumber(corev1.ProtocolUDP) != 17 {
		t.Error("UDP should be 17")
	}
	if protocolToNumber(corev1.ProtocolSCTP) != 132 {
		t.Error("SCTP should be 132")
	}
}

func TestComputeScopes(t *testing.T) {
	logger := zap.NewNop()
	w := &Watcher{logger: logger}

	// ClusterIP service.
	svc := &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP}}
	scopes := w.computeScopes(svc)
	if len(scopes) != 1 || scopes[0] != scopeClusterIP {
		t.Errorf("ClusterIP scopes = %v, want [0]", scopes)
	}

	// NodePort service.
	svc.Spec.Type = corev1.ServiceTypeNodePort
	scopes = w.computeScopes(svc)
	if len(scopes) != 2 {
		t.Errorf("NodePort scopes = %v, want [0, 1]", scopes)
	}

	// LoadBalancer service.
	svc.Spec.Type = corev1.ServiceTypeLoadBalancer
	scopes = w.computeScopes(svc)
	if len(scopes) != 3 {
		t.Errorf("LoadBalancer scopes = %v, want [0, 1, 3]", scopes)
	}

	// With ExternalIPs.
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	svc.Spec.ExternalIPs = []string{"1.2.3.4"}
	scopes = w.computeScopes(svc)
	if len(scopes) != 2 {
		t.Errorf("ClusterIP+ExternalIP scopes = %v, want [0, 2]", scopes)
	}
}

func TestComputeFlags(t *testing.T) {
	logger := zap.NewNop()
	w := &Watcher{logger: logger}

	svc := &corev1.Service{Spec: corev1.ServiceSpec{}}
	if w.computeFlags(svc) != 0 {
		t.Error("expected no flags")
	}

	svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
	if w.computeFlags(svc) != 0x01 {
		t.Error("expected affinity flag")
	}

	svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	if w.computeFlags(svc) != 0x03 {
		t.Error("expected affinity + ext local flags")
	}
}

func TestReconcileServiceDirect(t *testing.T) {
	mock := &mockDPClient{}
	logger := zap.NewNop()
	allocator := NewSlotAllocator(1000)

	w := &Watcher{
		dpClient:        mock,
		allocator:       allocator,
		defaultAlg:      "random",
		logger:          logger,
		maglevAllocator: NewSlotAllocator(1048576),
		services:        make(map[string]*serviceState),
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.43.0.100",
			Ports: []corev1.ServicePort{
				{
					Port:       80,
					TargetPort: intstr.FromInt32(8080),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Reconcile with no backends — should result in no service entries.
	w.reconcileService(svc)

	if len(mock.services) != 0 {
		t.Errorf("expected 0 service upserts with no backends, got %d", len(mock.services))
	}

	if _, exists := w.services["default/test-svc"]; exists {
		t.Error("service should not be tracked with 0 backends")
	}
}

func TestResolveAlgorithm(t *testing.T) {
	w := &Watcher{defaultAlg: "random"}
	if w.resolveAlgorithm() != algRandom {
		t.Error("expected random")
	}

	w.defaultAlg = "round-robin"
	if w.resolveAlgorithm() != algRoundRobin {
		t.Error("expected round-robin")
	}

	w.defaultAlg = "maglev"
	if w.resolveAlgorithm() != algMaglev {
		t.Error("expected maglev")
	}

	w.defaultAlg = "unknown"
	if w.resolveAlgorithm() != algRandom {
		t.Error("expected random for unknown")
	}
}
