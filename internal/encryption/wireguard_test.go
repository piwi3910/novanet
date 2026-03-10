package encryption

import (
	"errors"
	"net"
	"testing"
)

func TestPeerInfo(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	peer := PeerInfo{
		PublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==",
		Endpoint: net.UDPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 51820,
		},
		AllowedIPs: []net.IPNet{*cidr},
	}

	if peer.PublicKey != "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==" {
		t.Errorf("PublicKey = %q, want %q", peer.PublicKey, "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==")
	}
	if got := peer.Endpoint.String(); got != "192.168.1.1:51820" {
		t.Errorf("Endpoint = %q, want %q", got, "192.168.1.1:51820")
	}
	if len(peer.AllowedIPs) != 1 {
		t.Fatalf("AllowedIPs length = %d, want 1", len(peer.AllowedIPs))
	}
	if got := peer.AllowedIPs[0].String(); got != "10.0.0.0/24" {
		t.Errorf("AllowedIPs[0] = %q, want %q", got, "10.0.0.0/24")
	}
}

func TestPeerInfoMultipleAllowedIPs(t *testing.T) {
	_, cidr1, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR cidr1: %v", err)
	}

	_, cidr2, err := net.ParseCIDR("10.0.1.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR cidr2: %v", err)
	}

	_, cidr3, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR cidr3: %v", err)
	}

	peer := PeerInfo{
		PublicKey: "dGVzdC1rZXk=",
		Endpoint: net.UDPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 51820,
		},
		AllowedIPs: []net.IPNet{*cidr1, *cidr2, *cidr3},
	}

	if len(peer.AllowedIPs) != 3 {
		t.Fatalf("AllowedIPs length = %d, want 3", len(peer.AllowedIPs))
	}
	expected := []string{"10.0.0.0/24", "10.0.1.0/24", "fd00::/64"}
	for i, want := range expected {
		if got := peer.AllowedIPs[i].String(); got != want {
			t.Errorf("AllowedIPs[%d] = %q, want %q", i, got, want)
		}
	}
}

func TestErrNotSupported(t *testing.T) {
	want := "wireguard: not supported on this platform"
	if got := ErrNotSupported.Error(); got != want {
		t.Errorf("ErrNotSupported = %q, want %q", got, want)
	}
}

func TestNewWireGuardManagerUnsupported(t *testing.T) {
	// On non-Linux platforms, NewWireGuardManager should return ErrNotSupported.
	// On Linux (CI), this test is skipped since NewWireGuardManager requires root.
	if isLinux() {
		t.Skip("skipping on Linux: NewWireGuardManager requires root and WireGuard tools")
	}

	_, err := NewWireGuardManager(net.ParseIP("10.0.0.1"), 51820, nil)
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
}

func TestWireGuardManagerStubMethods(t *testing.T) {
	if isLinux() {
		t.Skip("skipping on Linux: stub methods not available")
	}

	m := &WireGuardManager{}
	if got := m.PublicKey(); got != "" {
		t.Errorf("PublicKey() = %q, want empty", got)
	}
	if err := m.AddPeer("key", net.UDPAddr{}, nil); !errors.Is(err, ErrNotSupported) {
		t.Errorf("AddPeer: expected ErrNotSupported, got %v", err)
	}
	if err := m.RemovePeer("key"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("RemovePeer: expected ErrNotSupported, got %v", err)
	}
	if peers := m.ListPeers(); peers != nil {
		t.Errorf("ListPeers() = %v, want nil", peers)
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close: unexpected error: %v", err)
	}
}
