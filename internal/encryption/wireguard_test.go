package encryption

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerInfo(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	peer := PeerInfo{
		PublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==",
		Endpoint: net.UDPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 51820,
		},
		AllowedIPs: []net.IPNet{*cidr},
	}

	assert.Equal(t, "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==", peer.PublicKey)
	assert.Equal(t, "192.168.1.1:51820", peer.Endpoint.String())
	assert.Len(t, peer.AllowedIPs, 1)
	assert.Equal(t, "10.0.0.0/24", peer.AllowedIPs[0].String())
}

func TestPeerInfoMultipleAllowedIPs(t *testing.T) {
	_, cidr1, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	_, cidr2, err := net.ParseCIDR("10.0.1.0/24")
	require.NoError(t, err)

	_, cidr3, err := net.ParseCIDR("fd00::/64")
	require.NoError(t, err)

	peer := PeerInfo{
		PublicKey: "dGVzdC1rZXk=",
		Endpoint: net.UDPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 51820,
		},
		AllowedIPs: []net.IPNet{*cidr1, *cidr2, *cidr3},
	}

	assert.Len(t, peer.AllowedIPs, 3)
	assert.Equal(t, "10.0.0.0/24", peer.AllowedIPs[0].String())
	assert.Equal(t, "10.0.1.0/24", peer.AllowedIPs[1].String())
	assert.Equal(t, "fd00::/64", peer.AllowedIPs[2].String())
}

func TestErrNotSupported(t *testing.T) {
	assert.EqualError(t, ErrNotSupported, "wireguard: not supported on this platform")
}

func TestNewWireGuardManagerUnsupported(t *testing.T) {
	// On non-Linux platforms, NewWireGuardManager should return ErrNotSupported.
	// On Linux (CI), this test is skipped since NewWireGuardManager requires root.
	if isLinux() {
		t.Skip("skipping on Linux: NewWireGuardManager requires root and WireGuard tools")
	}

	_, err := NewWireGuardManager(net.ParseIP("10.0.0.1"), 51820, nil)
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestWireGuardManagerStubMethods(t *testing.T) {
	if isLinux() {
		t.Skip("skipping on Linux: stub methods not available")
	}

	m := &WireGuardManager{}
	assert.Equal(t, "", m.PublicKey())
	assert.ErrorIs(t, m.AddPeer("key", net.UDPAddr{}, nil), ErrNotSupported)
	assert.ErrorIs(t, m.RemovePeer("key"), ErrNotSupported)
	assert.Nil(t, m.ListPeers())
	assert.NoError(t, m.Close())
}
