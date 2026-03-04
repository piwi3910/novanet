//go:build linux

package tunnel

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// ErrInvalidRemoteIP indicates the remote IP string could not be parsed.
var ErrInvalidRemoteIP = errors.New("invalid remote IP")

// createGeneveTunnel creates a Geneve tunnel interface on Linux.
// The interface is assigned a MAC derived from localIP so that decapsulated
// inner packets (whose destination MAC is set by the sending node's neighbor
// entry) are classified as PACKET_HOST by the kernel.
func createGeneveTunnel(name, remoteIP string, vni uint32, localIP net.IP) (int, error) {
	remote := net.ParseIP(remoteIP)
	if remote == nil {
		return 0, fmt.Errorf("%w: %s", ErrInvalidRemoteIP, remoteIP)
	}

	geneve := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         name,
			HardwareAddr: IPToTunnelMAC(localIP),
		},
		ID:     vni,
		Remote: remote,
		Dport:  6081, // Standard Geneve port.
	}

	// Delete any stale interface from a previous run.
	if existing, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(geneve); err != nil {
		return 0, fmt.Errorf("creating geneve interface %s: %w", name, err)
	}

	if err := netlink.LinkSetUp(geneve); err != nil {
		_ = netlink.LinkDel(geneve)
		return 0, fmt.Errorf("bringing up geneve interface %s: %w", name, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("looking up geneve interface %s: %w", name, err)
	}

	return link.Attrs().Index, nil
}
