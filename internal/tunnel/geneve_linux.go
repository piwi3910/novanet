//go:build linux

package tunnel

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// createGeneveTunnel creates a single collect-metadata (FlowBased) Geneve
// tunnel interface. The eBPF dataplane uses bpf_skb_set_tunnel_key to set
// the remote IP, VNI, and TTL per-packet before redirecting to this interface.
// This is the same approach used by Cilium and Calico.
// If the interface already exists, its ifindex is returned without recreating.
func createGeneveTunnel(name string, vni uint32, localIP net.IP) (int, error) {
	// Return existing interface if already created.
	if existing, err := netlink.LinkByName(name); err == nil {
		return existing.Attrs().Index, nil
	}

	geneve := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         name,
			HardwareAddr: IPToTunnelMAC(localIP),
		},
		ID:        vni,
		FlowBased: true, // Collect-metadata mode — no static Remote.
		Dport:     6081, // Standard Geneve port.
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
