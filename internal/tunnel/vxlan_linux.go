//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// createVxlanTunnel creates or returns the single shared VXLAN interface.
// Unlike Geneve (one interface per remote), Linux only allows one VXLAN device
// per VNI. All remote nodes share this interface and are distinguished via FDB
// and neighbor entries.
// If the interface already exists, its ifindex is returned without recreating it.
func createVxlanTunnel(name string, vni uint32, localIP net.IP) (int, error) {
	// Return existing interface if already created.
	if existing, err := netlink.LinkByName(name); err == nil {
		return existing.Attrs().Index, nil
	}

	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         name,
			HardwareAddr: IPToTunnelMAC(localIP),
		},
		VxlanId:  int(vni),
		Port:     4789,  // Standard VXLAN port.
		Learning: false, // We manage FDB entries ourselves.
	}

	if err := netlink.LinkAdd(vxlan); err != nil {
		return 0, fmt.Errorf("creating vxlan interface %s: %w", name, err)
	}

	if err := netlink.LinkSetUp(vxlan); err != nil {
		_ = netlink.LinkDel(vxlan)
		return 0, fmt.Errorf("bringing up vxlan interface %s: %w", name, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("looking up vxlan interface %s: %w", name, err)
	}

	return link.Attrs().Index, nil
}

// addVxlanFDB adds a bridge FDB entry mapping a remote node's tunnel MAC to
// its physical IP address. This tells the VXLAN driver where to send
// encapsulated packets for a given inner destination MAC.
func addVxlanFDB(ifName string, remoteMAC net.HardwareAddr, remoteNodeIP net.IP) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", ifName, err)
	}

	fdb := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: remoteMAC,
		IP:           remoteNodeIP,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
	}
	if err := netlink.NeighSet(fdb); err != nil {
		return fmt.Errorf("adding FDB entry on %s: %w", ifName, err)
	}
	return nil
}

// removeVxlanFDB removes a bridge FDB entry for a remote node.
func removeVxlanFDB(ifName string, remoteMAC net.HardwareAddr, remoteNodeIP net.IP) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", ifName, err)
	}

	fdb := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: remoteMAC,
		IP:           remoteNodeIP,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
	}
	if err := netlink.NeighDel(fdb); err != nil {
		return fmt.Errorf("removing FDB entry on %s: %w", ifName, err)
	}
	return nil
}
