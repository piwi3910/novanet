//go:build linux

// Package cni implements the CNI plugin for setting up and tearing down
// pod network namespaces with veth pairs and point-to-point routing.
package cni

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// SetupPodNetwork creates a veth pair, moves one end into the pod's network
// namespace, configures IP addressing with point-to-point routing, and adds
// a host-side route for the pod IP.
// Returns the ifindex of the host-side veth.
func SetupPodNetwork(netnsPath, podIfName, hostVethName string, podIP, gateway net.IP, mac net.HardwareAddr, prefixLen int) (int, error) {
	// Generate a random locally-administered MAC for the host-side veth.
	// We set this explicitly so we have a known MAC to use in the pod's
	// ARP entry, avoiding issues with reading MAC across namespace boundaries.
	hostMAC, err := generateHostMAC()
	if err != nil {
		return 0, fmt.Errorf("generating host veth MAC: %w", err)
	}

	// Create the veth pair.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         hostVethName,
			HardwareAddr: hostMAC,
		},
		PeerName:         podIfName,
		PeerHardwareAddr: mac,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return 0, fmt.Errorf("creating veth pair: %w", err)
	}

	// Open the network namespace.
	// netnsPath is always a /proc/<pid>/ns/net or /var/run/netns/<name> path
	// provided by the container runtime, not user input.
	cleanPath := filepath.Clean(netnsPath)
	nsfd, err := os.Open(cleanPath) //#nosec G304 -- path is from container runtime, not user input
	if err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("opening netns %s: %w", netnsPath, err)
	}
	defer func() { _ = nsfd.Close() }()

	// Get the peer (pod side) interface and move it to the pod netns.
	peerLink, err := netlink.LinkByName(podIfName)
	if err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("finding peer veth %s: %w", podIfName, err)
	}

	if err := netlink.LinkSetNsFd(peerLink, int(nsfd.Fd())); err != nil { //#nosec G115 -- fd is a small positive int from os.Open
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("moving %s to netns: %w", podIfName, err)
	}

	// Bring up the host-side veth.
	hostLink, err := netlink.LinkByName(hostVethName)
	if err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("finding host veth %s: %w", hostVethName, err)
	}

	if err := netlink.LinkSetUp(hostLink); err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("bringing up host veth: %w", err)
	}

	// Enable proxy ARP on the host veth so it responds to ARP for the gateway.
	// These sysctl files require 0644 permissions to be readable by the kernel.
	proxyARPPath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName)
	if err := os.WriteFile(proxyARPPath, []byte("1"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to enable proxy_arp on %s: %v\n", hostVethName, err)
	}

	// Also disable rp_filter on the host veth to allow asymmetric routing.
	rpFilterPath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", hostVethName)
	if err := os.WriteFile(rpFilterPath, []byte("0"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to disable rp_filter on %s: %v\n", hostVethName, err)
	}

	// Configure the pod-side interface inside the namespace.
	// Use a namespace-aware netlink handle to avoid cross-namespace issues.
	podNS, err := netns.GetFromPath(netnsPath)
	if err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("getting netns handle for %s: %w", netnsPath, err)
	}
	defer func() { _ = podNS.Close() }()

	if err := configureInNetns(podNS, podIfName, podIP, gateway, hostMAC); err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("configuring pod interface: %w", err)
	}

	// Add a /32 host route for the pod IP pointing to the host-side veth.
	podRoute := &netlink.Route{
		Dst: &net.IPNet{
			IP:   podIP,
			Mask: net.CIDRMask(32, 32),
		},
		LinkIndex: hostLink.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(podRoute); err != nil {
		_ = netlink.LinkDel(veth)
		return 0, fmt.Errorf("adding host route for pod %s: %w", podIP, err)
	}

	return hostLink.Attrs().Index, nil
}

// configureInNetns configures the pod interface using a namespace-aware
// netlink handle. This avoids the issues with thread-local namespace
// switching and the package-level netlink handle.
func configureInNetns(podNS netns.NsHandle, ifName string, podIP, gateway net.IP, hostMAC net.HardwareAddr) error {
	// Create a netlink handle that operates in the pod's namespace.
	nlh, err := netlink.NewHandleAt(podNS)
	if err != nil {
		return fmt.Errorf("creating netlink handle in pod netns: %w", err)
	}
	defer nlh.Close()

	// Find the interface in the pod namespace.
	link, err := nlh.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("finding interface %s in netns: %w", ifName, err)
	}

	// Add the IP address with /32 mask. This forces ALL traffic through the
	// default route, preventing the pod from trying to ARP directly for
	// same-subnet IPs (which would fail since other pods' veths are in
	// separate network namespaces).
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   podIP,
			Mask: net.CIDRMask(32, 32),
		},
	}
	if err := nlh.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("adding address to %s: %w", ifName, err)
	}

	// Bring up the interface.
	if err := nlh.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up %s: %w", ifName, err)
	}

	// Bring up loopback.
	lo, err := nlh.LinkByName("lo")
	if err == nil {
		if loErr := nlh.LinkSetUp(lo); loErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to bring up loopback: %v\n", loErr)
		}
	}

	// Add a neighbor (ARP) entry for the gateway pointing to the host veth's MAC.
	// This ensures the pod can resolve the gateway without a real gateway interface.
	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           gateway,
		HardwareAddr: hostMAC,
	}
	if err := nlh.NeighAdd(neigh); err != nil {
		return fmt.Errorf("adding neighbor entry for gateway: %w", err)
	}

	// Add a link-scope route for the gateway so the kernel considers it
	// reachable on the veth link (required since pod IP has /32 mask).
	gwRoute := &netlink.Route{
		Dst: &net.IPNet{
			IP:   gateway,
			Mask: net.CIDRMask(32, 32),
		},
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := nlh.RouteAdd(gwRoute); err != nil {
		return fmt.Errorf("adding gateway link route: %w", err)
	}

	// Add default route via the gateway.
	route := &netlink.Route{
		Dst: nil, // Default route.
		Gw:  gateway,
	}
	if err := nlh.RouteAdd(route); err != nil {
		return fmt.Errorf("adding default route: %w", err)
	}

	return nil
}

// CleanupPodNetwork removes the host-side veth (which also removes the pod side)
// and removes the host route for the pod IP.
func CleanupPodNetwork(hostVethName string, podIP net.IP) {
	// Remove the host route.
	if podIP != nil {
		route := &netlink.Route{
			Dst: &net.IPNet{
				IP:   podIP,
				Mask: net.CIDRMask(32, 32),
			},
		}
		if err := netlink.RouteDel(route); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to delete pod route for %s: %v\n", podIP, err)
		}
	}

	// Remove the veth pair.
	link, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return
	}
	if err := netlink.LinkDel(link); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to delete veth %s: %v\n", hostVethName, err)
	}
}

// generateHostMAC generates a random MAC address with the locally-administered
// bit set, for use on the host side of the veth pair.
func generateHostMAC() (net.HardwareAddr, error) {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	// Set locally administered and unicast bits.
	mac[0] = (mac[0] | 0x02) & 0xfe
	return net.HardwareAddr(mac), nil
}
