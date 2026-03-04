//go:build linux

package tunnel

import (
	"github.com/vishvananda/netlink"
)

// destroyTunnel removes a tunnel interface on Linux.
func destroyTunnel(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	_ = netlink.LinkDel(link)
}
