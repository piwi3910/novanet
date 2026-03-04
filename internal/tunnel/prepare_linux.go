//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/vishvananda/netlink"
)

// PrepareOverlay cleans up stale tunnel interfaces and reloads the kernel
// module for the given protocol. This works around a kernel bug where
// the geneve module's internal hash table gets corrupted after repeated
// interface create/delete cycles, causing decapsulated inner packets to
// not be delivered to the IP stack.
//
// Must be called once at agent startup, before creating any tunnels.
func PrepareOverlay(protocol string) error {
	moduleName := protocol // "geneve" or "vxlan"

	// Delete all existing interfaces for this tunnel type.
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}

	for _, link := range links {
		switch protocol {
		case protocolGeneve:
			if _, ok := link.(*netlink.Geneve); ok {
				_ = netlink.LinkDel(link)
			}
		case protocolVxlan:
			if _, ok := link.(*netlink.Vxlan); ok {
				_ = netlink.LinkDel(link)
			}
		}
	}

	// Reload the kernel module to clear internal state.
	// Ignore errors — the module might not be loaded or might be builtin.
	ctx := context.Background()
	_ = exec.CommandContext(ctx, "modprobe", "-r", moduleName).Run() //#nosec G204 -- moduleName is "geneve" or "vxlan"
	_ = exec.CommandContext(ctx, "modprobe", moduleName).Run()       //#nosec G204 -- moduleName is "geneve" or "vxlan"

	return nil
}
