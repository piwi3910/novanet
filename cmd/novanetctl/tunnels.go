package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newTunnelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnels",
		Short: "Show tunnel state",
		Long:  "Display the current overlay tunnel table showing peer nodes and their tunnel interfaces.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTunnels()
		},
	}

	return cmd
}

func runTunnels() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	// Get routing mode from status.
	status, err := client.GetAgentStatus(ctx, &pb.GetAgentStatusRequest{})
	if err != nil {
		return fmt.Errorf("GetAgentStatus failed: %w", err)
	}

	resp, err := client.ListTunnels(ctx, &pb.ListTunnelsRequest{})
	if err != nil {
		return fmt.Errorf("ListTunnels failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "TUNNEL STATE\n")
	_, _ = fmt.Fprintf(w, "============\n\n")
	_, _ = fmt.Fprintf(w, "Routing Mode:\t%s\n", status.RoutingMode)
	_, _ = fmt.Fprintf(w, "Tunnel Protocol:\t%s\n", status.TunnelProtocol)
	_, _ = fmt.Fprintf(w, "Active Tunnels:\t%d\n\n", len(resp.Tunnels))

	if len(resp.Tunnels) == 0 {
		_, _ = fmt.Fprintln(w, "No active tunnels.")
		_, _ = fmt.Fprintln(w)
		if status.RoutingMode == "native" {
			_, _ = fmt.Fprintln(w, "Note: Tunnels are not used in native routing mode.")
		} else {
			_, _ = fmt.Fprintln(w, "Note: Tunnels are created when remote nodes join the cluster.")
		}
	} else {
		_, _ = fmt.Fprintf(w, "NODE\tNODE_IP\tPOD_CIDR\tINTERFACE\tIFINDEX\tPROTOCOL\n")
		for _, t := range resp.Tunnels {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
				t.NodeName, t.NodeIp, t.PodCidr,
				t.InterfaceName, t.Ifindex, t.Protocol)
		}
	}

	return w.Flush()
}
