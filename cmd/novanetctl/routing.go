package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newRoutingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "routing",
		Short: "Inspect routing state",
		Long:  "Commands for inspecting BGP/OSPF/BFD routing state in native routing mode.",
	}

	cmd.AddCommand(
		newRoutingStatusCmd(),
		newRoutingPeersCmd(),
		newRoutingPrefixesCmd(),
	)

	return cmd
}

func newRoutingStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show routing status",
		Long:  "Display the current routing mode, protocol state, and connectivity status.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoutingStatus()
		},
	}

	return cmd
}

func runRoutingStatus() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	resp, err := client.GetAgentStatus(ctx, &pb.GetAgentStatusRequest{})
	if err != nil {
		return fmt.Errorf("GetAgentStatus failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	_, _ = fmt.Fprintln(w, "Routing Status")
	_, _ = fmt.Fprintln(w, "==============")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "Routing Mode:\t%s\n", resp.RoutingMode)
	_, _ = fmt.Fprintf(w, "Routing Connected:\t%v\n", resp.NovarouteConnected)
	_, _ = fmt.Fprintf(w, "Tunnel Protocol:\t%s\n", resp.TunnelProtocol)
	_, _ = fmt.Fprintf(w, "Encryption:\t%s\n", resp.Encryption)

	return w.Flush()
}

func newRoutingPeersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peers",
		Short: "Show routing peers",
		Long:  "Display BGP/OSPF peer state for native routing mode.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Routing peer information requires native routing mode. Use FRR vtysh for detailed BGP/OSPF peer state.")
		},
	}

	return cmd
}

func newRoutingPrefixesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prefixes",
		Short: "Show advertised and received prefixes",
		Long:  "Display BGP/OSPF prefix state for native routing mode.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Routing prefix information requires native routing mode. Use FRR vtysh for detailed prefix state.")
		},
	}

	return cmd
}
