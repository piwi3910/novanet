package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show agent and node status",
		Long:  "Display the full status of the NovaNet agent including routing mode, dataplane state, and counters.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(outputFormat)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	return cmd
}

func runStatus(outputFormat string) error {
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

	switch outputFormat {
	case "json":
		return printStatusJSON(resp)
	default:
		return printStatusTable(resp)
	}
}

func printStatusJSON(resp *pb.GetAgentStatusResponse) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

func printStatusTable(resp *pb.GetAgentStatusResponse) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	_, _ = fmt.Fprintln(w, "NovaNet Agent Status")
	_, _ = fmt.Fprintln(w, "====================")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "Routing Mode:\t%s\n", resp.RoutingMode)
	_, _ = fmt.Fprintf(w, "Tunnel Protocol:\t%s\n", resp.TunnelProtocol)
	_, _ = fmt.Fprintf(w, "Node IP:\t%s\n", resp.NodeIp)
	_, _ = fmt.Fprintf(w, "Pod CIDR:\t%s\n", resp.PodCidr)
	_, _ = fmt.Fprintf(w, "Cluster CIDR:\t%s\n", resp.ClusterCidr)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "Endpoints:\t%d\n", resp.EndpointCount)
	_, _ = fmt.Fprintf(w, "Policies:\t%d\n", resp.PolicyCount)
	_, _ = fmt.Fprintf(w, "Tunnels:\t%d\n", resp.TunnelCount)
	_, _ = fmt.Fprintf(w, "Identities:\t%d\n", resp.IdentityCount)
	_, _ = fmt.Fprintln(w)

	dpStatus := "disconnected"
	dpPrograms := uint32(0)
	if resp.Dataplane != nil {
		if resp.Dataplane.Connected {
			dpStatus = "connected"
		}
		dpPrograms = resp.Dataplane.AttachedPrograms
	}
	_, _ = fmt.Fprintf(w, "Dataplane:\t%s\n", dpStatus)
	_, _ = fmt.Fprintf(w, "Attached Programs:\t%d\n", dpPrograms)
	_, _ = fmt.Fprintf(w, "Routing Connected:\t%v\n", resp.NovarouteConnected)

	return w.Flush()
}
