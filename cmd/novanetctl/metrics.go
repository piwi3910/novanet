package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newMetricsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show summary metrics",
		Long:  "Display summary metrics from the NovaNet agent and dataplane.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetrics()
		},
	}

	return cmd
}

func runMetrics() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	status, err := client.GetAgentStatus(ctx, &pb.GetAgentStatusRequest{})
	if err != nil {
		return fmt.Errorf("GetAgentStatus failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "NOVANET METRICS SUMMARY\n")
	_, _ = fmt.Fprintf(w, "=======================\n\n")

	_, _ = fmt.Fprintf(w, "Endpoints:\t%d\n", status.EndpointCount)
	_, _ = fmt.Fprintf(w, "Identities:\t%d\n", status.IdentityCount)
	_, _ = fmt.Fprintf(w, "Policies:\t%d\n", status.PolicyCount)
	_, _ = fmt.Fprintf(w, "Tunnels:\t%d\n", status.TunnelCount)
	_, _ = fmt.Fprintln(w)

	dpStatus := "disconnected"
	dpPrograms := uint32(0)
	if status.Dataplane != nil {
		if status.Dataplane.Connected {
			dpStatus = "connected"
		}
		dpPrograms = status.Dataplane.AttachedPrograms
	}
	_, _ = fmt.Fprintf(w, "Dataplane Status:\t%s\n", dpStatus)
	_, _ = fmt.Fprintf(w, "Attached Programs:\t%d\n", dpPrograms)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "Note: Detailed flow/drop counters are available via the Prometheus")
	_, _ = fmt.Fprintf(w, "metrics endpoint or by using 'novanetctl flows' / 'novanetctl drops'.\n")

	return w.Flush()
}
