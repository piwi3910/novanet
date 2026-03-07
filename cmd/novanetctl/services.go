package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newServicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "Show L4 LB services",
		Long:  "Display the Kubernetes Services tracked by NovaNet's L4 load balancer.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServices()
		},
	}
	return cmd
}

func runServices() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	resp, err := client.ListServices(ctx, &pb.ListServicesRequest{})
	if err != nil {
		return fmt.Errorf("ListServices failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "L4 LB SERVICES\n")
	_, _ = fmt.Fprintf(w, "==============\n\n")
	_, _ = fmt.Fprintf(w, "Total Services:\t%d\n\n", len(resp.Services))

	if len(resp.Services) == 0 {
		_, _ = fmt.Fprintln(w, "No services tracked.")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Enable L4 LB with l4lb.enabled=true in the NovaNet config.")
	} else {
		_, _ = fmt.Fprintf(w, "CLUSTER-IP\tPORT\tPROTOCOL\tTYPE\tBACKENDS\tALGORITHM\n")
		for _, svc := range resp.Services {
			backends := fmt.Sprintf("%d", svc.BackendCount)
			_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
				svc.ClusterIp, svc.Port, svc.Protocol, svc.Scope,
				backends, svc.Algorithm)
		}
	}

	return w.Flush()
}
