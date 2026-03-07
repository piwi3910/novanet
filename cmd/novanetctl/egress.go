package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newEgressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "egress",
		Short: "Show egress policy rules",
		Long:  "Display the egress policy rules currently installed for pod-to-external traffic control.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEgress()
		},
	}

	return cmd
}

func runEgress() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	resp, err := client.ListEgressPolicies(ctx, &pb.ListEgressPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("ListEgressPolicies failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "EGRESS POLICIES\n")
	_, _ = fmt.Fprintf(w, "===============\n\n")
	_, _ = fmt.Fprintf(w, "Total Rules:\t%d\n\n", len(resp.Rules))

	if len(resp.Rules) == 0 {
		_, _ = fmt.Fprintln(w, "No egress policies installed.")
	} else {
		_, _ = fmt.Fprintf(w, "NAMESPACE\tNAME\tSRC_IDENTITY\tDST_CIDR\tPROTOCOL\tPORT\tACTION\n")
		for _, r := range resp.Rules {
			proto := protocolName(r.Protocol)
			action := egressActionName(r.Action)
			port := "*"
			if r.DstPort != 0 {
				port = fmt.Sprintf("%d", r.DstPort)
			}
			src := "*"
			if r.SrcIdentity != 0 {
				src = fmt.Sprintf("%d", r.SrcIdentity)
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Namespace, r.Name, src, r.DstCidr, proto, port, action)
		}
	}

	return w.Flush()
}

func egressActionName(action pb.EgressAction) string {
	switch action {
	case pb.EgressAction_EGRESS_ACTION_DENY:
		return verdictDeny
	case pb.EgressAction_EGRESS_ACTION_ALLOW:
		return "ALLOW"
	case pb.EgressAction_EGRESS_ACTION_SNAT:
		return "SNAT"
	default:
		return verdictDeny
	}
}
