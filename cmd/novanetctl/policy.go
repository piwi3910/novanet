package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Show compiled policy rules",
		Long:  "Display the compiled policy rules currently installed in the dataplane.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicy()
		},
	}

	return cmd
}

func runPolicy() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	resp, err := client.ListPolicies(ctx, &pb.ListPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("ListPolicies failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "POLICY RULES\n")
	_, _ = fmt.Fprintf(w, "============\n\n")
	_, _ = fmt.Fprintf(w, "Total Rules:\t%d\n\n", len(resp.Rules))

	if len(resp.Rules) == 0 {
		_, _ = fmt.Fprintln(w, "No policies installed.")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Policies are compiled from Kubernetes NetworkPolicy resources.")
	} else {
		_, _ = fmt.Fprintf(w, "SRC_IDENTITY\tDST_IDENTITY\tPROTOCOL\tPORT\tACTION\n")
		for _, r := range resp.Rules {
			proto := protocolName(r.Protocol)
			action := verdictDeny
			if r.Action == pb.PolicyAction_POLICY_ACTION_ALLOW {
				action = "ALLOW"
			}
			port := "*"
			if r.DstPort != 0 {
				port = fmt.Sprintf("%d", r.DstPort)
			}
			src := "*"
			if r.SrcIdentity != 0 {
				src = fmt.Sprintf("%d", r.SrcIdentity)
			}
			dst := "*"
			if r.DstIdentity != 0 {
				dst = fmt.Sprintf("%d", r.DstIdentity)
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", src, dst, proto, port, action)
		}
	}

	return w.Flush()
}
