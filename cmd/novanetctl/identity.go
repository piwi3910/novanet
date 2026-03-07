package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Show identity mappings",
		Long:  "Display the identity allocator state showing identity IDs, their label sets, and reference counts.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIdentity()
		},
	}

	return cmd
}

func runIdentity() error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	resp, err := client.ListIdentities(ctx, &pb.ListIdentitiesRequest{})
	if err != nil {
		return fmt.Errorf("ListIdentities failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "IDENTITY MAPPINGS\n")
	_, _ = fmt.Fprintf(w, "=================\n\n")
	_, _ = fmt.Fprintf(w, "Total Identities:\t%d\n\n", len(resp.Identities))

	if len(resp.Identities) == 0 {
		_, _ = fmt.Fprintln(w, "No identities allocated.")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Identities are allocated when pods are scheduled to this node.")
	} else {
		_, _ = fmt.Fprintf(w, "ID\tPOD_COUNT\tLABELS\n")
		for _, id := range resp.Identities {
			labels := formatLabels(id.Labels)
			_, _ = fmt.Fprintf(w, "%d\t%d\t%s\n", id.IdentityId, id.RefCount, labels)
		}
	}

	return w.Flush()
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "<none>"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}
	return strings.Join(parts, ", ")
}
