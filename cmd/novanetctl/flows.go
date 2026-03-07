package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"

	"github.com/spf13/cobra"
)

func newFlowsCmd() *cobra.Command {
	var identityFilter uint32

	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Stream real-time flow events",
		Long:  "Display real-time network flow events from the dataplane. Streams continuously until interrupted with Ctrl+C.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFlows(identityFilter, false)
		},
	}

	cmd.Flags().Uint32Var(&identityFilter, "identity", 0, "Filter flows by identity ID (0 = all)")

	return cmd
}

func runFlows(identityFilter uint32, dropsOnly bool) error {
	conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := newAgentClient(conn)

	// Create a context that is cancelled on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	stream, err := client.StreamAgentFlows(ctx, &pb.StreamAgentFlowsRequest{
		IdentityFilter: identityFilter,
		DropsOnly:      dropsOnly,
	})
	if err != nil {
		return fmt.Errorf("StreamAgentFlows failed: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "TIMESTAMP\tSRC_IP\tDST_IP\tSRC_ID\tDST_ID\tPROTO\tPORT\tVERDICT\tBYTES")
	if dropsOnly {
		_, _ = fmt.Fprintf(w, "\tDROP_REASON")
	}
	_, _ = fmt.Fprintln(w)
	_ = w.Flush()

	for {
		flow, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// If context was cancelled (Ctrl+C), exit cleanly.
			if ctx.Err() != nil {
				_, _ = fmt.Fprintln(os.Stderr, "\nStream interrupted.")
				return nil
			}
			return fmt.Errorf("stream error: %w", err)
		}

		printFlow(w, flow, dropsOnly)
		_ = w.Flush()
	}
}

func printFlow(w *tabwriter.Writer, flow *pb.FlowEvent, showDropReason bool) {
	ts := time.Unix(0, flow.TimestampNs).UTC().Format("15:04:05.000")
	srcIP := uint32ToIP(flow.SrcIp)
	dstIP := uint32ToIP(flow.DstIp)
	proto := protocolName(flow.Protocol)
	verdict := verdictName(flow.Verdict)

	_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t%d\t%s\t%d",
		ts, srcIP, dstIP, flow.SrcIdentity, flow.DstIdentity,
		proto, flow.DstPort, verdict, flow.Bytes)

	if showDropReason {
		_, _ = fmt.Fprintf(w, "\t%s", dropReasonName(flow.DropReason))
	}

	_, _ = fmt.Fprintln(w)
}

// uint32ToIP converts a uint32 in network byte order to a dotted-decimal IP string.
func uint32ToIP(n uint32) string {
	ip := net.IPv4(
		byte(n>>24),  //nolint:gosec // right-shifted to 0-255 range
		byte(n>>16),  //nolint:gosec // right-shifted to 0-255 range
		byte(n>>8),   //nolint:gosec // right-shifted to 0-255 range
		byte(n&0xFF), //nolint:gosec // masked to 0-255 range
	)
	return ip.String()
}

func verdictName(v pb.PolicyAction) string {
	switch v {
	case pb.PolicyAction_POLICY_ACTION_ALLOW:
		return "ALLOW"
	case pb.PolicyAction_POLICY_ACTION_DENY:
		return verdictDeny
	default:
		return "UNKNOWN"
	}
}

func dropReasonName(r pb.DropReason) string {
	switch r {
	case pb.DropReason_DROP_REASON_NONE:
		return "-"
	case pb.DropReason_DROP_REASON_POLICY_DENIED:
		return "POLICY_DENIED"
	case pb.DropReason_DROP_REASON_NO_IDENTITY:
		return "NO_IDENTITY"
	case pb.DropReason_DROP_REASON_NO_ROUTE:
		return "NO_ROUTE"
	case pb.DropReason_DROP_REASON_NO_TUNNEL:
		return "NO_TUNNEL"
	case pb.DropReason_DROP_REASON_TTL_EXCEEDED:
		return "TTL_EXCEEDED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", r)
	}
}
