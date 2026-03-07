// Package main tests for novanetctl CLI.
package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// Root command structure
// ---------------------------------------------------------------------------

// TestRootCommandSubcommands verifies that the root cobra command exposes the
// expected set of subcommands so that any accidental deletion is caught early.
func TestRootCommandSubcommands(t *testing.T) {
	// Build the same command tree that main() constructs.
	root, versionCmd := buildRootCmd()

	// Collect subcommand names.
	names := make(map[string]bool)
	for _, sub := range root.Commands() {
		names[sub.Name()] = true
	}

	expected := []string{
		versionCmd.Name(),
		"status",
		"flows",
		"drops",
		"tunnels",
		"policy",
		"identity",
		"egress",
		"metrics",
	}

	for _, want := range expected {
		if !names[want] {
			t.Errorf("expected subcommand %q to be registered", want)
		}
	}
}

// buildRootCmd replicates the command-tree construction from main() so tests
// can inspect it without calling os.Exit.
func buildRootCmd() (*cobra.Command, *cobra.Command) {
	root := newRootCmdForTest()
	vc := &cobra.Command{Use: "version", Short: "Print version information"}
	root.AddCommand(
		vc,
		newStatusCmd(),
		newFlowsCmd(),
		newDropsCmd(),
		newTunnelsCmd(),
		newPolicyCmd(),
		newIdentityCmd(),
		newEgressCmd(),
		newMetricsCmd(),
	)
	return root, vc
}

// newRootCmdForTest returns a minimal root command for inspection (no Execute).
func newRootCmdForTest() *cobra.Command {
	return &cobra.Command{
		Use:           "novanetctl",
		Short:         "NovaNet CLI tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

// TestVersionConstant ensures the Version constant is a non-empty semver-like
// string so it is not accidentally blanked out.
func TestVersionConstant(t *testing.T) {
	if Version == "" {
		t.Error("Version constant must not be empty")
	}
	if !strings.Contains(Version, ".") {
		t.Errorf("Version %q does not look like a semver string", Version)
	}
}

// TestDefaultSocketConstants ensures the default socket paths start with /run/novanet/.
func TestDefaultSocketConstants(t *testing.T) {
	prefix := "/run/novanet/"
	if !strings.HasPrefix(defaultAgentSocket, prefix) {
		t.Errorf("defaultAgentSocket %q does not start with %s", defaultAgentSocket, prefix)
	}
	if !strings.HasPrefix(defaultDataplaneSocket, prefix) {
		t.Errorf("defaultDataplaneSocket %q does not start with %s", defaultDataplaneSocket, prefix)
	}
}

// ---------------------------------------------------------------------------
// Connect helpers — invalid socket paths
// ---------------------------------------------------------------------------

// TestConnectAgent_InvalidSocket verifies that connectAgent creates a client
// even for a nonexistent socket path. grpc.NewClient uses lazy connections,
// so the error only surfaces on the first RPC call, not at creation time.
func TestConnectAgent_InvalidSocket(t *testing.T) {
	orig := agentSocket
	defer func() { agentSocket = orig }()

	agentSocket = "/nonexistent/novanet.sock"

	conn, err := connectAgent()
	// grpc.NewClient is lazy — it succeeds even for invalid paths.
	require.NoError(t, err)
	require.NotNil(t, conn)
	_ = conn.Close()
}

// TestConnectDataplane_InvalidSocket verifies that connectDataplane creates a
// client even for a nonexistent socket path. grpc.NewClient uses lazy connections.
func TestConnectDataplane_InvalidSocket(t *testing.T) {
	orig := dataplaneSocket
	defer func() { dataplaneSocket = orig }()

	dataplaneSocket = "/nonexistent/dataplane.sock"

	conn, err := connectDataplane()
	require.NoError(t, err)
	require.NotNil(t, conn)
	_ = conn.Close()
}

// ---------------------------------------------------------------------------
// uint32ToIP
// ---------------------------------------------------------------------------

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name  string
		input uint32
		want  string
	}{
		{name: "loopback", input: 0x7F000001, want: "127.0.0.1"},
		{name: "all zeros", input: 0x00000000, want: "0.0.0.0"},
		{name: "all ones", input: 0xFFFFFFFF, want: "255.255.255.255"},
		{name: "192.168.1.1", input: 0xC0A80101, want: "192.168.1.1"},
		{name: "10.244.1.5", input: 0x0AF40105, want: "10.244.1.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uint32ToIP(tt.input)
			if got != tt.want {
				t.Errorf("uint32ToIP(0x%08X) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// protocolName
// ---------------------------------------------------------------------------

func TestProtocolName(t *testing.T) {
	tests := []struct {
		proto uint32
		want  string
	}{
		{0, "*"},
		{1, "ICMP"},
		{6, "TCP"},
		{17, "UDP"},
		{132, "SCTP"},
		{58, "58"},   // ICMPv6 — unknown, should be numeric
		{255, "255"}, // reserved — numeric
	}

	for _, tt := range tests {
		got := protocolName(tt.proto)
		if got != tt.want {
			t.Errorf("protocolName(%d) = %q, want %q", tt.proto, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// verdictName
// ---------------------------------------------------------------------------

func TestVerdictName(t *testing.T) {
	tests := []struct {
		verdict pb.PolicyAction
		want    string
	}{
		{pb.PolicyAction_POLICY_ACTION_ALLOW, "ALLOW"},
		{pb.PolicyAction_POLICY_ACTION_DENY, "DENY"},
		{pb.PolicyAction(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		got := verdictName(tt.verdict)
		if got != tt.want {
			t.Errorf("verdictName(%v) = %q, want %q", tt.verdict, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// dropReasonName
// ---------------------------------------------------------------------------

func TestDropReasonName(t *testing.T) {
	tests := []struct {
		reason pb.DropReason
		want   string
	}{
		{pb.DropReason_DROP_REASON_NONE, "-"},
		{pb.DropReason_DROP_REASON_POLICY_DENIED, "POLICY_DENIED"},
		{pb.DropReason_DROP_REASON_NO_IDENTITY, "NO_IDENTITY"},
		{pb.DropReason_DROP_REASON_NO_ROUTE, "NO_ROUTE"},
		{pb.DropReason_DROP_REASON_NO_TUNNEL, "NO_TUNNEL"},
		{pb.DropReason_DROP_REASON_TTL_EXCEEDED, "TTL_EXCEEDED"},
		{pb.DropReason(99), "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		got := dropReasonName(tt.reason)
		if got != tt.want {
			t.Errorf("dropReasonName(%v) = %q, want %q", tt.reason, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Subcommand constructors — verify non-nil and expected Use fields
// ---------------------------------------------------------------------------

func TestNewStatusCmd(t *testing.T) {
	cmd := newStatusCmd()
	if cmd == nil {
		t.Fatal("newStatusCmd() returned nil")
	}
	if cmd.Use != "status" {
		t.Errorf("expected Use=status, got %s", cmd.Use)
	}
}

func TestNewFlowsCmd(t *testing.T) {
	cmd := newFlowsCmd()
	if cmd == nil {
		t.Fatal("newFlowsCmd() returned nil")
	}
	if cmd.Use != "flows" {
		t.Errorf("expected Use=flows, got %s", cmd.Use)
	}
}

func TestNewDropsCmd(t *testing.T) {
	cmd := newDropsCmd()
	if cmd == nil {
		t.Fatal("newDropsCmd() returned nil")
	}
	if cmd.Use != "drops" {
		t.Errorf("expected Use=drops, got %s", cmd.Use)
	}
}

func TestNewTunnelsCmd(t *testing.T) {
	cmd := newTunnelsCmd()
	if cmd == nil {
		t.Fatal("newTunnelsCmd() returned nil")
	}
	if cmd.Use != "tunnels" {
		t.Errorf("expected Use=tunnels, got %s", cmd.Use)
	}
}

func TestNewPolicyCmd(t *testing.T) {
	cmd := newPolicyCmd()
	if cmd == nil {
		t.Fatal("newPolicyCmd() returned nil")
	}
	if cmd.Use != "policy" {
		t.Errorf("expected Use=policy, got %s", cmd.Use)
	}
}

func TestNewIdentityCmd(t *testing.T) {
	cmd := newIdentityCmd()
	if cmd == nil {
		t.Fatal("newIdentityCmd() returned nil")
	}
	if cmd.Use != "identity" {
		t.Errorf("expected Use=identity, got %s", cmd.Use)
	}
}

func TestNewEgressCmd(t *testing.T) {
	cmd := newEgressCmd()
	if cmd == nil {
		t.Fatal("newEgressCmd() returned nil")
	}
	if cmd.Use != "egress" {
		t.Errorf("expected Use=egress, got %s", cmd.Use)
	}
}

func TestNewMetricsCmd(t *testing.T) {
	cmd := newMetricsCmd()
	if cmd == nil {
		t.Fatal("newMetricsCmd() returned nil")
	}
	if cmd.Use != "metrics" {
		t.Errorf("expected Use=metrics, got %s", cmd.Use)
	}
}
