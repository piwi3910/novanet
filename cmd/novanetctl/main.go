// Package main implements novanetctl, the CLI tool for inspecting and
// controlling a running NovaNet agent and dataplane.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	// Version is the build version of novanetctl. Overridden at build time.
	Version = "0.1.0"

	// defaultAgentSocket is the default novanet-agent gRPC socket.
	defaultAgentSocket = "/run/novanet/novanet.sock"

	// defaultDataplaneSocket is the default dataplane gRPC socket.
	defaultDataplaneSocket = "/run/novanet/dataplane.sock"
)

// Global flags accessible to all subcommands.
var (
	agentSocket     string
	dataplaneSocket string
)

func main() {
	rootCmd := &cobra.Command{
		Use:           "novanetctl",
		Short:         "NovaNet CLI tool",
		Long:          "novanetctl is the command-line tool for inspecting and controlling a running NovaNet agent.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags.
	rootCmd.PersistentFlags().StringVar(&agentSocket, "agent-socket", defaultAgentSocket,
		"Path to the novanet-agent gRPC socket")
	rootCmd.PersistentFlags().StringVar(&dataplaneSocket, "dataplane-socket", defaultDataplaneSocket,
		"Path to the dataplane gRPC socket")

	// Version subcommand.
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintf(os.Stdout, "novanetctl %s\n", Version)
		},
	}

	// Register all subcommands.
	rootCmd.AddCommand(
		versionCmd,
		newStatusCmd(),
		newFlowsCmd(),
		newDropsCmd(),
		newTunnelsCmd(),
		newPolicyCmd(),
		newIdentityCmd(),
		newEgressCmd(),
		newMetricsCmd(),
		newServicesCmd(),
		newRoutingCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
