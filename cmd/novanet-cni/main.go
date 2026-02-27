// Package main implements the NovaNet CNI binary. This is a short-lived
// process invoked by kubelet on pod creation and deletion. It delegates
// all real work to the novanet-agent via a gRPC call over a Unix domain
// socket.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	pb "github.com/piwi3910/novanet/api/v1"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// defaultAgentSocket is the default path to the novanet-agent CNI socket.
	defaultAgentSocket = "/run/novanet/cni.sock"

	// agentCallTimeout is the maximum time to wait for an agent RPC response.
	agentCallTimeout = 30 * time.Second

	// supportedVersions lists the CNI spec versions this plugin supports.
	cniVersion = "1.0.0"
)

// NetConf is the CNI network configuration parsed from stdin.
type NetConf struct {
	types.NetConf

	// AgentSocket overrides the default path to the agent gRPC socket.
	AgentSocket string `json:"agentSocket,omitempty"`

	// LogFile is the path to write CNI log output.
	LogFile string `json:"logFile,omitempty"`
}

// cniLogger writes log messages to a file for debugging. CNI binaries must
// never write anything to stdout except the CNI result JSON.
type cniLogger struct {
	w io.Writer
}

func (l *cniLogger) Printf(format string, args ...interface{}) {
	if l.w != nil {
		ts := time.Now().UTC().Format(time.RFC3339)
		fmt.Fprintf(l.w, "%s [novanet-cni] %s\n", ts, fmt.Sprintf(format, args...))
	}
}

func main() {
	supportedVersions := version.PluginSupports("0.3.0", "0.3.1", "0.4.0", "1.0.0")
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, supportedVersions, "NovaNet CNI plugin v0.1.0")
}

// parseConfig reads the CNI network configuration from the raw bytes.
func parseConfig(data []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("failed to parse CNI config: %w", err)
	}

	if conf.AgentSocket == "" {
		conf.AgentSocket = defaultAgentSocket
	}

	return conf, nil
}

// openLog opens the log file for writing. Returns nil writer if the path is
// empty or the file cannot be opened.
func openLog(path string) *cniLogger {
	if path == "" {
		return &cniLogger{}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return &cniLogger{}
	}
	// Note: we intentionally do not close this file handle. The CNI binary
	// is a short-lived process, and the OS will reclaim the fd on exit.
	return &cniLogger{w: f}
}

// dialAgent creates a gRPC client connection to the novanet-agent.
func dialAgent(socketPath string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to novanet-agent at %s: %w", socketPath, err)
	}
	return conn, nil
}

// parseCNIArgs extracts key-value pairs from the CNI_ARGS environment variable.
// The format is "KEY1=VAL1;KEY2=VAL2;...".
func parseCNIArgs(args string) map[string]string {
	result := make(map[string]string)
	if args == "" {
		return result
	}
	for _, pair := range strings.Split(args, ";") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

// cmdAdd handles the CNI ADD command.
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	log := openLog(conf.LogFile)
	log.Printf("ADD container=%s netns=%s ifname=%s", args.ContainerID, args.Netns, args.IfName)

	// Parse pod name and namespace from CNI_ARGS.
	cniArgs := parseCNIArgs(args.Args)
	podName := cniArgs["K8S_POD_NAME"]
	podNamespace := cniArgs["K8S_POD_NAMESPACE"]

	if podName == "" || podNamespace == "" {
		log.Printf("warning: K8S_POD_NAME or K8S_POD_NAMESPACE not set in CNI_ARGS")
	}

	// Connect to agent.
	conn, err := dialAgent(conf.AgentSocket)
	if err != nil {
		log.Printf("ERROR: %v", err)
		return fmt.Errorf("connecting to novanet-agent: %w", err)
	}
	defer conn.Close()

	client := pb.NewAgentControlClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), agentCallTimeout)
	defer cancel()

	// Call AddPod.
	resp, err := client.AddPod(ctx, &pb.AddPodRequest{
		PodName:      podName,
		PodNamespace: podNamespace,
		ContainerId:  args.ContainerID,
		Netns:        args.Netns,
		IfName:       args.IfName,
	})
	if err != nil {
		log.Printf("ERROR: AddPod failed: %v", err)
		return fmt.Errorf("AddPod RPC failed: %w", err)
	}

	log.Printf("ADD result: ip=%s gateway=%s mac=%s prefix=%d",
		resp.Ip, resp.Gateway, resp.Mac, resp.PrefixLength)

	// Build the CNI result.
	podIP, podNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", resp.Ip, resp.PrefixLength))
	if err != nil {
		return fmt.Errorf("invalid IP from agent: %w", err)
	}
	podNet.IP = podIP

	gwIP := net.ParseIP(resp.Gateway)
	if gwIP == nil {
		return fmt.Errorf("invalid gateway from agent: %s", resp.Gateway)
	}

	_, defaultDst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("parsing default route CIDR: %w", err)
	}

	result := &types100.Result{
		CNIVersion: cniVersion,
		Interfaces: []*types100.Interface{
			{
				Name:    args.IfName,
				Mac:     resp.Mac,
				Sandbox: args.Netns,
			},
		},
		IPs: []*types100.IPConfig{
			{
				Address:   *podNet,
				Gateway:   gwIP,
				Interface: intPtr(0),
			},
		},
		Routes: []*types.Route{
			{
				Dst: *defaultDst,
				GW:  gwIP,
			},
		},
	}

	return types.PrintResult(result, cniVersion)
}

// cmdDel handles the CNI DEL command.
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	log := openLog(conf.LogFile)
	log.Printf("DEL container=%s netns=%s ifname=%s", args.ContainerID, args.Netns, args.IfName)

	// Parse pod name and namespace from CNI_ARGS.
	cniArgs := parseCNIArgs(args.Args)
	podName := cniArgs["K8S_POD_NAME"]
	podNamespace := cniArgs["K8S_POD_NAMESPACE"]

	// Connect to agent.
	conn, err := dialAgent(conf.AgentSocket)
	if err != nil {
		// On DEL, if the agent is not reachable, we should not return
		// an error because kubelet will retry indefinitely. The pod's
		// resources may already be cleaned up.
		log.Printf("WARNING: agent unreachable on DEL, treating as success: %v", err)
		return nil
	}
	defer conn.Close()

	client := pb.NewAgentControlClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), agentCallTimeout)
	defer cancel()

	// Call DelPod.
	_, err = client.DelPod(ctx, &pb.DelPodRequest{
		PodName:      podName,
		PodNamespace: podNamespace,
		ContainerId:  args.ContainerID,
		Netns:        args.Netns,
		IfName:       args.IfName,
	})
	if err != nil {
		log.Printf("ERROR: DelPod failed: %v", err)
		return fmt.Errorf("DelPod RPC failed: %w", err)
	}

	log.Printf("DEL completed successfully")
	return nil
}

// cmdCheck handles the CNI CHECK command.
func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	log := openLog(conf.LogFile)
	log.Printf("CHECK container=%s netns=%s ifname=%s", args.ContainerID, args.Netns, args.IfName)

	// Connect to agent and verify it is healthy.
	conn, err := dialAgent(conf.AgentSocket)
	if err != nil {
		log.Printf("ERROR: agent unreachable on CHECK: %v", err)
		return fmt.Errorf("novanet-agent unreachable: %w", err)
	}
	defer conn.Close()

	client := pb.NewAgentControlClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), agentCallTimeout)
	defer cancel()

	// Verify agent is operational by checking status.
	_, err = client.GetAgentStatus(ctx, &pb.GetAgentStatusRequest{})
	if err != nil {
		log.Printf("ERROR: agent status check failed: %v", err)
		return fmt.Errorf("agent status check failed: %w", err)
	}

	log.Printf("CHECK passed")
	return nil
}


// intPtr returns a pointer to an int.
func intPtr(i int) *int {
	return &i
}
