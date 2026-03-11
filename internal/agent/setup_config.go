package agent

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/egress"
	"github.com/azrtydxb/novanet/internal/identity"
	"github.com/azrtydxb/novanet/internal/ipam"
	"github.com/azrtydxb/novanet/internal/masquerade"
	"github.com/azrtydxb/novanet/internal/policy"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ParseFlags parses command-line flags and handles --version.
func ParseFlags() Params {
	configPath := flag.String("config", "/etc/novanet/config.json", "Path to configuration file")
	podCIDR := flag.String("pod-cidr", "", "Node's PodCIDR (e.g., 10.244.1.0/24)")
	nodeIPStr := flag.String("node-ip", "", "Node IP address")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		_, _ = fmt.Fprintf(os.Stdout, "novanet-agent %s\n", Version)
		os.Exit(0)
	}

	return Params{
		ConfigPath: *configPath,
		PodCIDR:    *podCIDR,
		NodeIPStr:  *nodeIPStr,
		NodeName:   os.Getenv("NOVANET_NODE_NAME"),
	}
}

// LoadConfig loads and validates the agent configuration file.
func LoadConfig(configPath string) *config.Config {
	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = config.DefaultConfig()
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
	}
	config.ExpandEnvVars(cfg)

	if err := config.Validate(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// BuildLogger creates a production zap logger with JSON encoding and ISO8601 timestamps.
func BuildLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch strings.ToLower(level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg := zap.Config{Level: zap.NewAtomicLevelAt(zapLevel), Encoding: "json", EncoderConfig: encoderCfg,
		OutputPaths: []string{"stderr"}, ErrorOutputPaths: []string{"stderr"}}
	return cfg.Build()
}

// CreateK8sClient creates a Kubernetes clientset if running inside a cluster.
func CreateK8sClient(logger *zap.Logger, nodeName string) *kubernetes.Clientset {
	if nodeName == "" {
		return nil
	}
	k8sCfg, err := rest.InClusterConfig()
	if err != nil {
		logger.Fatal("failed to create in-cluster config", zap.Error(err))
	}
	k8sClient, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		logger.Fatal("failed to create kubernetes client", zap.Error(err))
	}
	return k8sClient
}

// ResolveNodeParams auto-detects pod-cidr and node-ip from the Kubernetes API.
func ResolveNodeParams(logger *zap.Logger, k8sClient *kubernetes.Clientset, params *Params) {
	if (params.PodCIDR == "" || params.NodeIPStr == "") && k8sClient != nil {
		logger.Info("auto-detecting node-ip/pod-cidr from Kubernetes API",
			zap.String("node_name", params.NodeName))
		nodeCtx, nodeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		node, err := k8sClient.CoreV1().Nodes().Get(nodeCtx, params.NodeName, metav1.GetOptions{})
		nodeCancel()
		if err != nil {
			logger.Fatal("failed to get node for auto-detection", zap.Error(err), zap.String("node", params.NodeName))
		}
		if params.PodCIDR == "" && node.Spec.PodCIDR != "" {
			params.PodCIDR = node.Spec.PodCIDR
			logger.Info("auto-detected pod-cidr", zap.String("pod_cidr", params.PodCIDR))
		}
		if params.NodeIPStr == "" {
			for _, addr := range node.Status.Addresses {
				if addr.Type == "InternalIP" {
					params.NodeIPStr = addr.Address
					logger.Info("auto-detected node-ip", zap.String("node_ip", params.NodeIPStr))
					break
				}
			}
		}
	}
	if params.PodCIDR == "" {
		logger.Fatal("--pod-cidr is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
	if params.NodeIPStr == "" {
		logger.Fatal("--node-ip is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
}

// ParseNodeIP parses and validates the node IP string (IPv4 or IPv6).
func ParseNodeIP(logger *zap.Logger, nodeIPStr string) net.IP {
	nodeIP := net.ParseIP(nodeIPStr)
	if nodeIP == nil {
		logger.Fatal("invalid --node-ip", zap.String("value", nodeIPStr))
	}
	return nodeIP
}

// NodeInternalIP returns the InternalIP address of a Kubernetes node.
func NodeInternalIP(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == "InternalIP" {
			return addr.Address
		}
	}
	return ""
}

// CreateIPAM creates the IPAM allocator for the node's PodCIDR.
func CreateIPAM(logger *zap.Logger, podCIDR string) *ipam.Allocator {
	ipAlloc, err := ipam.NewAllocatorWithStateDir(podCIDR, "/var/lib/cni/networks/novanet")
	if err != nil {
		logger.Fatal("failed to create IPAM allocator", zap.Error(err))
	}
	ipAlloc.SetLogger(logger)
	logger.Info("IPAM allocator created", zap.String("pod_cidr", podCIDR), zap.Int("available", ipAlloc.Available()))
	return ipAlloc
}

// SetupMasquerade configures NAT masquerade if a cluster CIDR is configured.
func SetupMasquerade(logger *zap.Logger, cfg *config.Config, podCIDR string) {
	if cfg.ClusterCIDR == "" {
		return
	}
	if err := masquerade.EnsureMasquerade(podCIDR, cfg.ClusterCIDR); err != nil {
		logger.Error("failed to setup NAT masquerade", zap.Error(err))
	} else {
		logger.Info("NAT masquerade configured", zap.String("pod_cidr", podCIDR), zap.String("cluster_cidr", cfg.ClusterCIDR))
	}
}

// CreatePolicyCompiler creates the policy compiler with port/namespace resolvers.
func CreatePolicyCompiler(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	idAlloc *identity.Allocator) *policy.Compiler {
	policyCompiler := policy.NewCompiler(idAlloc, logger)
	if k8sClient != nil {
		policyCompiler.SetPortResolver(func(portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {
			return resolveNamedPorts(ctx, k8sClient, portName, protocol, namespace, selector)
		})
		policyCompiler.SetNamespaceResolver(func(selector metav1.LabelSelector) []string {
			return resolveNamespaces(ctx, k8sClient, selector)
		})
	}
	logger.Info("policy compiler created")
	return policyCompiler
}

func resolveNamedPorts(ctx context.Context, k8sClient *kubernetes.Clientset,
	portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil
	}
	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return nil
	}
	seen := make(map[uint16]bool)
	var ports []uint16
	for _, pod := range pods.Items {
		for _, c := range pod.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name == portName && cp.Protocol == protocol {
					if !seen[uint16(cp.ContainerPort)] { //nolint:gosec // K8s port range 1-65535 fits uint16
						seen[uint16(cp.ContainerPort)] = true           //nolint:gosec // K8s port range 1-65535 fits uint16
						ports = append(ports, uint16(cp.ContainerPort)) //nolint:gosec // K8s port range 1-65535 fits uint16
					}
				}
			}
		}
	}
	return ports
}

func resolveNamespaces(ctx context.Context, k8sClient *kubernetes.Clientset, selector metav1.LabelSelector) []string {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil
	}
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return nil
	}
	var names []string
	for _, ns := range nsList.Items {
		names = append(names, ns.Name)
	}
	return names
}

// CreateEgressManager creates the egress manager if a cluster CIDR is configured.
func CreateEgressManager(logger *zap.Logger, cfg *config.Config, nodeIP net.IP) *egress.Manager {
	if cfg.ClusterCIDR == "" {
		return nil
	}
	_, clusterNet, err := net.ParseCIDR(cfg.ClusterCIDR)
	if err != nil {
		logger.Warn("failed to parse cluster CIDR, egress manager disabled",
			zap.String("cluster_cidr", cfg.ClusterCIDR), zap.Error(err))
		return nil
	}
	mgr := egress.NewManager(nodeIP, clusterNet, logger)
	logger.Info("egress manager created")
	return mgr
}
