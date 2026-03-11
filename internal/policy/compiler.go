// Package policy compiles Kubernetes NetworkPolicy objects into identity-based
// rules suitable for the eBPF dataplane.
package policy

import (
	"math"
	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/azrtydxb/novanet/internal/constants"
	"github.com/azrtydxb/novanet/internal/identity"
)

// Action constants for compiled rules — aliased from constants package.
const (
	ActionDeny  = constants.ActionDeny
	ActionAllow = constants.ActionAllow
)

// Protocol constants — aliased from constants package.
const (
	ProtocolTCP  = constants.ProtocolTCP
	ProtocolUDP  = constants.ProtocolUDP
	ProtocolSCTP = constants.ProtocolSCTP
	ProtocolAny  = constants.ProtocolAny
)

// WildcardIdentity matches any identity in a rule (used for open selectors).
const WildcardIdentity uint64 = 0

// PortResolver resolves a named port to numeric port numbers for pods
// matching the given selector in the given namespace. Returns nil if
// resolution is not supported or no matches are found.
type PortResolver func(portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16

// NamespaceResolver resolves a namespace label selector to matching namespace
// names. This is needed to support arbitrary namespace selectors in NetworkPolicy
// peers (beyond just kubernetes.io/metadata.name).
type NamespaceResolver func(selector metav1.LabelSelector) []string

// CompiledRule represents a single policy rule ready for the dataplane.
type CompiledRule struct {
	// SrcIdentity is the source identity ID (0 = wildcard/any).
	SrcIdentity uint64
	// DstIdentity is the destination identity ID (0 = wildcard/any).
	DstIdentity uint64
	// Protocol is the IP protocol number (0 = any).
	Protocol uint8
	// DstPort is the destination port (0 = any).
	DstPort uint16
	// Action is the policy action (0 = deny, 1 = allow).
	Action uint8
	// CIDR is set for IPBlock-based rules (empty for identity-based rules).
	CIDR string
	// IsEgress indicates whether this is an egress rule (vs ingress).
	IsEgress bool
	// Namespace is the Kubernetes namespace of the NetworkPolicy that produced this rule.
	Namespace string
}

// Compiler compiles Kubernetes NetworkPolicy resources into identity-based rules.
type Compiler struct {
	peerResolver
	portResolver PortResolver
}

// NewCompiler creates a new policy compiler.
func NewCompiler(identityAllocator *identity.Allocator, logger *zap.Logger) *Compiler {
	return &Compiler{
		peerResolver: peerResolver{
			identityAllocator: identityAllocator,
			logger:            logger,
		},
	}
}

// SetPortResolver sets the function used to resolve named ports to numbers.
func (c *Compiler) SetPortResolver(resolver PortResolver) {
	c.portResolver = resolver
}

// SetNamespaceResolver sets the function used to resolve namespace selectors
// to namespace names. Without this, only kubernetes.io/metadata.name selectors
// are supported; other namespace selectors produce deterministic fallback hashes.
func (c *Compiler) SetNamespaceResolver(resolver NamespaceResolver) {
	c.namespaceResolver = resolver
}

// CompilePolicy compiles a single NetworkPolicy into a list of compiled rules.
func (c *Compiler) CompilePolicy(np *networkingv1.NetworkPolicy) []*CompiledRule {
	if np == nil {
		return nil
	}

	var rules []*CompiledRule

	// Determine the identities of pods selected by this policy.
	// A selector may match multiple distinct identities (pods with different
	// label supersets all containing the selector labels).
	targetIdentities := c.selectorToIdentities(np.Spec.PodSelector, np.Namespace)

	for _, targetID := range targetIdentities {
		// Process ingress rules.
		if hasPolicyType(np, networkingv1.PolicyTypeIngress) {
			if len(np.Spec.Ingress) == 0 {
				// Default deny ingress: deny all traffic to selected pods.
				rules = append(rules, &CompiledRule{
					SrcIdentity: WildcardIdentity,
					DstIdentity: targetID,
					Protocol:    ProtocolAny,
					DstPort:     0,
					Action:      ActionDeny,
					Namespace:   np.Namespace,
				})
			} else {
				for _, ingressRule := range np.Spec.Ingress {
					rules = append(rules, c.compileIngressRule(ingressRule, targetID, np.Namespace, np.Spec.PodSelector)...)
				}
			}
		}

		// Process egress rules.
		if hasPolicyType(np, networkingv1.PolicyTypeEgress) {
			if len(np.Spec.Egress) == 0 {
				// Default deny egress: deny all traffic from selected pods.
				rules = append(rules, &CompiledRule{
					SrcIdentity: targetID,
					DstIdentity: WildcardIdentity,
					Protocol:    ProtocolAny,
					DstPort:     0,
					Action:      ActionDeny,
					Namespace:   np.Namespace,
				})
			} else {
				for _, egressRule := range np.Spec.Egress {
					rules = append(rules, c.compileEgressRule(egressRule, targetID, np.Namespace)...)
				}
			}
		}
	}

	c.logger.Debug("compiled policy",
		zap.String("namespace", np.Namespace),
		zap.String("name", np.Name),
		zap.Int("rule_count", len(rules)),
	)

	return rules
}

// CompileAll compiles all NetworkPolicies into a combined list of rules.
func (c *Compiler) CompileAll(policies []*networkingv1.NetworkPolicy) []*CompiledRule {
	allRules := make([]*CompiledRule, 0, len(policies))
	for _, np := range policies {
		allRules = append(allRules, c.CompilePolicy(np)...)
	}
	return allRules
}

// compileIngressRule compiles a single ingress rule for the target identity.
func (c *Compiler) compileIngressRule(rule networkingv1.NetworkPolicyIngressRule, dstIdentity uint64, namespace string, podSelector metav1.LabelSelector) []*CompiledRule {
	// Resolve source identities from peers.
	srcIdentities := c.resolvePeers(rule.From, namespace)
	// Resolve IPBlock CIDRs.
	srcCIDRs := c.resolvePeersWithIPBlock(rule.From)

	rules := make([]*CompiledRule, 0, len(srcIdentities)+len(srcCIDRs))

	// Resolve ports (named ports resolve against the target pods).
	ports := c.resolvePorts(rule.Ports, namespace, podSelector)

	// If no peers specified, allow from any source.
	if len(rule.From) == 0 {
		srcIdentities = []uint64{WildcardIdentity}
	}

	// If no ports specified, allow all ports.
	if len(ports) == 0 {
		ports = []portProto{{protocol: ProtocolAny, port: 0}}
	}

	// Create cartesian product of sources x ports (identity-based).
	rules = append(rules, buildIdentityRules(srcIdentities, dstIdentity, ports, false, namespace)...)

	// Create CIDR-based rules for IPBlock peers (including Except deny rules).
	rules = append(rules, buildCIDRRules(srcCIDRs, dstIdentity, ports, false, namespace)...)

	return rules
}

// compileEgressRule compiles a single egress rule for the source identity.
func (c *Compiler) compileEgressRule(rule networkingv1.NetworkPolicyEgressRule, srcIdentity uint64, namespace string) []*CompiledRule {
	// Resolve destination identities from peers.
	dstIdentities := c.resolvePeers(rule.To, namespace)
	// Resolve IPBlock CIDRs.
	dstCIDRs := c.resolvePeersWithIPBlock(rule.To)

	rules := make([]*CompiledRule, 0, len(dstIdentities)+len(dstCIDRs))

	// Resolve ports. For egress, named ports are on the destination pods,
	// but we don't know which pods those are, so use numeric only.
	ports := c.resolvePorts(rule.Ports, namespace, metav1.LabelSelector{})

	// If no peers specified, allow to any destination.
	if len(rule.To) == 0 {
		dstIdentities = []uint64{WildcardIdentity}
	}

	// If no ports specified, allow all ports.
	if len(ports) == 0 {
		ports = []portProto{{protocol: ProtocolAny, port: 0}}
	}

	// Create cartesian product of destinations x ports (identity-based).
	rules = append(rules, buildIdentityRules(dstIdentities, srcIdentity, ports, true, namespace)...)

	// Create CIDR-based rules for IPBlock peers (including Except deny rules).
	rules = append(rules, buildCIDRRules(dstCIDRs, srcIdentity, ports, true, namespace)...)

	return rules
}

// cidrEntry represents a CIDR from an IPBlock with an associated action.
// The primary CIDR gets ActionAllow while Except CIDRs get ActionDeny.
type cidrEntry struct {
	cidr   string
	action uint8 // ActionAllow or ActionDeny
}

// portProto combines a protocol and port for rule generation.
type portProto struct {
	protocol uint8
	port     uint16
}

// resolvePeers converts NetworkPolicyPeer selectors to identity IDs.
// Supports both MatchLabels and MatchExpressions for pod and namespace selectors.
// It matches against actually allocated identities when possible, falling
// back to hashing the selector labels when no matching identities exist yet.
func (c *Compiler) resolvePeers(peers []networkingv1.NetworkPolicyPeer, namespace string) []uint64 {
	var identities []uint64

	for _, peer := range peers {
		if peer.IPBlock != nil {
			continue
		}
		identities = append(identities, c.resolvePodAndNsPeers(
			peer.PodSelector, peer.NamespaceSelector, namespace,
		)...)
	}

	return identities
}

// resolvePeersWithIPBlock returns IPBlock CIDRs from peers (for CIDR-based rules).
// The primary CIDR is returned with ActionAllow, and any Except CIDRs are
// returned with ActionDeny so callers can create corresponding deny rules.
func (c *Compiler) resolvePeersWithIPBlock(peers []networkingv1.NetworkPolicyPeer) []cidrEntry {
	var entries []cidrEntry
	for _, peer := range peers {
		if peer.IPBlock == nil {
			continue
		}
		entries = append(entries, resolveIPBlockCIDRs(
			peer.IPBlock.CIDR, peer.IPBlock.Except, c.logger,
		)...)
	}
	return entries
}

// resolvePorts converts NetworkPolicyPort to portProto pairs.
// Handles both numeric and named ports. Named ports are resolved using the
// PortResolver against pods matching the given selector.
func (c *Compiler) resolvePorts(npPorts []networkingv1.NetworkPolicyPort, namespace string, podSelector metav1.LabelSelector) []portProto {
	var ports []portProto

	for _, p := range npPorts {
		proto := ProtocolTCP // Default protocol is TCP.
		if p.Protocol != nil {
			switch *p.Protocol {
			case corev1.ProtocolTCP:
				proto = ProtocolTCP
			case corev1.ProtocolUDP:
				proto = ProtocolUDP
			case corev1.ProtocolSCTP:
				proto = ProtocolSCTP
			}
		}

		if p.Port != nil && p.Port.Type == intstr.String {
			// Named port — resolve to numeric port(s) via the PortResolver.
			portName := p.Port.StrVal
			coreProto := corev1.ProtocolTCP
			if p.Protocol != nil {
				coreProto = *p.Protocol
			}
			if c.portResolver != nil {
				resolved := c.portResolver(portName, coreProto, namespace, podSelector)
				for _, rp := range resolved {
					ports = append(ports, portProto{protocol: proto, port: rp})
				}
				if len(resolved) > 0 {
					continue
				}
			}
			c.logger.Warn("unable to resolve named port, skipping",
				zap.String("port_name", portName))
			continue
		}

		var port uint16
		if p.Port != nil {
			pv := p.Port.IntValue()
			if pv > 0 && pv <= math.MaxUint16 {
				port = uint16(pv & math.MaxUint16)
			}
		}

		ports = append(ports, portProto{
			protocol: proto,
			port:     port,
		})
	}

	return ports
}

// hasPolicyType checks if a NetworkPolicy specifies a given policy type.
// If no policy types are specified, Ingress is assumed per the Kubernetes spec.
func hasPolicyType(np *networkingv1.NetworkPolicy, pt networkingv1.PolicyType) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		// Default: only Ingress.
		return pt == networkingv1.PolicyTypeIngress
	}
	return slices.Contains(np.Spec.PolicyTypes, pt)
}
