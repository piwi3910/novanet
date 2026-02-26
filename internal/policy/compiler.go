// Package policy compiles Kubernetes NetworkPolicy objects into identity-based
// rules suitable for the eBPF dataplane.
package policy

import (
	"maps"
	"net"
	"slices"

	"go.uber.org/zap"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/piwi3910/novanet/internal/identity"
)

// Action constants for compiled rules.
const (
	ActionDeny  uint8 = 0
	ActionAllow uint8 = 1
)

// Protocol constants.
const (
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
	ProtocolSCTP uint8 = 132
	ProtocolAny  uint8 = 0
)

// WildcardIdentity matches any identity in a rule (used for open selectors).
const WildcardIdentity uint32 = 0

// CompiledRule represents a single policy rule ready for the dataplane.
type CompiledRule struct {
	// SrcIdentity is the source identity ID (0 = wildcard/any).
	SrcIdentity uint32
	// DstIdentity is the destination identity ID (0 = wildcard/any).
	DstIdentity uint32
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
	identityAllocator *identity.Allocator
	logger            *zap.Logger
}

// NewCompiler creates a new policy compiler.
func NewCompiler(identityAllocator *identity.Allocator, logger *zap.Logger) *Compiler {
	return &Compiler{
		identityAllocator: identityAllocator,
		logger:            logger,
	}
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
					rules = append(rules, c.compileIngressRule(ingressRule, targetID, np.Namespace)...)
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
	var allRules []*CompiledRule
	for _, np := range policies {
		allRules = append(allRules, c.CompilePolicy(np)...)
	}
	return allRules
}

// compileIngressRule compiles a single ingress rule for the target identity.
func (c *Compiler) compileIngressRule(rule networkingv1.NetworkPolicyIngressRule, dstIdentity uint32, namespace string) []*CompiledRule {
	var rules []*CompiledRule

	// Resolve source identities from peers.
	srcIdentities := c.resolvePeers(rule.From, namespace)
	// Resolve IPBlock CIDRs.
	srcCIDRs := c.resolvePeersWithIPBlock(rule.From)

	// Resolve ports.
	ports := c.resolvePorts(rule.Ports)

	// If no peers specified, allow from any source.
	if len(rule.From) == 0 {
		srcIdentities = []uint32{WildcardIdentity}
	}

	// If no ports specified, allow all ports.
	if len(ports) == 0 {
		ports = []portProto{{protocol: ProtocolAny, port: 0}}
	}

	// Create cartesian product of sources x ports (identity-based).
	for _, srcID := range srcIdentities {
		for _, pp := range ports {
			rules = append(rules, &CompiledRule{
				SrcIdentity: srcID,
				DstIdentity: dstIdentity,
				Protocol:    pp.protocol,
				DstPort:     pp.port,
				Action:      ActionAllow,
				Namespace:   namespace,
			})
		}
	}

	// Create CIDR-based rules for IPBlock peers (including Except deny rules).
	for _, entry := range srcCIDRs {
		for _, pp := range ports {
			rules = append(rules, &CompiledRule{
				SrcIdentity: WildcardIdentity,
				DstIdentity: dstIdentity,
				Protocol:    pp.protocol,
				DstPort:     pp.port,
				Action:      entry.action,
				CIDR:        entry.cidr,
				Namespace:   namespace,
			})
		}
	}

	return rules
}

// compileEgressRule compiles a single egress rule for the source identity.
func (c *Compiler) compileEgressRule(rule networkingv1.NetworkPolicyEgressRule, srcIdentity uint32, namespace string) []*CompiledRule {
	var rules []*CompiledRule

	// Resolve destination identities from peers.
	dstIdentities := c.resolvePeers(rule.To, namespace)
	// Resolve IPBlock CIDRs.
	dstCIDRs := c.resolvePeersWithIPBlock(rule.To)

	// Resolve ports.
	ports := c.resolvePorts(rule.Ports)

	// If no peers specified, allow to any destination.
	if len(rule.To) == 0 {
		dstIdentities = []uint32{WildcardIdentity}
	}

	// If no ports specified, allow all ports.
	if len(ports) == 0 {
		ports = []portProto{{protocol: ProtocolAny, port: 0}}
	}

	// Create cartesian product of destinations x ports (identity-based).
	for _, dstID := range dstIdentities {
		for _, pp := range ports {
			rules = append(rules, &CompiledRule{
				SrcIdentity: srcIdentity,
				DstIdentity: dstID,
				Protocol:    pp.protocol,
				DstPort:     pp.port,
				Action:      ActionAllow,
				IsEgress:    true,
				Namespace:   namespace,
			})
		}
	}

	// Create CIDR-based rules for IPBlock peers (including Except deny rules).
	for _, entry := range dstCIDRs {
		for _, pp := range ports {
			rules = append(rules, &CompiledRule{
				SrcIdentity: srcIdentity,
				DstIdentity: WildcardIdentity,
				Protocol:    pp.protocol,
				DstPort:     pp.port,
				Action:      entry.action,
				CIDR:        entry.cidr,
				IsEgress:    true,
				Namespace:   namespace,
			})
		}
	}

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
// It matches against actually allocated identities when possible, falling
// back to hashing the selector labels when no matching identities exist yet.
func (c *Compiler) resolvePeers(peers []networkingv1.NetworkPolicyPeer, namespace string) []uint32 {
	var identities []uint32

	for _, peer := range peers {
		if peer.IPBlock != nil {
			// IPBlock rules are handled separately via resolvePeersWithIPBlock.
			continue
		}

		// Build label set from selectors.
		labels := make(map[string]string)

		if peer.PodSelector != nil {
			maps.Copy(labels, peer.PodSelector.MatchLabels)
		}

		if peer.NamespaceSelector != nil {
			// Encode namespace selector labels with a prefix to distinguish them.
			for k, v := range peer.NamespaceSelector.MatchLabels {
				labels["ns:"+k] = v
			}
		} else if peer.PodSelector != nil {
			// If only podSelector is specified, scope to the policy's namespace.
			labels["ns:kubernetes.io/metadata.name"] = namespace
		}

		if len(labels) > 0 {
			// Find allocated identities whose labels are a superset of the selector.
			matches := c.identityAllocator.FindMatchingIdentities(labels)
			if len(matches) > 0 {
				identities = append(identities, matches...)
			} else {
				// Fallback: no matching identities yet. Use hash of selector labels
				// so rules are ready when matching pods are created.
				identities = append(identities, identity.HashLabels(labels))
			}
		} else {
			// Empty selector matches everything.
			identities = append(identities, WildcardIdentity)
		}
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
		// Validate primary CIDR.
		_, _, err := net.ParseCIDR(peer.IPBlock.CIDR)
		if err != nil {
			c.logger.Warn("invalid IPBlock CIDR, skipping",
				zap.String("cidr", peer.IPBlock.CIDR),
				zap.Error(err),
			)
			continue
		}
		entries = append(entries, cidrEntry{cidr: peer.IPBlock.CIDR, action: ActionAllow})

		// Generate deny entries for IPBlock.Except CIDRs. These must be
		// evaluated before the allow rule (more-specific prefix wins in LPM).
		for _, exceptCIDR := range peer.IPBlock.Except {
			_, _, err := net.ParseCIDR(exceptCIDR)
			if err != nil {
				c.logger.Warn("invalid IPBlock.Except CIDR, skipping",
					zap.String("except_cidr", exceptCIDR),
					zap.Error(err),
				)
				continue
			}
			entries = append(entries, cidrEntry{cidr: exceptCIDR, action: ActionDeny})
		}
	}
	return entries
}

// resolvePorts converts NetworkPolicyPort to portProto pairs.
func (c *Compiler) resolvePorts(npPorts []networkingv1.NetworkPolicyPort) []portProto {
	var ports []portProto

	for _, p := range npPorts {
		proto := ProtocolTCP // Default protocol is TCP.
		if p.Protocol != nil {
			switch *p.Protocol {
			case "TCP":
				proto = ProtocolTCP
			case "UDP":
				proto = ProtocolUDP
			case "SCTP":
				proto = ProtocolSCTP
			}
		}

		var port uint16
		if p.Port != nil {
			port = uint16(p.Port.IntValue())
		}

		ports = append(ports, portProto{
			protocol: proto,
			port:     port,
		})
	}

	return ports
}

// selectorToIdentities converts a LabelSelector plus namespace into identity IDs.
// It finds all allocated identities whose labels are a superset of the selector,
// falling back to hashing the selector labels if no matches exist yet.
func (c *Compiler) selectorToIdentities(selector metav1.LabelSelector, namespace string) []uint32 {
	labels := make(map[string]string)
	maps.Copy(labels, selector.MatchLabels)
	// Always scope to the policy namespace.
	labels["ns:kubernetes.io/metadata.name"] = namespace

	// Find allocated identities that match (their labels contain all selector labels).
	matches := c.identityAllocator.FindMatchingIdentities(labels)
	if len(matches) > 0 {
		return matches
	}

	// Fallback: no matching identities yet. Use hash of selector labels so
	// rules exist as placeholders until matching pods are created.
	return []uint32{identity.HashLabels(labels)}
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
