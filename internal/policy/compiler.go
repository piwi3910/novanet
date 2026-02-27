// Package policy compiles Kubernetes NetworkPolicy objects into identity-based
// rules suitable for the eBPF dataplane.
package policy

import (
	"maps"
	"net"
	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

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
	portResolver      PortResolver
	namespaceResolver NamespaceResolver
	logger            *zap.Logger
}

// NewCompiler creates a new policy compiler.
func NewCompiler(identityAllocator *identity.Allocator, logger *zap.Logger) *Compiler {
	return &Compiler{
		identityAllocator: identityAllocator,
		logger:            logger,
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
	var allRules []*CompiledRule
	for _, np := range policies {
		allRules = append(allRules, c.CompilePolicy(np)...)
	}
	return allRules
}

// compileIngressRule compiles a single ingress rule for the target identity.
func (c *Compiler) compileIngressRule(rule networkingv1.NetworkPolicyIngressRule, dstIdentity uint32, namespace string, podSelector metav1.LabelSelector) []*CompiledRule {
	var rules []*CompiledRule

	// Resolve source identities from peers.
	srcIdentities := c.resolvePeers(rule.From, namespace)
	// Resolve IPBlock CIDRs.
	srcCIDRs := c.resolvePeersWithIPBlock(rule.From)

	// Resolve ports (named ports resolve against the target pods).
	ports := c.resolvePorts(rule.Ports, namespace, podSelector)

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

	// Resolve ports. For egress, named ports are on the destination pods,
	// but we don't know which pods those are, so use numeric only.
	ports := c.resolvePorts(rule.Ports, namespace, metav1.LabelSelector{})

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
// Supports both MatchLabels and MatchExpressions for pod and namespace selectors.
// It matches against actually allocated identities when possible, falling
// back to hashing the selector labels when no matching identities exist yet.
func (c *Compiler) resolvePeers(peers []networkingv1.NetworkPolicyPeer, namespace string) []uint32 {
	var identities []uint32

	for _, peer := range peers {
		if peer.IPBlock != nil {
			continue
		}

		if peer.PodSelector == nil && peer.NamespaceSelector == nil {
			identities = append(identities, WildcardIdentity)
			continue
		}

		// Build the pod selector part.
		podSelector := metav1.LabelSelector{}
		if peer.PodSelector != nil {
			podSelector = *peer.PodSelector.DeepCopy()
		}

		if peer.NamespaceSelector != nil {
			nsSel := peer.NamespaceSelector
			if len(nsSel.MatchLabels) == 0 && len(nsSel.MatchExpressions) == 0 {
				// Empty namespace selector = all namespaces.
				if len(podSelector.MatchLabels) == 0 && len(podSelector.MatchExpressions) == 0 {
					identities = append(identities, WildcardIdentity)
				} else {
					identities = append(identities, c.findOrFallback(podSelector)...)
				}
			} else {
				// Non-empty namespace selector. Resolve to namespace names.
				nsNames := c.resolveNamespaceNames(nsSel)
				if len(nsNames) > 0 {
					for _, nsName := range nsNames {
						scoped := podSelector.DeepCopy()
						if scoped.MatchLabels == nil {
							scoped.MatchLabels = make(map[string]string)
						}
						scoped.MatchLabels["novanet.io/namespace"] = nsName
						identities = append(identities, c.findOrFallback(*scoped)...)
					}
				} else {
					// Cannot resolve namespace names. Create a deterministic
					// fallback hash from combined pod + namespace matchLabels.
					fallback := make(map[string]string)
					maps.Copy(fallback, podSelector.MatchLabels)
					for k, v := range nsSel.MatchLabels {
						fallback["ns."+k] = v
					}
					identities = append(identities, identity.HashLabels(fallback))
				}
			}
		} else {
			// No namespace selector — scope to the policy's namespace.
			if podSelector.MatchLabels == nil {
				podSelector.MatchLabels = make(map[string]string)
			}
			podSelector.MatchLabels["novanet.io/namespace"] = namespace
			identities = append(identities, c.findOrFallback(podSelector)...)
		}
	}

	return identities
}

// findOrFallback finds allocated identities matching the selector, or falls
// back to hashing the MatchLabels if no matches exist yet.
func (c *Compiler) findOrFallback(selector metav1.LabelSelector) []uint32 {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		c.logger.Warn("invalid peer label selector, skipping", zap.Error(err))
		return nil
	}
	matches := c.identityAllocator.FindMatchingIdentities(sel)
	if len(matches) > 0 {
		return matches
	}
	// Fallback: hash MatchLabels as placeholder.
	fallback := make(map[string]string)
	maps.Copy(fallback, selector.MatchLabels)
	return []uint32{identity.HashLabels(fallback)}
}

// resolveNamespaceNames resolves a namespace label selector to namespace names.
func (c *Compiler) resolveNamespaceNames(nsSel *metav1.LabelSelector) []string {
	// Direct resolution: kubernetes.io/metadata.name is the namespace name.
	if name, ok := nsSel.MatchLabels["kubernetes.io/metadata.name"]; ok {
		return []string{name}
	}
	// Use the NamespaceResolver callback if available.
	if c.namespaceResolver != nil {
		return c.namespaceResolver(*nsSel)
	}
	return nil
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
// Handles both numeric and named ports. Named ports are resolved using the
// PortResolver against pods matching the given selector.
func (c *Compiler) resolvePorts(npPorts []networkingv1.NetworkPolicyPort, namespace string, podSelector metav1.LabelSelector) []portProto {
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
// It finds all allocated identities whose labels match the selector (including
// MatchExpressions), falling back to hashing the MatchLabels if no matches exist yet.
func (c *Compiler) selectorToIdentities(selector metav1.LabelSelector, namespace string) []uint32 {
	// Clone and add namespace scoping.
	scoped := selector.DeepCopy()
	if scoped.MatchLabels == nil {
		scoped.MatchLabels = make(map[string]string)
	}
	scoped.MatchLabels["novanet.io/namespace"] = namespace

	// Convert to labels.Selector for full MatchLabels + MatchExpressions support.
	sel, err := metav1.LabelSelectorAsSelector(scoped)
	if err != nil {
		c.logger.Warn("invalid pod selector", zap.Error(err))
		return []uint32{WildcardIdentity}
	}

	// Find allocated identities that match.
	matches := c.identityAllocator.FindMatchingIdentities(sel)
	if len(matches) > 0 {
		return matches
	}

	// Fallback: no matching identities yet. Use hash of MatchLabels so
	// rules exist as placeholders until matching pods are created.
	return []uint32{identity.HashLabels(scoped.MatchLabels)}
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
