package policy

import (
	"fmt"
	"math"
	"slices"

	"go.uber.org/zap"

	"github.com/azrtydxb/novanet/api/v1alpha1"
	"github.com/azrtydxb/novanet/internal/identity"
)

// Protocol string constants used in NovaNetworkPolicyPort.
const (
	protocolStrTCP  = "TCP"
	protocolStrUDP  = "UDP"
	protocolStrSCTP = "SCTP"
)

// maxExpandablePortRange is the maximum port range size that will be expanded
// into individual per-port rules. Ranges larger than this use DstPort=0 to
// avoid generating an excessive number of rules.
const maxExpandablePortRange = 100

// ExtendedCompiler compiles NovaNetworkPolicy CRDs into CompiledRule entries.
// It supports all features of the standard compiler plus port ranges, FQDN
// peers, and ServiceAccount peers.
type ExtendedCompiler struct {
	peerResolver
	portResolver PortResolver
	dnsCache     *DNSCache
}

// NewExtendedCompiler creates a new extended policy compiler.
func NewExtendedCompiler(identityAllocator *identity.Allocator, logger *zap.Logger) *ExtendedCompiler {
	return &ExtendedCompiler{
		peerResolver: peerResolver{
			identityAllocator: identityAllocator,
			logger:            logger,
		},
		dnsCache: NewDNSCache(logger, defaultMaxEntries),
	}
}

// SetPortResolver sets the function used to resolve named ports to numbers.
func (c *ExtendedCompiler) SetPortResolver(resolver PortResolver) {
	c.portResolver = resolver
}

// SetNamespaceResolver sets the function used to resolve namespace selectors
// to namespace names.
func (c *ExtendedCompiler) SetNamespaceResolver(resolver NamespaceResolver) {
	c.namespaceResolver = resolver
}

// SetDNSCache replaces the default DNS cache with a custom one (useful for testing).
func (c *ExtendedCompiler) SetDNSCache(cache *DNSCache) {
	c.dnsCache = cache
}

// CompilePolicy compiles a single NovaNetworkPolicy into a list of compiled rules.
func (c *ExtendedCompiler) CompilePolicy(nnp *v1alpha1.NovaNetworkPolicy) []*CompiledRule {
	if nnp == nil {
		return nil
	}

	var rules []*CompiledRule

	targetIdentities := c.selectorToIdentities(nnp.Spec.PodSelector, nnp.Namespace)

	for _, targetID := range targetIdentities {
		// Process ingress rules.
		if hasExtendedPolicyType(nnp, v1alpha1.PolicyTypeIngress) {
			if len(nnp.Spec.Ingress) == 0 {
				rules = append(rules, &CompiledRule{
					SrcIdentity: WildcardIdentity,
					DstIdentity: targetID,
					Protocol:    ProtocolAny,
					DstPort:     0,
					Action:      ActionDeny,
					Namespace:   nnp.Namespace,
				})
			} else {
				for _, ingressRule := range nnp.Spec.Ingress {
					rules = append(rules, c.compileIngressRule(ingressRule, targetID, nnp.Namespace)...)
				}
			}
		}

		// Process egress rules.
		if hasExtendedPolicyType(nnp, v1alpha1.PolicyTypeEgress) {
			if len(nnp.Spec.Egress) == 0 {
				rules = append(rules, &CompiledRule{
					SrcIdentity: targetID,
					DstIdentity: WildcardIdentity,
					Protocol:    ProtocolAny,
					DstPort:     0,
					Action:      ActionDeny,
					IsEgress:    true,
					Namespace:   nnp.Namespace,
				})
			} else {
				for _, egressRule := range nnp.Spec.Egress {
					rules = append(rules, c.compileEgressRule(egressRule, targetID, nnp.Namespace)...)
				}
			}
		}
	}

	c.logger.Debug("compiled extended policy",
		zap.String("namespace", nnp.Namespace),
		zap.String("name", nnp.Name),
		zap.Int("rule_count", len(rules)),
	)

	return rules
}

// CompileAll compiles all NovaNetworkPolicies into a combined list of rules.
func (c *ExtendedCompiler) CompileAll(policies []*v1alpha1.NovaNetworkPolicy) []*CompiledRule {
	allRules := make([]*CompiledRule, 0, len(policies))
	for _, nnp := range policies {
		allRules = append(allRules, c.CompilePolicy(nnp)...)
	}
	return allRules
}

// compileIngressRule compiles a single extended ingress rule for the target identity.
func (c *ExtendedCompiler) compileIngressRule(rule v1alpha1.NovaNetworkPolicyIngressRule, dstIdentity uint64, namespace string) []*CompiledRule {
	return c.compileDirectionalRule(rule.From, rule.Ports, dstIdentity, false, namespace)
}

// compileEgressRule compiles a single extended egress rule for the source identity.
func (c *ExtendedCompiler) compileEgressRule(rule v1alpha1.NovaNetworkPolicyEgressRule, srcIdentity uint64, namespace string) []*CompiledRule {
	return c.compileDirectionalRule(rule.To, rule.Ports, srcIdentity, true, namespace)
}

// compileDirectionalRule is the shared implementation for both ingress and egress
// rule compilation. The peers parameter is the From (ingress) or To (egress) list,
// fixedID is the target identity, and isEgress controls direction assignment.
func (c *ExtendedCompiler) compileDirectionalRule(
	peers []v1alpha1.NovaNetworkPolicyPeer,
	nnpPorts []v1alpha1.NovaNetworkPolicyPort,
	fixedID uint64,
	isEgress bool,
	namespace string,
) []*CompiledRule {
	identities := c.resolveExtendedPeers(peers, namespace)
	cidrEntries := c.resolveExtendedCIDRs(peers)
	fqdnCIDRs := c.resolveFQDNPeers(peers)

	rules := make([]*CompiledRule, 0, len(identities)+len(cidrEntries)+len(fqdnCIDRs))

	ports := c.resolveExtendedPorts(nnpPorts)

	if len(peers) == 0 {
		identities = []uint64{WildcardIdentity}
	}

	if len(ports) == 0 {
		ports = []portProto{{protocol: ProtocolAny, port: 0}}
	}

	// Identity-based rules.
	rules = append(rules, buildIdentityRules(identities, fixedID, ports, isEgress, namespace)...)

	// CIDR-based rules from IPBlock peers.
	rules = append(rules, buildCIDRRules(cidrEntries, fixedID, ports, isEgress, namespace)...)

	// CIDR-based rules from FQDN peers.
	rules = append(rules, buildFQDNCIDRRules(fqdnCIDRs, fixedID, ports, isEgress, namespace)...)

	return rules
}

// resolveExtendedPeers converts NovaNetworkPolicyPeer selectors to identity IDs.
// Handles PodSelector, NamespaceSelector, and ServiceAccount peers.
func (c *ExtendedCompiler) resolveExtendedPeers(peers []v1alpha1.NovaNetworkPolicyPeer, namespace string) []uint64 {
	var identities []uint64

	for _, peer := range peers {
		if peer.IPBlock != nil || peer.FQDN != nil {
			continue
		}

		if peer.ServiceAccount != nil {
			identities = append(identities, c.resolveServiceAccountPeer(peer.ServiceAccount, namespace))
			continue
		}

		identities = append(identities, c.resolvePodAndNsPeers(
			peer.PodSelector, peer.NamespaceSelector, namespace,
		)...)
	}

	return identities
}

// resolveServiceAccountPeer translates a ServiceAccount peer into an identity
// by constructing a label selector that matches pods with the given SA.
func (c *ExtendedCompiler) resolveServiceAccountPeer(sa *v1alpha1.ServiceAccountPeer, policyNamespace string) uint64 {
	ns := sa.Namespace
	if ns == "" {
		ns = policyNamespace
	}
	labels := map[string]string{
		"novanet.io/namespace":       ns,
		"novanet.io/service-account": sa.Name,
	}
	return identity.HashLabels(labels)
}

// resolveExtendedCIDRs extracts IPBlock CIDRs from extended peers.
func (c *ExtendedCompiler) resolveExtendedCIDRs(peers []v1alpha1.NovaNetworkPolicyPeer) []cidrEntry {
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

// resolveFQDNPeers resolves FQDN peers to CIDR strings (one /32 or /128 per IP).
func (c *ExtendedCompiler) resolveFQDNPeers(peers []v1alpha1.NovaNetworkPolicyPeer) []string {
	var cidrs []string
	for _, peer := range peers {
		if peer.FQDN == nil {
			continue
		}
		ips := c.dnsCache.Resolve(*peer.FQDN)
		for _, ip := range ips {
			if ip.To4() != nil {
				cidrs = append(cidrs, fmt.Sprintf("%s/32", ip.String()))
			} else {
				cidrs = append(cidrs, fmt.Sprintf("%s/128", ip.String()))
			}
		}
	}
	return cidrs
}

// resolveExtendedPorts converts NovaNetworkPolicyPort to portProto pairs,
// handling port ranges.
func (c *ExtendedCompiler) resolveExtendedPorts(nnpPorts []v1alpha1.NovaNetworkPolicyPort) []portProto {
	var ports []portProto

	for _, p := range nnpPorts {
		proto := ProtocolTCP
		if p.Protocol != nil {
			switch *p.Protocol {
			case protocolStrTCP:
				proto = ProtocolTCP
			case protocolStrUDP:
				proto = ProtocolUDP
			case protocolStrSCTP:
				proto = ProtocolSCTP
			}
		}

		if p.Port == nil {
			ports = append(ports, portProto{protocol: proto, port: 0})
			continue
		}

		portVal := *p.Port
		if portVal < 0 || portVal > math.MaxUint16 {
			continue
		}
		startPort := uint16(portVal & math.MaxUint16)

		if p.EndPort == nil {
			ports = append(ports, portProto{protocol: proto, port: startPort})
			continue
		}

		endPortVal := *p.EndPort
		if endPortVal < 0 || endPortVal > math.MaxUint16 {
			continue
		}
		endPort := uint16(endPortVal & math.MaxUint16)
		rangeSize := int(endPort) - int(startPort) + 1

		if rangeSize <= 0 {
			c.logger.Warn("invalid port range (endPort < port), skipping",
				zap.Int32("port", *p.Port),
				zap.Int32("end_port", *p.EndPort),
			)
			continue
		}

		if rangeSize > maxExpandablePortRange {
			// Large range: use DstPort=0 (any port) as approximation.
			c.logger.Info("port range too large to expand, using wildcard port",
				zap.Int32("port", *p.Port),
				zap.Int32("end_port", *p.EndPort),
				zap.Int("range_size", rangeSize),
			)
			ports = append(ports, portProto{protocol: proto, port: 0})
			continue
		}

		// Small range: expand to individual per-port rules.
		for port := startPort; port <= endPort; port++ {
			ports = append(ports, portProto{protocol: proto, port: port})
		}
	}

	return ports
}

// hasExtendedPolicyType checks if a NovaNetworkPolicy specifies a given policy type.
// If no policy types are specified, Ingress is assumed.
func hasExtendedPolicyType(nnp *v1alpha1.NovaNetworkPolicy, pt v1alpha1.PolicyType) bool {
	if len(nnp.Spec.PolicyTypes) == 0 {
		return pt == v1alpha1.PolicyTypeIngress
	}
	return slices.Contains(nnp.Spec.PolicyTypes, pt)
}
