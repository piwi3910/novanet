package policy

import (
	"maps"
	"net"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/azrtydxb/novanet/internal/identity"
)

// peerResolver provides shared peer resolution logic used by both the standard
// Compiler and the ExtendedCompiler. It avoids code duplication (dupl) between
// the two compilers for identity resolution, namespace resolution, and CIDR
// extraction.
type peerResolver struct {
	identityAllocator *identity.Allocator
	namespaceResolver NamespaceResolver
	logger            *zap.Logger
}

// selectorToIdentities converts a LabelSelector plus namespace into identity IDs.
// It finds all allocated identities whose labels match the selector (including
// MatchExpressions), falling back to hashing the MatchLabels if no matches exist yet.
func (r *peerResolver) selectorToIdentities(selector metav1.LabelSelector, namespace string) []uint64 {
	scoped := selector.DeepCopy()
	if scoped.MatchLabels == nil {
		scoped.MatchLabels = make(map[string]string)
	}
	scoped.MatchLabels["novanet.io/namespace"] = namespace

	sel, err := metav1.LabelSelectorAsSelector(scoped)
	if err != nil {
		r.logger.Warn("invalid pod selector", zap.Error(err))
		return []uint64{WildcardIdentity}
	}

	matches := r.identityAllocator.FindMatchingIdentities(sel)
	if len(matches) > 0 {
		return matches
	}

	return []uint64{identity.HashLabels(scoped.MatchLabels)}
}

// findOrFallback finds allocated identities matching the selector, or falls
// back to hashing the MatchLabels if no matches exist yet.
func (r *peerResolver) findOrFallback(selector metav1.LabelSelector) []uint64 {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		r.logger.Warn("invalid peer label selector, skipping", zap.Error(err))
		return nil
	}
	matches := r.identityAllocator.FindMatchingIdentities(sel)
	if len(matches) > 0 {
		return matches
	}
	fallback := make(map[string]string)
	maps.Copy(fallback, selector.MatchLabels)
	return []uint64{identity.HashLabels(fallback)}
}

// resolveNamespaceNames resolves a namespace label selector to namespace names.
func (r *peerResolver) resolveNamespaceNames(nsSel *metav1.LabelSelector) []string {
	if name, ok := nsSel.MatchLabels["kubernetes.io/metadata.name"]; ok {
		return []string{name}
	}
	if r.namespaceResolver != nil {
		return r.namespaceResolver(*nsSel)
	}
	return nil
}

// resolvePodAndNsPeers resolves pod/namespace selector peers to identity IDs.
// This is the common logic shared between Compiler.resolvePeers and
// ExtendedCompiler.resolveExtendedPeers.
func (r *peerResolver) resolvePodAndNsPeers(
	podSel *metav1.LabelSelector,
	nsSel *metav1.LabelSelector,
	namespace string,
) []uint64 {
	if podSel == nil && nsSel == nil {
		return []uint64{WildcardIdentity}
	}

	podSelector := metav1.LabelSelector{}
	if podSel != nil {
		podSelector = *podSel.DeepCopy()
	}

	if nsSel != nil {
		if len(nsSel.MatchLabels) == 0 && len(nsSel.MatchExpressions) == 0 {
			if len(podSelector.MatchLabels) == 0 && len(podSelector.MatchExpressions) == 0 {
				return []uint64{WildcardIdentity}
			}
			return r.findOrFallback(podSelector)
		}

		nsNames := r.resolveNamespaceNames(nsSel)
		if len(nsNames) > 0 {
			var identities []uint64
			for _, nsName := range nsNames {
				scoped := podSelector.DeepCopy()
				if scoped.MatchLabels == nil {
					scoped.MatchLabels = make(map[string]string)
				}
				scoped.MatchLabels["novanet.io/namespace"] = nsName
				identities = append(identities, r.findOrFallback(*scoped)...)
			}
			return identities
		}

		fallback := make(map[string]string)
		maps.Copy(fallback, podSelector.MatchLabels)
		for k, v := range nsSel.MatchLabels {
			fallback["ns."+k] = v
		}
		return []uint64{identity.HashLabels(fallback)}
	}

	// No namespace selector: scope to the policy's namespace.
	if podSelector.MatchLabels == nil {
		podSelector.MatchLabels = make(map[string]string)
	}
	podSelector.MatchLabels["novanet.io/namespace"] = namespace
	return r.findOrFallback(podSelector)
}

// buildIdentityRules creates the cartesian product of identity IDs x ports.
// For ingress rules, ids are source identities and fixedID is the destination;
// for egress rules, ids are destination identities and fixedID is the source.
func buildIdentityRules(ids []uint64, fixedID uint64, ports []portProto, isEgress bool, namespace string) []*CompiledRule {
	rules := make([]*CompiledRule, 0, len(ids)*len(ports))
	for _, id := range ids {
		for _, pp := range ports {
			r := &CompiledRule{
				Protocol:  pp.protocol,
				DstPort:   pp.port,
				Action:    ActionAllow,
				IsEgress:  isEgress,
				Namespace: namespace,
			}
			if isEgress {
				r.SrcIdentity = fixedID
				r.DstIdentity = id
			} else {
				r.SrcIdentity = id
				r.DstIdentity = fixedID
			}
			rules = append(rules, r)
		}
	}
	return rules
}

// buildCIDRRules creates CIDR-based rules from IPBlock peers.
// For ingress, fixedID is the destination identity; for egress, fixedID is the source.
func buildCIDRRules(entries []cidrEntry, fixedID uint64, ports []portProto, isEgress bool, namespace string) []*CompiledRule {
	rules := make([]*CompiledRule, 0, len(entries)*len(ports))
	for _, entry := range entries {
		for _, pp := range ports {
			r := &CompiledRule{
				Protocol:  pp.protocol,
				DstPort:   pp.port,
				Action:    entry.action,
				CIDR:      entry.cidr,
				IsEgress:  isEgress,
				Namespace: namespace,
			}
			if isEgress {
				r.SrcIdentity = fixedID
				r.DstIdentity = WildcardIdentity
			} else {
				r.SrcIdentity = WildcardIdentity
				r.DstIdentity = fixedID
			}
			rules = append(rules, r)
		}
	}
	return rules
}

// buildFQDNCIDRRules creates CIDR-based allow rules from FQDN-resolved CIDRs.
// For ingress, fixedID is the destination identity; for egress, fixedID is the source.
func buildFQDNCIDRRules(cidrs []string, fixedID uint64, ports []portProto, isEgress bool, namespace string) []*CompiledRule {
	rules := make([]*CompiledRule, 0, len(cidrs)*len(ports))
	for _, cidr := range cidrs {
		for _, pp := range ports {
			r := &CompiledRule{
				Protocol:  pp.protocol,
				DstPort:   pp.port,
				Action:    ActionAllow,
				CIDR:      cidr,
				IsEgress:  isEgress,
				Namespace: namespace,
			}
			if isEgress {
				r.SrcIdentity = fixedID
				r.DstIdentity = WildcardIdentity
			} else {
				r.SrcIdentity = WildcardIdentity
				r.DstIdentity = fixedID
			}
			rules = append(rules, r)
		}
	}
	return rules
}

// resolveIPBlockCIDRs extracts IPBlock CIDRs from peers as cidrEntry values.
// The primary CIDR gets ActionAllow while Except CIDRs get ActionDeny.
func resolveIPBlockCIDRs(cidr string, except []string, logger *zap.Logger) []cidrEntry {
	var entries []cidrEntry

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		logger.Warn("invalid IPBlock CIDR, skipping",
			zap.String("cidr", cidr),
			zap.Error(err),
		)
		return nil
	}
	entries = append(entries, cidrEntry{cidr: cidr, action: ActionAllow})

	for _, exceptCIDR := range except {
		_, _, err := net.ParseCIDR(exceptCIDR)
		if err != nil {
			logger.Warn("invalid IPBlock.Except CIDR, skipping",
				zap.String("except_cidr", exceptCIDR),
				zap.Error(err),
			)
			continue
		}
		entries = append(entries, cidrEntry{cidr: exceptCIDR, action: ActionDeny})
	}

	return entries
}
