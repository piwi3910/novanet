package hostfirewall

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/azrtydxb/novanet/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
)

// Protocol constants matching IP protocol numbers.
const (
	ProtocolAny  uint8 = 0
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
	ProtocolSCTP uint8 = 132
)

// Action constants for firewall rules.
const (
	ActionDeny  uint8 = 0
	ActionAllow uint8 = 1
)

// Direction indicates whether a rule applies to ingress or egress traffic.
type Direction uint8

const (
	DirectionIngress Direction = 0
	DirectionEgress  Direction = 1
)

// CompiledHostRule is a fully resolved firewall rule ready for dataplane programming.
type CompiledHostRule struct {
	RuleID     string
	Direction  Direction
	Protocol   uint8
	CIDR       net.IPNet
	Port       uint16
	EndPort    uint16 // 0 = single port
	Action     uint8  // 0=deny, 1=allow
	PolicyName string // source HostEndpointPolicy name
}

// Manager manages host-level firewall rules compiled from HostEndpointPolicy resources.
type Manager struct {
	mu     sync.RWMutex
	rules  map[string]*CompiledHostRule // key: rule_id
	logger *zap.Logger
}

// NewManager creates a new host firewall Manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		rules:  make(map[string]*CompiledHostRule),
		logger: logger,
	}
}

// CompilePolicy converts a HostEndpointPolicy into a list of CompiledHostRules.
// Each combination of rule, CIDR, and port generates a separate compiled rule.
func (m *Manager) CompilePolicy(policy *v1alpha1.HostEndpointPolicy) ([]*CompiledHostRule, error) {
	if policy == nil {
		return nil, errors.New("policy must not be nil")
	}

	var compiled []*CompiledHostRule

	ingressRules, err := m.compileRules(policy.Name, DirectionIngress, policy.Spec.Ingress)
	if err != nil {
		return nil, fmt.Errorf("compiling ingress rules: %w", err)
	}
	compiled = append(compiled, ingressRules...)

	egressRules, err := m.compileRules(policy.Name, DirectionEgress, policy.Spec.Egress)
	if err != nil {
		return nil, fmt.Errorf("compiling egress rules: %w", err)
	}
	compiled = append(compiled, egressRules...)

	m.logger.Debug("compiled host firewall policy",
		zap.String("policy", policy.Name),
		zap.Int("rules", len(compiled)),
	)

	return compiled, nil
}

// compileRules compiles a slice of HostRules into CompiledHostRules.
func (m *Manager) compileRules(policyName string, dir Direction, rules []v1alpha1.HostRule) ([]*CompiledHostRule, error) {
	var compiled []*CompiledHostRule
	idx := 0

	for i, rule := range rules {
		action, err := convertAction(rule.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}

		proto := convertProtocol(rule.Protocol)

		cidrs, err := parseCIDRs(rule.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}

		// If no CIDRs specified, use 0.0.0.0/0 to match all.
		if len(cidrs) == 0 {
			_, allNet, _ := net.ParseCIDR("0.0.0.0/0")
			cidrs = []net.IPNet{*allNet}
		}

		ports := expandPorts(rule.Ports)
		// If no ports specified, use a single entry with port=0 meaning any.
		if len(ports) == 0 {
			ports = []portRange{{port: 0, endPort: 0}}
		}

		dirStr := "ingress"
		if dir == DirectionEgress {
			dirStr = "egress"
		}

		for _, cidr := range cidrs {
			for _, pr := range ports {
				ruleID := fmt.Sprintf("%s/%s/%d", policyName, dirStr, idx)
				compiled = append(compiled, &CompiledHostRule{
					RuleID:     ruleID,
					Direction:  dir,
					Protocol:   proto,
					CIDR:       cidr,
					Port:       pr.port,
					EndPort:    pr.endPort,
					Action:     action,
					PolicyName: policyName,
				})
				idx++
			}
		}
	}

	return compiled, nil
}

// ApplyRules replaces all rules from the given policy with the provided rules.
// It removes any existing rules belonging to the same policy before applying.
func (m *Manager) ApplyRules(rules []*CompiledHostRule) {
	if len(rules) == 0 {
		return
	}

	policyName := rules[0].PolicyName

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove existing rules for this policy.
	for id, r := range m.rules {
		if r.PolicyName == policyName {
			delete(m.rules, id)
		}
	}

	// Apply new rules.
	for _, r := range rules {
		m.rules[r.RuleID] = r
	}

	m.logger.Debug("applied host firewall rules",
		zap.String("policy", policyName),
		zap.Int("count", len(rules)),
	)
}

// RemovePolicy removes all compiled rules associated with the given policy name.
func (m *Manager) RemovePolicy(policyName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	for id, r := range m.rules {
		if r.PolicyName == policyName {
			delete(m.rules, id)
			removed++
		}
	}

	m.logger.Debug("removed host firewall policy",
		zap.String("policy", policyName),
		zap.Int("removed", removed),
	)
}

// GetRules returns a copy of all currently stored compiled rules.
func (m *Manager) GetRules() []*CompiledHostRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*CompiledHostRule, 0, len(m.rules))
	for _, r := range m.rules {
		result = append(result, r)
	}
	return result
}

// GetRulesByDirection returns all rules matching the given direction.
func (m *Manager) GetRulesByDirection(dir Direction) []*CompiledHostRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*CompiledHostRule
	for _, r := range m.rules {
		if r.Direction == dir {
			result = append(result, r)
		}
	}
	return result
}

// Count returns the total number of compiled rules.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}

// portRange represents a port or port range.
type portRange struct {
	port    uint16
	endPort uint16
}

// convertAction converts a HostRuleAction to the uint8 action constant.
func convertAction(action v1alpha1.HostRuleAction) (uint8, error) {
	switch action {
	case v1alpha1.HostRuleActionAllow:
		return ActionAllow, nil
	case v1alpha1.HostRuleActionDeny:
		return ActionDeny, nil
	default:
		return 0, fmt.Errorf("unknown action %q", action)
	}
}

// convertProtocol converts a Kubernetes Protocol pointer to an IP protocol number.
func convertProtocol(proto *corev1.Protocol) uint8 {
	if proto == nil {
		return ProtocolAny
	}
	switch *proto {
	case corev1.ProtocolTCP:
		return ProtocolTCP
	case corev1.ProtocolUDP:
		return ProtocolUDP
	case corev1.ProtocolSCTP:
		return ProtocolSCTP
	default:
		return ProtocolAny
	}
}

// parseCIDRs parses a slice of CIDR strings into net.IPNet values.
func parseCIDRs(cidrs []string) ([]net.IPNet, error) {
	var result []net.IPNet
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		result = append(result, *ipNet)
	}
	return result, nil
}

// expandPorts converts HostPort entries to portRange values.
func expandPorts(ports []v1alpha1.HostPort) []portRange {
	var result []portRange
	for _, p := range ports {
		pr := portRange{
			port: uint16(p.Port),
		}
		if p.EndPort != nil {
			pr.endPort = uint16(*p.EndPort)
		}
		result = append(result, pr)
	}
	return result
}
