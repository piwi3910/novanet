// Package egress implements egress traffic control, including masquerade
// (SNAT) configuration and per-namespace egress rules.
package egress

import (
	"fmt"
	"net"
	"sync"

	"github.com/azrtydxb/novanet/internal/constants"
	"go.uber.org/zap"
)

// Action constants — aliased from constants package.
const (
	ActionDeny  = constants.ActionDeny
	ActionAllow = constants.ActionAllow
	ActionSNAT  = constants.ActionSNAT
)

// Rule defines a single egress policy rule.
type Rule struct {
	// Name is a unique identifier for this rule within a namespace.
	Name string
	// SrcIdentity is the identity ID of the source pods.
	SrcIdentity uint64
	// DstCIDR is the destination CIDR to match.
	DstCIDR string
	// Protocol is the IP protocol number (6=TCP, 17=UDP, 0=any).
	Protocol uint8
	// DstPort is the destination port (0=any).
	DstPort uint16
	// Action is the action to apply (ActionDeny, ActionAllow, ActionSNAT).
	Action uint8
}

// CompiledEgressRule is a compiled version of an EgressRule with parsed CIDR.
type CompiledEgressRule struct {
	// Namespace is the Kubernetes namespace this rule applies to.
	Namespace string
	// Name is the rule name within the namespace.
	Name string
	// SrcIdentity is the identity ID of the source pods.
	SrcIdentity uint64
	// DstCIDR is the parsed destination CIDR.
	DstCIDR net.IPNet
	// Protocol is the IP protocol number (0=any).
	Protocol uint8
	// DstPort is the destination port (0=any).
	DstPort uint16
	// Action is the egress action (0=deny, 1=allow, 2=snat).
	Action uint8
}

// Manager handles egress traffic control.
type Manager struct {
	mu sync.RWMutex

	logger      *zap.Logger
	nodeIP      net.IP
	clusterCIDR *net.IPNet
	masquerade  bool

	// rules is keyed by namespace/name.
	rules map[string]*CompiledEgressRule
}

// NewManager creates a new egress manager.
func NewManager(nodeIP net.IP, clusterCIDR *net.IPNet, logger *zap.Logger) *Manager {
	return &Manager{
		logger:      logger,
		nodeIP:      nodeIP,
		clusterCIDR: clusterCIDR,
		masquerade:  true,
		rules:       make(map[string]*CompiledEgressRule),
	}
}

// SetMasqueradeEnabled enables or disables SNAT masquerade for traffic
// leaving the cluster CIDR.
func (m *Manager) SetMasqueradeEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.masquerade = enabled
	m.logger.Info("masquerade setting changed",
		zap.Bool("enabled", enabled),
	)
}

// IsMasqueradeEnabled returns whether masquerade is enabled.
func (m *Manager) IsMasqueradeEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masquerade
}

// AddEgressRule adds or updates an egress rule for the given namespace.
func (m *Manager) AddEgressRule(namespace string, rule Rule) error {
	_, cidr, err := net.ParseCIDR(rule.DstCIDR)
	if err != nil {
		return fmt.Errorf("parsing destination CIDR %q: %w", rule.DstCIDR, err)
	}

	compiled := &CompiledEgressRule{
		Namespace:   namespace,
		Name:        rule.Name,
		SrcIdentity: rule.SrcIdentity,
		DstCIDR:     *cidr,
		Protocol:    rule.Protocol,
		DstPort:     rule.DstPort,
		Action:      rule.Action,
	}

	key := ruleKey(namespace, rule.Name)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.rules[key] = compiled
	m.logger.Debug("added egress rule",
		zap.String("namespace", namespace),
		zap.String("name", rule.Name),
		zap.Uint64("src_identity", rule.SrcIdentity),
		zap.String("dst_cidr", rule.DstCIDR),
		zap.Uint8("action", rule.Action),
	)

	return nil
}

// RemoveEgressRule removes an egress rule.
func (m *Manager) RemoveEgressRule(namespace, name string) {
	key := ruleKey(namespace, name)

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.rules[key]; ok {
		delete(m.rules, key)
		m.logger.Debug("removed egress rule",
			zap.String("namespace", namespace),
			zap.String("name", name),
		)
	}
}

// GetRules returns a snapshot of all compiled egress rules.
func (m *Manager) GetRules() []CompiledEgressRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]CompiledEgressRule, 0, len(m.rules))
	for _, rule := range m.rules {
		result = append(result, *rule)
	}
	return result
}

// GetRule returns a specific egress rule.
func (m *Manager) GetRule(namespace, name string) (*CompiledEgressRule, bool) {
	key := ruleKey(namespace, name)

	m.mu.RLock()
	defer m.mu.RUnlock()

	rule, ok := m.rules[key]
	if !ok {
		return nil, false
	}
	r := *rule
	return &r, true
}

// Count returns the number of egress rules.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}

// NodeIP returns the node IP used for SNAT.
func (m *Manager) NodeIP() net.IP {
	return m.nodeIP
}

// ClusterCIDR returns the cluster CIDR.
func (m *Manager) ClusterCIDR() *net.IPNet {
	return m.clusterCIDR
}

func ruleKey(namespace, name string) string {
	return namespace + "/" + name
}
