package hostfirewall

import (
	"testing"

	"github.com/azrtydxb/novanet/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func ptrProtocol(p corev1.Protocol) *corev1.Protocol { return &p }
func ptrInt32(v int32) *int32                         { return &v }

func makePolicy(name string, ingress, egress []v1alpha1.HostRule) *v1alpha1.HostEndpointPolicy {
	return &v1alpha1.HostEndpointPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.HostEndpointPolicySpec{
			NodeSelector: metav1.LabelSelector{},
			Ingress:      ingress,
			Egress:       egress,
		},
	}
}

func TestCompileIngressAllowRules(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("allow-ssh", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"10.0.0.0/8"},
			Ports:    []v1alpha1.HostPort{{Port: 22}},
		},
	}, nil)

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Direction != DirectionIngress {
		t.Errorf("expected DirectionIngress, got %d", r.Direction)
	}
	if r.Action != ActionAllow {
		t.Errorf("expected ActionAllow (1), got %d", r.Action)
	}
	if r.Protocol != ProtocolTCP {
		t.Errorf("expected ProtocolTCP (6), got %d", r.Protocol)
	}
	if r.CIDR.String() != "10.0.0.0/8" {
		t.Errorf("expected CIDR 10.0.0.0/8, got %s", r.CIDR.String())
	}
	if r.Port != 22 {
		t.Errorf("expected port 22, got %d", r.Port)
	}
	if r.EndPort != 0 {
		t.Errorf("expected endPort 0, got %d", r.EndPort)
	}
	if r.PolicyName != "allow-ssh" {
		t.Errorf("expected policy name allow-ssh, got %s", r.PolicyName)
	}
	if r.RuleID != "allow-ssh/ingress/0" {
		t.Errorf("expected rule ID allow-ssh/ingress/0, got %s", r.RuleID)
	}
}

func TestCompileEgressDenyRules(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("block-external", nil, []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionDeny,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"0.0.0.0/0"},
			Ports:    []v1alpha1.HostPort{{Port: 443}},
		},
	})

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Direction != DirectionEgress {
		t.Errorf("expected DirectionEgress, got %d", r.Direction)
	}
	if r.Action != ActionDeny {
		t.Errorf("expected ActionDeny (0), got %d", r.Action)
	}
	if r.RuleID != "block-external/egress/0" {
		t.Errorf("expected rule ID block-external/egress/0, got %s", r.RuleID)
	}
}

func TestCompilePortRanges(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("port-range", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"192.168.0.0/16"},
			Ports: []v1alpha1.HostPort{
				{Port: 8000, EndPort: ptrInt32(9000)},
			},
		},
	}, nil)

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Port != 8000 {
		t.Errorf("expected port 8000, got %d", r.Port)
	}
	if r.EndPort != 9000 {
		t.Errorf("expected endPort 9000, got %d", r.EndPort)
	}
}

func TestCompileMultipleCIDRs(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("multi-cidr", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolUDP),
			CIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			Ports:    []v1alpha1.HostPort{{Port: 53}},
		},
	}, nil)

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 CIDRs x 1 port = 3 rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	expectedCIDRs := map[string]bool{
		"10.0.0.0/8":     false,
		"172.16.0.0/12":  false,
		"192.168.0.0/16": false,
	}

	for _, r := range rules {
		if r.Protocol != ProtocolUDP {
			t.Errorf("expected ProtocolUDP (17), got %d", r.Protocol)
		}
		cidr := r.CIDR.String()
		if _, ok := expectedCIDRs[cidr]; !ok {
			t.Errorf("unexpected CIDR %s", cidr)
		}
		expectedCIDRs[cidr] = true
	}

	for cidr, seen := range expectedCIDRs {
		if !seen {
			t.Errorf("CIDR %s not found in compiled rules", cidr)
		}
	}
}

func TestRemovePolicy(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("to-remove", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"10.0.0.0/8"},
			Ports:    []v1alpha1.HostPort{{Port: 80}},
		},
	}, []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionDeny,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"0.0.0.0/0"},
			Ports:    []v1alpha1.HostPort{{Port: 443}},
		},
	})

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mgr.ApplyRules(rules)

	if mgr.Count() != 2 {
		t.Fatalf("expected 2 rules after apply, got %d", mgr.Count())
	}

	mgr.RemovePolicy("to-remove")

	if mgr.Count() != 0 {
		t.Errorf("expected 0 rules after remove, got %d", mgr.Count())
	}

	remaining := mgr.GetRules()
	if len(remaining) != 0 {
		t.Errorf("expected empty rules after remove, got %d", len(remaining))
	}
}

func TestGetRulesByDirection(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("mixed-dir", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"10.0.0.0/8"},
			Ports:    []v1alpha1.HostPort{{Port: 22}},
		},
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"10.0.0.0/8"},
			Ports:    []v1alpha1.HostPort{{Port: 80}},
		},
	}, []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionDeny,
			Protocol: ptrProtocol(corev1.ProtocolUDP),
			CIDRs:    []string{"0.0.0.0/0"},
			Ports:    []v1alpha1.HostPort{{Port: 53}},
		},
	})

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mgr.ApplyRules(rules)

	ingress := mgr.GetRulesByDirection(DirectionIngress)
	if len(ingress) != 2 {
		t.Errorf("expected 2 ingress rules, got %d", len(ingress))
	}
	for _, r := range ingress {
		if r.Direction != DirectionIngress {
			t.Errorf("expected ingress direction, got %d", r.Direction)
		}
	}

	egress := mgr.GetRulesByDirection(DirectionEgress)
	if len(egress) != 1 {
		t.Errorf("expected 1 egress rule, got %d", len(egress))
	}
	for _, r := range egress {
		if r.Direction != DirectionEgress {
			t.Errorf("expected egress direction, got %d", r.Direction)
		}
	}
}

func TestCompileNilPolicy(t *testing.T) {
	mgr := NewManager(testLogger())
	_, err := mgr.CompilePolicy(nil)
	if err == nil {
		t.Error("expected error for nil policy")
	}
}

func TestCompileInvalidCIDR(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("bad-cidr", []v1alpha1.HostRule{
		{
			Action: v1alpha1.HostRuleActionAllow,
			CIDRs:  []string{"not-a-cidr"},
		},
	}, nil)

	_, err := mgr.CompilePolicy(policy)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestCompileNoCIDRsDefaultsToAll(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("no-cidr", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			Ports:    []v1alpha1.HostPort{{Port: 80}},
		},
	}, nil)

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].CIDR.String() != "0.0.0.0/0" {
		t.Errorf("expected default CIDR 0.0.0.0/0, got %s", rules[0].CIDR.String())
	}
}

func TestCompileNilProtocolDefaultsToAny(t *testing.T) {
	mgr := NewManager(testLogger())

	policy := makePolicy("no-proto", []v1alpha1.HostRule{
		{
			Action: v1alpha1.HostRuleActionAllow,
			CIDRs:  []string{"10.0.0.0/8"},
		},
	}, nil)

	rules, err := mgr.CompilePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rules[0].Protocol != ProtocolAny {
		t.Errorf("expected ProtocolAny (0), got %d", rules[0].Protocol)
	}
}

func TestApplyRulesReplacesExisting(t *testing.T) {
	mgr := NewManager(testLogger())

	// Apply initial rules.
	policy1 := makePolicy("replace-test", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"10.0.0.0/8"},
			Ports:    []v1alpha1.HostPort{{Port: 80}},
		},
	}, nil)

	rules1, err := mgr.CompilePolicy(policy1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.ApplyRules(rules1)

	if mgr.Count() != 1 {
		t.Fatalf("expected 1 rule, got %d", mgr.Count())
	}

	// Apply replacement rules for the same policy.
	policy2 := makePolicy("replace-test", []v1alpha1.HostRule{
		{
			Action:   v1alpha1.HostRuleActionAllow,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			CIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
			Ports:    []v1alpha1.HostPort{{Port: 443}},
		},
	}, nil)

	rules2, err := mgr.CompilePolicy(policy2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.ApplyRules(rules2)

	if mgr.Count() != 2 {
		t.Errorf("expected 2 rules after replace, got %d", mgr.Count())
	}
}
