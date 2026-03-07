package policy

import (
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/azrtydxb/novanet/internal/identity"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func testCompiler() (*Compiler, *identity.Allocator) {
	idAlloc := identity.NewAllocator(testLogger())
	compiler := NewCompiler(idAlloc, testLogger())
	return compiler, idAlloc
}

func TestCompilePolicyNil(t *testing.T) {
	c, _ := testCompiler()
	rules := c.CompilePolicy(nil)
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules for nil policy, got %d", len(rules))
	}
}

func TestCompileDefaultDenyIngress(t *testing.T) {
	c, _ := testCompiler()

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-all",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			// No ingress rules = default deny.
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Action != ActionDeny {
		t.Fatalf("expected deny action, got %d", r.Action)
	}
	if r.SrcIdentity != WildcardIdentity {
		t.Fatalf("expected wildcard source, got %d", r.SrcIdentity)
	}
	if r.DstIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard destination for selected pods")
	}
}

func TestCompileDefaultDenyEgress(t *testing.T) {
	c, _ := testCompiler()

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-egress",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			// No egress rules = default deny egress.
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Action != ActionDeny {
		t.Fatalf("expected deny action, got %d", r.Action)
	}
	if r.DstIdentity != WildcardIdentity {
		t.Fatalf("expected wildcard destination, got %d", r.DstIdentity)
	}
	if r.SrcIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard source for selected pods")
	}
}

func TestCompileIngressWithPodSelector(t *testing.T) {
	c, _ := testCompiler()

	tcpProto := corev1.ProtocolTCP
	port80 := intstr.FromInt(80)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-web",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &tcpProto,
							Port:     &port80,
						},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Action != ActionAllow {
		t.Fatalf("expected allow action, got %d", r.Action)
	}
	if r.Protocol != ProtocolTCP {
		t.Fatalf("expected TCP protocol, got %d", r.Protocol)
	}
	if r.DstPort != 80 {
		t.Fatalf("expected port 80, got %d", r.DstPort)
	}
	if r.SrcIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard source identity")
	}
	if r.DstIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard destination identity")
	}
}

func TestCompileIngressFromAny(t *testing.T) {
	c, _ := testCompiler()

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-all-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					// No From = allow from any.
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.SrcIdentity != WildcardIdentity {
		t.Fatalf("expected wildcard source for allow-all, got %d", r.SrcIdentity)
	}
	if r.Action != ActionAllow {
		t.Fatalf("expected allow action, got %d", r.Action)
	}
}

func TestCompileIngressMultiplePorts(t *testing.T) {
	c, _ := testCompiler()

	tcpProto := corev1.ProtocolTCP
	udpProto := corev1.ProtocolUDP
	port80 := intstr.FromInt(80)
	port53 := intstr.FromInt(53)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-port",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &port80},
						{Protocol: &udpProto, Port: &port53},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (one per port), got %d", len(rules))
	}

	// Verify both ports are represented.
	foundTCP80 := false
	foundUDP53 := false
	for _, r := range rules {
		if r.Protocol == ProtocolTCP && r.DstPort == 80 {
			foundTCP80 = true
		}
		if r.Protocol == ProtocolUDP && r.DstPort == 53 {
			foundUDP53 = true
		}
	}
	if !foundTCP80 {
		t.Fatal("expected TCP:80 rule")
	}
	if !foundUDP53 {
		t.Fatal("expected UDP:53 rule")
	}
}

func TestCompileIngressWithNamespaceSelector(t *testing.T) {
	c, _ := testCompiler()

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.SrcIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard source from namespace+pod selector")
	}
	if r.Action != ActionAllow {
		t.Fatalf("expected allow action, got %d", r.Action)
	}
}

func TestCompileEgressRules(t *testing.T) {
	c, _ := testCompiler()

	tcpProto := corev1.ProtocolTCP
	port443 := intstr.FromInt(443)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-egress",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "db"},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &port443},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Action != ActionAllow {
		t.Fatalf("expected allow action, got %d", r.Action)
	}
	if r.SrcIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard source identity for egress")
	}
	if r.DstIdentity == WildcardIdentity {
		t.Fatal("expected non-wildcard destination identity for egress")
	}
	if r.Protocol != ProtocolTCP {
		t.Fatalf("expected TCP protocol, got %d", r.Protocol)
	}
	if r.DstPort != 443 {
		t.Fatalf("expected port 443, got %d", r.DstPort)
	}
}

func TestCompileAllPolicies(t *testing.T) {
	c, _ := testCompiler()

	policies := []*networkingv1.NetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "policy-2",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
			},
		},
	}

	rules := c.CompileAll(policies)
	// Both are default-deny, so 2 rules.
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestCompileNoPolicyTypes(t *testing.T) {
	c, _ := testCompiler()

	// When no PolicyTypes is specified, Ingress is assumed.
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "implicit-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			// No PolicyTypes specified.
		},
	}

	rules := c.CompilePolicy(np)
	// Default ingress with no ingress rules = default deny ingress.
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (default deny ingress), got %d", len(rules))
	}
	if rules[0].Action != ActionDeny {
		t.Fatalf("expected deny action, got %d", rules[0].Action)
	}
}

func TestCompileIngressAndEgress(t *testing.T) {
	c, _ := testCompiler()

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "both-directions",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// No rules = default deny both.
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (deny ingress + deny egress), got %d", len(rules))
	}
}

func TestCompileMultipleSources(t *testing.T) {
	c, _ := testCompiler()

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-source",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "worker"},
							},
						},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	// 2 sources x 1 port (any) = 2 rules.
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (one per source), got %d", len(rules))
	}
}

func TestHasPolicyType(t *testing.T) {
	tests := []struct {
		name       string
		types      []networkingv1.PolicyType
		check      networkingv1.PolicyType
		wantResult bool
	}{
		{
			name:       "no types defaults to ingress",
			types:      nil,
			check:      networkingv1.PolicyTypeIngress,
			wantResult: true,
		},
		{
			name:       "no types does not have egress",
			types:      nil,
			check:      networkingv1.PolicyTypeEgress,
			wantResult: false,
		},
		{
			name:       "explicit ingress",
			types:      []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			check:      networkingv1.PolicyTypeIngress,
			wantResult: true,
		},
		{
			name:       "explicit egress only",
			types:      []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			check:      networkingv1.PolicyTypeIngress,
			wantResult: false,
		},
		{
			name:       "both types has ingress",
			types:      []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			check:      networkingv1.PolicyTypeIngress,
			wantResult: true,
		},
		{
			name:       "both types has egress",
			types:      []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			check:      networkingv1.PolicyTypeEgress,
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			np := &networkingv1.NetworkPolicy{
				Spec: networkingv1.NetworkPolicySpec{
					PolicyTypes: tt.types,
				},
			}
			got := hasPolicyType(np, tt.check)
			if got != tt.wantResult {
				t.Fatalf("expected %v, got %v", tt.wantResult, got)
			}
		})
	}
}

// --- MatchExpressions tests ---

func TestCompileMatchExpressionIn(t *testing.T) {
	c, idAlloc := testCompiler()

	// Pre-allocate an identity with matching labels.
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "web",
		"tier":                 "frontend",
		"novanet.io/namespace": "default",
	})

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "match-expr-in",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "tier",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"frontend", "backend"},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule matching the allocated identity, got %d", len(rules))
	}
	if rules[0].Action != ActionDeny {
		t.Fatalf("expected deny action (default deny), got %d", rules[0].Action)
	}
}

func TestCompileMatchExpressionNotIn(t *testing.T) {
	c, idAlloc := testCompiler()

	// This identity should NOT match (tier=frontend is in the NotIn list).
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "web",
		"tier":                 "frontend",
		"novanet.io/namespace": "default",
	})
	// This identity SHOULD match (tier=data is not in the NotIn list).
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "db",
		"tier":                 "data",
		"novanet.io/namespace": "default",
	})

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "match-expr-notin",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "tier",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"frontend", "backend"},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only data tier matches), got %d", len(rules))
	}
}

func TestCompileMatchExpressionExists(t *testing.T) {
	c, idAlloc := testCompiler()

	// Has "environment" label — should match.
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "web",
		"environment":          "prod",
		"novanet.io/namespace": "default",
	})
	// Missing "environment" label — should NOT match.
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "worker",
		"novanet.io/namespace": "default",
	})

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "match-expr-exists",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "environment",
						Operator: metav1.LabelSelectorOpExists,
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only pod with environment label), got %d", len(rules))
	}
}

func TestCompileMatchExpressionDoesNotExist(t *testing.T) {
	c, idAlloc := testCompiler()

	// Has "legacy" label — should NOT match.
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "old-svc",
		"legacy":               "true",
		"novanet.io/namespace": "default",
	})
	// Missing "legacy" label — should match.
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "new-svc",
		"novanet.io/namespace": "default",
	})

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "match-expr-dne",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "legacy",
						Operator: metav1.LabelSelectorOpDoesNotExist,
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only pod without legacy label), got %d", len(rules))
	}
}

func TestCompileCombinedMatchLabelsAndExpressions(t *testing.T) {
	c, idAlloc := testCompiler()

	// Matches: app=web AND tier In [frontend,backend]
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "web",
		"tier":                 "frontend",
		"novanet.io/namespace": "default",
	})
	// Does NOT match: app=api (wrong matchLabels)
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "api",
		"tier":                 "frontend",
		"novanet.io/namespace": "default",
	})

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "combined",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "tier",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"frontend", "backend"},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only app=web with tier=frontend), got %d", len(rules))
	}
}

// --- Named port tests ---

func TestCompileNamedPort(t *testing.T) {
	c, _ := testCompiler()

	// Set up a port resolver that resolves "http" → 8080.
	c.SetPortResolver(func(portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {
		if portName == "http" && protocol == corev1.ProtocolTCP {
			return []uint16{8080}
		}
		return nil
	})

	tcpProto := corev1.ProtocolTCP
	namedPort := intstr.FromString("http")

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "named-port",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &namedPort},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].DstPort != 8080 {
		t.Fatalf("expected port 8080 (resolved from 'http'), got %d", rules[0].DstPort)
	}
	if rules[0].Protocol != ProtocolTCP {
		t.Fatalf("expected TCP protocol, got %d", rules[0].Protocol)
	}
}

func TestCompileNamedPortMultipleResolutions(t *testing.T) {
	c, _ := testCompiler()

	// Port resolver returns multiple ports (different pods use different port numbers).
	c.SetPortResolver(func(portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {
		if portName == "metrics" {
			return []uint16{9090, 9091}
		}
		return nil
	})

	tcpProto := corev1.ProtocolTCP
	namedPort := intstr.FromString("metrics")

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-named-port",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &namedPort},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (one per resolved port), got %d", len(rules))
	}
}

func TestCompileNamedPortNoResolver(t *testing.T) {
	c, _ := testCompiler()
	// No port resolver set — named ports should be skipped.

	tcpProto := corev1.ProtocolTCP
	namedPort := intstr.FromString("http")
	port443 := intstr.FromInt(443)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-resolver",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &namedPort}, // skipped
						{Protocol: &tcpProto, Port: &port443},   // kept
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (named port skipped, numeric kept), got %d", len(rules))
	}
	if rules[0].DstPort != 443 {
		t.Fatalf("expected port 443, got %d", rules[0].DstPort)
	}
}

// --- Peer MatchExpressions test ---

func TestCompilePeerWithMatchExpressions(t *testing.T) {
	c, idAlloc := testCompiler()

	// Pre-allocate source identities.
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "api",
		"version":              "v2",
		"novanet.io/namespace": "default",
	})
	idAlloc.AllocateIdentity(map[string]string{
		"app":                  "api",
		"version":              "v1",
		"novanet.io/namespace": "default",
	})

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "peer-expr",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "version",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"v2", "v3"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	rules := c.CompilePolicy(np)
	// Should only match the v2 identity, not v1.
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only api v2 matches), got %d", len(rules))
	}
}
