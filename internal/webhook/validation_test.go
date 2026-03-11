package webhook

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"valid IPv4", "10.0.0.0/8", false},
		{"valid IPv6", "fd00::/64", false},
		{"valid /32", "192.168.1.1/32", false},
		{"invalid no mask", "10.0.0.0", true},
		{"invalid garbage", "not-a-cidr", true},
		{"non-canonical", "10.0.0.1/8", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIDR(tt.cidr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid IPv4", "10.0.0.1", false},
		{"valid IPv6", "::1", false},
		{"invalid", "999.999.999.999", true},
		{"empty", "", true},
		{"cidr not ip", "10.0.0.0/8", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIP(tt.ip)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	assert.NoError(t, validatePort(1))
	assert.NoError(t, validatePort(65535))
	assert.NoError(t, validatePort(80))
	assert.Error(t, validatePort(0))
	assert.Error(t, validatePort(-1))
	assert.Error(t, validatePort(65536))
}

func TestValidatePortRange(t *testing.T) {
	assert.NoError(t, validatePortRange(80, 90))
	assert.NoError(t, validatePortRange(80, 80))
	assert.Error(t, validatePortRange(90, 80))
	assert.Error(t, validatePortRange(0, 80))
	assert.Error(t, validatePortRange(80, 0))
}

func TestValidateProtocol(t *testing.T) {
	assert.NoError(t, validateProtocol("TCP"))
	assert.NoError(t, validateProtocol("UDP"))
	assert.NoError(t, validateProtocol("SCTP"))
	assert.NoError(t, validateProtocol("tcp"))
	assert.Error(t, validateProtocol("ICMP"))
	assert.Error(t, validateProtocol(""))
}

func TestHostEndpointPolicyValidator_ValidCreate(t *testing.T) {
	tcp := corev1.ProtocolTCP
	hep := &novanetv1alpha1.HostEndpointPolicy{
		Spec: novanetv1alpha1.HostEndpointPolicySpec{
			NodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"role": "worker"},
			},
			Ingress: []novanetv1alpha1.HostRule{
				{
					Action:   novanetv1alpha1.HostRuleActionAllow,
					Protocol: &tcp,
					CIDRs:    []string{"10.0.0.0/8"},
					Ports:    []novanetv1alpha1.HostPort{{Port: 443}},
				},
			},
		},
	}
	v := &HostEndpointPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), hep)
	require.NoError(t, err)
}

func TestHostEndpointPolicyValidator_InvalidCIDR(t *testing.T) {
	hep := &novanetv1alpha1.HostEndpointPolicy{
		Spec: novanetv1alpha1.HostEndpointPolicySpec{
			Ingress: []novanetv1alpha1.HostRule{
				{Action: novanetv1alpha1.HostRuleActionAllow, CIDRs: []string{"not-a-cidr"}},
			},
		},
	}
	v := &HostEndpointPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), hep)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestHostEndpointPolicyValidator_InvalidAction(t *testing.T) {
	hep := &novanetv1alpha1.HostEndpointPolicy{
		Spec: novanetv1alpha1.HostEndpointPolicySpec{
			Ingress: []novanetv1alpha1.HostRule{{Action: "Drop"}},
		},
	}
	v := &HostEndpointPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), hep)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "action")
}

func TestHostEndpointPolicyValidator_InvalidPortRange(t *testing.T) {
	endPort := int32(79)
	hep := &novanetv1alpha1.HostEndpointPolicy{
		Spec: novanetv1alpha1.HostEndpointPolicySpec{
			Egress: []novanetv1alpha1.HostRule{
				{
					Action: novanetv1alpha1.HostRuleActionDeny,
					Ports:  []novanetv1alpha1.HostPort{{Port: 80, EndPort: &endPort}},
				},
			},
		},
	}
	v := &HostEndpointPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), hep)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endPort")
}

func TestHostEndpointPolicyValidator_Delete(t *testing.T) {
	v := &HostEndpointPolicyValidator{}
	_, err := v.ValidateDelete(context.Background(), &novanetv1alpha1.HostEndpointPolicy{})
	require.NoError(t, err)
}

func TestNovaNetworkPolicyValidator_ValidCreate(t *testing.T) {
	proto := "TCP"
	port := int32(80)
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []novanetv1alpha1.PolicyType{novanetv1alpha1.PolicyTypeIngress},
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{
					Ports: []novanetv1alpha1.NovaNetworkPolicyPort{{Protocol: &proto, Port: &port}},
					From: []novanetv1alpha1.NovaNetworkPolicyPeer{
						{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}},
					},
				},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.NoError(t, err)
}

func TestNovaNetworkPolicyValidator_InvalidCIDR(t *testing.T) {
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{From: []novanetv1alpha1.NovaNetworkPolicyPeer{
					{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "invalid"}},
				}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestNovaNetworkPolicyValidator_InvalidProtocol(t *testing.T) {
	proto := "ICMP"
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{Ports: []novanetv1alpha1.NovaNetworkPolicyPort{{Protocol: &proto}}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "protocol")
}

func TestNovaNetworkPolicyValidator_InvalidPort(t *testing.T) {
	port := int32(0)
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Egress: []novanetv1alpha1.NovaNetworkPolicyEgressRule{
				{Ports: []novanetv1alpha1.NovaNetworkPolicyPort{{Port: &port}}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

func TestNovaNetworkPolicyValidator_EndPortWithoutPort(t *testing.T) {
	endPort := int32(100)
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{Ports: []novanetv1alpha1.NovaNetworkPolicyPort{{EndPort: &endPort}}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port must be set")
}

func TestNovaNetworkPolicyValidator_InvalidExceptCIDR(t *testing.T) {
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{From: []novanetv1alpha1.NovaNetworkPolicyPeer{
					{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "10.0.0.0/8", Except: []string{"bad-cidr"}}},
				}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestIPPoolValidator_ValidCreate(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeLoadBalancerVIP, CIDRs: []string{"10.0.0.0/24"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.NoError(t, err)
}

func TestIPPoolValidator_ValidWithAddresses(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeCustom, Addresses: []string{"10.0.0.1", "10.0.0.2", "::1"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.NoError(t, err)
}

func TestIPPoolValidator_InvalidType(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: "InvalidType", CIDRs: []string{"10.0.0.0/24"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestIPPoolValidator_InvalidCIDR(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypePodCIDR, CIDRs: []string{"garbage"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestIPPoolValidator_OverlappingCIDRs(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeLoadBalancerVIP, CIDRs: []string{"10.0.0.0/8", "10.1.0.0/16"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overlaps")
}

func TestIPPoolValidator_InvalidAddress(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeCustom, Addresses: []string{"not-an-ip"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP")
}

func TestIPPoolValidator_EmptyPool(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeCustom},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one")
}

func TestIPPoolValidator_Delete(t *testing.T) {
	v := &IPPoolValidator{}
	_, err := v.ValidateDelete(context.Background(), &novanetv1alpha1.IPPool{})
	require.NoError(t, err)
}

func TestIPPoolValidator_Update(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeIngressIP, CIDRs: []string{"192.168.0.0/16"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateUpdate(context.Background(), nil, pool)
	require.NoError(t, err)
}

func TestIPPoolValidator_MultipleCIDRsNoOverlap(t *testing.T) {
	pool := &novanetv1alpha1.IPPool{
		Spec: novanetv1alpha1.IPPoolSpec{Type: novanetv1alpha1.IPPoolTypeLoadBalancerVIP, CIDRs: []string{"10.0.0.0/24", "10.1.0.0/24", "fd00::/64"}},
	}
	v := &IPPoolValidator{}
	_, err := v.ValidateCreate(context.Background(), pool)
	require.NoError(t, err)
}

// --- IPBlock.Except containment tests (issue #83) ---

func TestNovaNetworkPolicyValidator_ExceptNotContained(t *testing.T) {
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{From: []novanetv1alpha1.NovaNetworkPolicyPeer{
					{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "10.0.0.0/8", Except: []string{"192.168.0.0/16"}}},
				}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not contained within")
}

func TestNovaNetworkPolicyValidator_ExceptContained(t *testing.T) {
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{From: []novanetv1alpha1.NovaNetworkPolicyPeer{
					{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}},
				}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.NoError(t, err)
}

func TestNovaNetworkPolicyValidator_ExceptPartiallyOutside(t *testing.T) {
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Egress: []novanetv1alpha1.NovaNetworkPolicyEgressRule{
				{To: []novanetv1alpha1.NovaNetworkPolicyPeer{
					{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.0/7"}}},
				}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not contained within")
}

func TestNovaNetworkPolicyValidator_ExceptIPv6Contained(t *testing.T) {
	nnp := &novanetv1alpha1.NovaNetworkPolicy{
		Spec: novanetv1alpha1.NovaNetworkPolicySpec{
			Ingress: []novanetv1alpha1.NovaNetworkPolicyIngressRule{
				{From: []novanetv1alpha1.NovaNetworkPolicyPeer{
					{IPBlock: &novanetv1alpha1.NovaIPBlock{CIDR: "fd00::/32", Except: []string{"fd00::/48"}}},
				}},
			},
		},
	}
	v := &NovaNetworkPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), nnp)
	require.NoError(t, err)
}

func TestCidrContains(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		child    string
		expected bool
	}{
		{"child within parent", "10.0.0.0/8", "10.1.0.0/16", true},
		{"child equals parent", "10.0.0.0/8", "10.0.0.0/8", true},
		{"child outside parent", "10.0.0.0/8", "192.168.0.0/16", false},
		{"child wider than parent", "10.0.0.0/16", "10.0.0.0/8", false},
		{"child at boundary end", "10.0.0.0/24", "10.0.0.128/25", true},
		{"ipv6 contained", "fd00::/32", "fd00::/48", true},
		{"ipv6 not contained", "fd00::/48", "fd01::/48", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, parentNet, err := net.ParseCIDR(tt.parent)
			require.NoError(t, err)
			_, childNet, err := net.ParseCIDR(tt.child)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cidrContains(parentNet, childNet))
		})
	}
}

// --- EgressGatewayPolicy webhook tests (issue #82) ---

func TestEgressGatewayPolicyValidator_ValidCreate(t *testing.T) {
	egp := &novanetv1alpha1.EgressGatewayPolicy{
		Spec: novanetv1alpha1.EgressGatewayPolicySpec{
			PodSelector:      metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			DestinationCIDRs: []string{"0.0.0.0/0"},
			ExcludedCIDRs:    []string{"10.0.0.0/8"},
			GatewaySelector:  metav1.LabelSelector{MatchLabels: map[string]string{"role": "gateway"}},
			EgressIP:         "203.0.113.1",
		},
	}
	v := &EgressGatewayPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), egp)
	require.NoError(t, err)
}

func TestEgressGatewayPolicyValidator_InvalidDestCIDR(t *testing.T) {
	egp := &novanetv1alpha1.EgressGatewayPolicy{
		Spec: novanetv1alpha1.EgressGatewayPolicySpec{
			DestinationCIDRs: []string{"not-a-cidr"},
		},
	}
	v := &EgressGatewayPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), egp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestEgressGatewayPolicyValidator_InvalidEgressIP(t *testing.T) {
	egp := &novanetv1alpha1.EgressGatewayPolicy{
		Spec: novanetv1alpha1.EgressGatewayPolicySpec{
			EgressIP: "not-an-ip",
		},
	}
	v := &EgressGatewayPolicyValidator{}
	_, err := v.ValidateCreate(context.Background(), egp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP")
}

func TestEgressGatewayPolicyValidator_Delete(t *testing.T) {
	v := &EgressGatewayPolicyValidator{}
	_, err := v.ValidateDelete(context.Background(), &novanetv1alpha1.EgressGatewayPolicy{})
	require.NoError(t, err)
}

// --- NovanetCluster webhook tests (issue #82) ---

func TestNovanetClusterValidator_ValidCreate(t *testing.T) {
	nnc := &novanetv1alpha1.NovaNetCluster{
		Spec: novanetv1alpha1.NovaNetClusterSpec{
			Version: "v1.0.0",
			Networking: novanetv1alpha1.NetworkingSpec{
				ClusterCIDR: "10.0.0.0/16",
			},
		},
	}
	v := &NovanetClusterValidator{}
	_, err := v.ValidateCreate(context.Background(), nnc)
	require.NoError(t, err)
}

func TestNovanetClusterValidator_InvalidClusterCIDR(t *testing.T) {
	nnc := &novanetv1alpha1.NovaNetCluster{
		Spec: novanetv1alpha1.NovaNetClusterSpec{
			Version: "v1.0.0",
			Networking: novanetv1alpha1.NetworkingSpec{
				ClusterCIDR: "bad-cidr",
			},
		},
	}
	v := &NovanetClusterValidator{}
	_, err := v.ValidateCreate(context.Background(), nnc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestNovanetClusterValidator_InvalidMTU(t *testing.T) {
	mtu := int32(500)
	nnc := &novanetv1alpha1.NovaNetCluster{
		Spec: novanetv1alpha1.NovaNetClusterSpec{
			Version: "v1.0.0",
			Networking: novanetv1alpha1.NetworkingSpec{
				ClusterCIDR: "10.0.0.0/16",
				MTU:         &mtu,
			},
		},
	}
	v := &NovanetClusterValidator{}
	_, err := v.ValidateCreate(context.Background(), nnc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MTU")
}

func TestNovanetClusterValidator_Delete(t *testing.T) {
	v := &NovanetClusterValidator{}
	_, err := v.ValidateDelete(context.Background(), &novanetv1alpha1.NovaNetCluster{})
	require.NoError(t, err)
}
