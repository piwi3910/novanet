package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPPoolType identifies the purpose of an IP pool.
// +kubebuilder:validation:Enum=LoadBalancerVIP;IngressIP;PodCIDR;ServiceClusterIP;Custom
type IPPoolType string

// IPPool type constants.
const (
	IPPoolTypeLoadBalancerVIP  IPPoolType = "LoadBalancerVIP"
	IPPoolTypeIngressIP        IPPoolType = "IngressIP"
	IPPoolTypePodCIDR          IPPoolType = "PodCIDR"
	IPPoolTypeServiceClusterIP IPPoolType = "ServiceClusterIP"
	IPPoolTypeCustom           IPPoolType = "Custom"
)

// IPPoolSpec defines the desired state of IPPool.
type IPPoolSpec struct {
	// Type identifies the purpose of this IP pool.
	// +kubebuilder:validation:Required
	Type IPPoolType `json:"type"`

	// CIDRs is a list of CIDR ranges in this pool.
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`

	// Addresses is a list of individual IP addresses (for non-CIDR pools).
	// +optional
	Addresses []string `json:"addresses,omitempty"`

	// AutoAssign enables automatic allocation from this pool.
	// +kubebuilder:default=true
	// +optional
	AutoAssign bool `json:"autoAssign,omitempty"`

	// Owner identifies which project owns this pool (e.g. novaedge, novanet).
	// +optional
	Owner string `json:"owner,omitempty"`
}

// IPPoolAllocationStatus records a single IP allocation within the pool.
type IPPoolAllocationStatus struct {
	// IP is the allocated address.
	IP string `json:"ip"`

	// Owner is the allocating client identity.
	Owner string `json:"owner"`

	// Resource is a Kubernetes resource reference (e.g. novaedge/proxyvip/my-vip).
	// +optional
	Resource string `json:"resource,omitempty"`

	// Timestamp is when the allocation was made.
	Timestamp metav1.Time `json:"timestamp"`
}

// IPPoolStatus defines the observed state of IPPool.
type IPPoolStatus struct {
	// Allocated is the number of IPs currently allocated.
	Allocated int32 `json:"allocated,omitempty"`

	// Total is the total number of IPs in this pool.
	Total int32 `json:"total,omitempty"`

	// Available is the number of IPs available for allocation.
	Available int32 `json:"available,omitempty"`

	// Allocations is the list of current allocations.
	// +optional
	Allocations []IPPoolAllocationStatus `json:"allocations,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ipp
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Allocated",type=integer,JSONPath=`.status.allocated`
// +kubebuilder:printcolumn:name="Total",type=integer,JSONPath=`.status.total`
// +kubebuilder:printcolumn:name="Available",type=integer,JSONPath=`.status.available`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IPPool defines a pool of IP addresses for allocation by the IPAM service.
type IPPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IPPoolSpec   `json:"spec,omitempty"`
	Status IPPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IPPoolList contains a list of IPPool.
type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPPool `json:"items"`
}

var _ = func() bool {
	SchemeBuilder.Register(&IPPool{}, &IPPoolList{})
	return true
}()
