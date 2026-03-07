package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPAllocationState represents the state of an IP allocation.
// +kubebuilder:validation:Enum=Bound;Released;Conflict
type IPAllocationState string

// IPAllocation state constants.
const (
	IPAllocationStateBound    IPAllocationState = "Bound"
	IPAllocationStateReleased IPAllocationState = "Released"
	IPAllocationStateConflict IPAllocationState = "Conflict"
)

// IPAllocationSpec defines the desired state of IPAllocation.
type IPAllocationSpec struct {
	// Pool is the name of the IPPool this allocation belongs to.
	// +kubebuilder:validation:Required
	Pool string `json:"pool"`

	// IP is the allocated address.
	// +kubebuilder:validation:Required
	IP string `json:"ip"`

	// Owner identifies the allocating client (e.g. novaedge, novanet-agent).
	// +kubebuilder:validation:Required
	Owner string `json:"owner"`

	// Resource is a Kubernetes resource reference (e.g. novaedge/proxyvip/my-vip).
	// +optional
	Resource string `json:"resource,omitempty"`
}

// IPAllocationStatus defines the observed state of IPAllocation.
type IPAllocationStatus struct {
	// State is the current state of the allocation.
	State IPAllocationState `json:"state,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ipa
// +kubebuilder:printcolumn:name="Pool",type=string,JSONPath=`.spec.pool`
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.spec.ip`
// +kubebuilder:printcolumn:name="Owner",type=string,JSONPath=`.spec.owner`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IPAllocation tracks a single IP allocation from an IPPool.
type IPAllocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IPAllocationSpec   `json:"spec,omitempty"`
	Status IPAllocationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IPAllocationList contains a list of IPAllocation.
type IPAllocationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPAllocation `json:"items"`
}

var _ = func() bool {
	SchemeBuilder.Register(&IPAllocation{}, &IPAllocationList{})
	return true
}()
