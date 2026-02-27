package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterPhase represents the phase of the NovaNetCluster.
// +kubebuilder:validation:Enum=Pending;Initializing;Running;Upgrading;Degraded;Failed
type ClusterPhase string

const (
	ClusterPhasePending      ClusterPhase = "Pending"
	ClusterPhaseInitializing ClusterPhase = "Initializing"
	ClusterPhaseRunning      ClusterPhase = "Running"
	ClusterPhaseUpgrading    ClusterPhase = "Upgrading"
	ClusterPhaseDegraded     ClusterPhase = "Degraded"
	ClusterPhaseFailed       ClusterPhase = "Failed"
)

// NovaNetClusterSpec defines the desired state of NovaNetCluster.
type NovaNetClusterSpec struct {
	// Version of NovaNet components to deploy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$`
	Version string `json:"version"`

	// ImageRepository for NovaNet images.
	// +kubebuilder:default="ghcr.io/piwi3910/novanet"
	// +optional
	ImageRepository string `json:"imageRepository,omitempty"`

	// ImagePullPolicy for all containers.
	// +kubebuilder:default="IfNotPresent"
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets for pulling images.
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Agent defines the Go management plane configuration.
	// +kubebuilder:validation:Required
	Agent NovaNetAgentSpec `json:"agent"`

	// Dataplane defines the Rust eBPF dataplane configuration.
	// +kubebuilder:validation:Required
	Dataplane DataplaneSpec `json:"dataplane"`

	// CNI defines the CNI binary installation configuration.
	// +optional
	CNI *CNISpec `json:"cni,omitempty"`

	// Networking defines cluster networking configuration.
	// +kubebuilder:validation:Required
	Networking NetworkingSpec `json:"networking"`

	// NovaRouteIntegration enables native routing via NovaRoute.
	// +optional
	NovaRouteIntegration *NovaRouteIntegrationSpec `json:"novaRouteIntegration,omitempty"`

	// NodeSelector for scheduling.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for scheduling.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// UpdateStrategy for the DaemonSet.
	// +optional
	UpdateStrategy *UpdateStrategySpec `json:"updateStrategy,omitempty"`
}

// NovaNetAgentSpec defines the agent container configuration.
type NovaNetAgentSpec struct {
	// Image overrides the default agent image.
	// +optional
	Image string `json:"image,omitempty"`

	// Resources for the agent container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// LogLevel for the agent.
	// +kubebuilder:default="info"
	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// MetricsPort for Prometheus metrics.
	// +kubebuilder:default=9090
	// +optional
	MetricsPort *int32 `json:"metricsPort,omitempty"`

	// HealthPort for health checks.
	// +kubebuilder:default=9091
	// +optional
	HealthPort *int32 `json:"healthPort,omitempty"`

	// ExtraArgs are additional command-line arguments.
	// +optional
	ExtraArgs []string `json:"extraArgs,omitempty"`

	// ExtraEnv are additional environment variables.
	// +optional
	ExtraEnv []corev1.EnvVar `json:"extraEnv,omitempty"`
}

// DataplaneSpec defines the eBPF dataplane container configuration.
type DataplaneSpec struct {
	// Image overrides the default dataplane image.
	// +optional
	Image string `json:"image,omitempty"`

	// Resources for the dataplane container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// CNISpec defines CNI binary installation settings.
type CNISpec struct {
	// Image overrides the image used for the CNI init container.
	// +optional
	Image string `json:"image,omitempty"`

	// BinDir is the host path for CNI binaries.
	// +kubebuilder:default="/opt/cni/bin"
	// +optional
	BinDir string `json:"binDir,omitempty"`

	// ConfDir is the host path for CNI config.
	// +kubebuilder:default="/etc/cni/net.d"
	// +optional
	ConfDir string `json:"confDir,omitempty"`
}

// NetworkingSpec defines cluster networking settings.
type NetworkingSpec struct {
	// ClusterCIDR is the pod IP range.
	// +kubebuilder:validation:Required
	ClusterCIDR string `json:"clusterCIDR"`

	// TunnelProtocol for overlay mode.
	// +kubebuilder:default="geneve"
	// +kubebuilder:validation:Enum=geneve;vxlan
	// +optional
	TunnelProtocol string `json:"tunnelProtocol,omitempty"`

	// RoutingMode determines how packets reach other nodes.
	// +kubebuilder:default="overlay"
	// +kubebuilder:validation:Enum=overlay;native
	// +optional
	RoutingMode string `json:"routingMode,omitempty"`

	// MTU for pod interfaces. 0 = auto-detect.
	// +kubebuilder:default=0
	// +optional
	MTU *int32 `json:"mtu,omitempty"`
}

// NovaRouteIntegrationSpec configures native routing via NovaRoute.
type NovaRouteIntegrationSpec struct {
	// Enabled activates NovaRoute integration for native routing.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// SocketPath is the NovaRoute Unix socket path.
	// +kubebuilder:default="/run/novaroute/novaroute.sock"
	// +optional
	SocketPath string `json:"socketPath,omitempty"`

	// OwnerToken is the authentication token for the NovaRoute gRPC API.
	// +optional
	OwnerToken string `json:"ownerToken,omitempty"`
}

// UpdateStrategySpec defines the DaemonSet update strategy.
type UpdateStrategySpec struct {
	// Type is RollingUpdate or OnDelete.
	// +kubebuilder:default="RollingUpdate"
	// +kubebuilder:validation:Enum=RollingUpdate;OnDelete
	Type string `json:"type,omitempty"`

	// MaxUnavailable for RollingUpdate.
	// +kubebuilder:default=1
	// +optional
	MaxUnavailable *int32 `json:"maxUnavailable,omitempty"`
}

// ComponentStatus holds the status of a managed component.
type ComponentStatus struct {
	Ready        bool  `json:"ready"`
	DesiredNodes int32 `json:"desiredNodes"`
	ReadyNodes   int32 `json:"readyNodes"`
	UpdatedNodes int32 `json:"updatedNodes"`
}

// NovaNetClusterStatus defines the observed state of NovaNetCluster.
type NovaNetClusterStatus struct {
	// Phase is the current lifecycle phase.
	Phase ClusterPhase `json:"phase,omitempty"`

	// Agent is the DaemonSet status.
	// +optional
	Agent *ComponentStatus `json:"agent,omitempty"`

	// Version is the observed deployed version.
	Version string `json:"version,omitempty"`

	// ObservedGeneration is the last observed generation.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=nnc
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.agent.readyNodes`
// +kubebuilder:printcolumn:name="Desired",type=integer,JSONPath=`.status.agent.desiredNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NovaNetCluster is the Schema for the novanetclusters API.
type NovaNetCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NovaNetClusterSpec   `json:"spec,omitempty"`
	Status NovaNetClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NovaNetClusterList contains a list of NovaNetCluster.
type NovaNetClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NovaNetCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NovaNetCluster{}, &NovaNetClusterList{})
}
