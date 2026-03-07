// Package controller implements the NovaNet operator controllers that manage
// the lifecycle of NovaNetCluster resources via Kubernetes reconciliation loops.
package controller

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

const (
	novanetClusterFinalizer = "novanet.io/finalizer"

	// ConditionTypeReady indicates the cluster is fully ready.
	ConditionTypeReady = "Ready"
	// ConditionTypeAgentOK indicates the agent DaemonSet is ready.
	ConditionTypeAgentOK = "AgentReady"
	// ConditionTypeDegraded indicates the cluster is in a degraded state.
	ConditionTypeDegraded = "Degraded"
)

// errNotClientObject indicates that an object does not implement client.Object.
var errNotClientObject = stderrors.New("object does not implement client.Object")

// NovaNetClusterReconciler reconciles a NovaNetCluster object.
type NovaNetClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=novanet.io,resources=novanetclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=novanet.io,resources=novanetclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=novanet.io,resources=novanetclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services;serviceaccounts;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop.
func (r *NovaNetClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling NovaNetCluster", "name", req.Name, "namespace", req.Namespace)

	// Fetch the NovaNetCluster instance
	cluster := &novanetv1alpha1.NovaNetCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("NovaNetCluster resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching NovaNetCluster: %w", err)
	}

	// Handle finalizer
	if cluster.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(cluster, novanetClusterFinalizer) {
			controllerutil.AddFinalizer(cluster, novanetClusterFinalizer)
			if err := r.Update(ctx, cluster); err != nil {
				return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
			}
		}
	} else {
		if controllerutil.ContainsFinalizer(cluster, novanetClusterFinalizer) {
			if err := r.cleanupResources(ctx, cluster); err != nil {
				return ctrl.Result{}, fmt.Errorf("cleaning up resources: %w", err)
			}
			controllerutil.RemoveFinalizer(cluster, novanetClusterFinalizer)
			if err := r.Update(ctx, cluster); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Initialize status if needed
	if cluster.Status.Phase == "" {
		cluster.Status.Phase = novanetv1alpha1.ClusterPhasePending
		if err := r.Status().Update(ctx, cluster); err != nil {
			return ctrl.Result{}, fmt.Errorf("initializing status: %w", err)
		}
	}

	// Reconcile all components
	var reconcileErrors []error

	// 1. RBAC
	if err := r.reconcileRBAC(ctx, cluster); err != nil {
		reconcileErrors = append(reconcileErrors, fmt.Errorf("RBAC: %w", err))
	}

	// 2. ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		reconcileErrors = append(reconcileErrors, fmt.Errorf("ConfigMap: %w", err))
	}

	// 3. DaemonSet
	if err := r.reconcileDaemonSet(ctx, cluster); err != nil {
		reconcileErrors = append(reconcileErrors, fmt.Errorf("DaemonSet: %w", err))
	}

	// 4. Metrics Service
	if err := r.reconcileMetricsService(ctx, cluster); err != nil {
		reconcileErrors = append(reconcileErrors, fmt.Errorf("MetricsService: %w", err))
	}

	// 5. PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		reconcileErrors = append(reconcileErrors, fmt.Errorf("PDB: %w", err))
	}

	// Update status
	if err := r.updateStatus(ctx, cluster); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	if len(reconcileErrors) > 0 {
		logger.Error(reconcileErrors[0], "Reconciliation errors", "count", len(reconcileErrors))
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	logger.Info("NovaNetCluster reconciled successfully")
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) cleanupResources(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	logger := log.FromContext(ctx)
	logger.Info("Cleaning up cluster-scoped resources for NovaNetCluster", "name", cluster.Name)

	// Namespaced resources are garbage-collected via owner references.
	// Only cluster-scoped resources (ClusterRole, ClusterRoleBinding) need
	// explicit deletion.
	clusterScopedNames := []string{
		r.clusterRoleName(cluster),
		r.clusterRoleBindingName(cluster),
	}

	for _, name := range clusterScopedNames[:1] {
		cr := &rbacv1.ClusterRole{}
		if err := r.Get(ctx, types.NamespacedName{Name: name}, cr); err == nil {
			if err := r.Delete(ctx, cr); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("deleting ClusterRole %s: %w", name, err)
			}
		}
	}

	for _, name := range clusterScopedNames[1:] {
		crb := &rbacv1.ClusterRoleBinding{}
		if err := r.Get(ctx, types.NamespacedName{Name: name}, crb); err == nil {
			if err := r.Delete(ctx, crb); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("deleting ClusterRoleBinding %s: %w", name, err)
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) reconcileRBAC(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	if err := r.reconcileServiceAccount(ctx, cluster); err != nil {
		return fmt.Errorf("ServiceAccount: %w", err)
	}
	if err := r.reconcileClusterRole(ctx, cluster); err != nil {
		return fmt.Errorf("ClusterRole: %w", err)
	}
	if err := r.reconcileClusterRoleBinding(ctx, cluster); err != nil {
		return fmt.Errorf("ClusterRoleBinding: %w", err)
	}
	return nil
}

func (r *NovaNetClusterReconciler) reconcileServiceAccount(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.serviceAccountName(cluster),
			Namespace: cluster.Namespace,
			Labels:    r.getLabels(cluster),
		},
	}
	if err := controllerutil.SetControllerReference(cluster, sa, r.Scheme); err != nil {
		return fmt.Errorf("setting owner reference: %w", err)
	}
	return r.createOrUpdate(ctx, sa)
}

func (r *NovaNetClusterReconciler) reconcileClusterRole(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   r.clusterRoleName(cluster),
			Labels: r.getLabels(cluster),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
		},
	}
	// ClusterRole is cluster-scoped, so no owner reference.
	return r.createOrUpdate(ctx, cr)
}

func (r *NovaNetClusterReconciler) reconcileClusterRoleBinding(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   r.clusterRoleBindingName(cluster),
			Labels: r.getLabels(cluster),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     r.clusterRoleName(cluster),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      r.serviceAccountName(cluster),
				Namespace: cluster.Namespace,
			},
		},
	}
	return r.createOrUpdate(ctx, crb)
}

// ---------------------------------------------------------------------------
// ConfigMap
// ---------------------------------------------------------------------------

// novanetConfig mirrors the JSON config the agent reads at /etc/novanet/novanet.json.
type novanetConfig struct {
	ListenSocket    string              `json:"listen_socket"`
	CNISocket       string              `json:"cni_socket"`
	DataplaneSocket string              `json:"dataplane_socket"`
	ClusterCIDR     string              `json:"cluster_cidr"`
	NodeCIDRMask    int                 `json:"node_cidr_mask_size"`
	TunnelProtocol  string              `json:"tunnel_protocol"`
	RoutingMode     string              `json:"routing_mode"`
	NovaRoute       novanetNovaRouteCfg `json:"novaroute"`
	Egress          novanetEgressCfg    `json:"egress"`
	Policy          novanetPolicyCfg    `json:"policy"`
	LogLevel        string              `json:"log_level"`
	MetricsAddress  string              `json:"metrics_address"`
}

type novanetNovaRouteCfg struct {
	Socket                        string `json:"socket"`
	Token                         string `json:"token"`
	Protocol                      string `json:"protocol"`
	ControlPlaneVIP               string `json:"control_plane_vip,omitempty"`
	ControlPlaneVIPHealthInterval int    `json:"control_plane_vip_health_interval,omitempty"`
}

type novanetEgressCfg struct {
	MasqueradeEnabled bool `json:"masquerade_enabled"`
}

type novanetPolicyCfg struct {
	DefaultDeny bool `json:"default_deny"`
}

func (r *NovaNetClusterReconciler) reconcileConfigMap(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	metricsPort := int32(9090)
	if cluster.Spec.Agent.MetricsPort != nil {
		metricsPort = *cluster.Spec.Agent.MetricsPort
	}

	cfg := novanetConfig{
		ListenSocket:    "/run/novanet/novanet.sock",
		CNISocket:       "/run/novanet/cni.sock",
		DataplaneSocket: "/run/novanet/dataplane.sock",
		ClusterCIDR:     cluster.Spec.Networking.ClusterCIDR,
		NodeCIDRMask:    24,
		TunnelProtocol:  cluster.Spec.Networking.TunnelProtocol,
		RoutingMode:     cluster.Spec.Networking.RoutingMode,
		Egress:          novanetEgressCfg{MasqueradeEnabled: true},
		Policy:          novanetPolicyCfg{DefaultDeny: false},
		LogLevel:        cluster.Spec.Agent.LogLevel,
		MetricsAddress:  fmt.Sprintf(":%d", metricsPort),
	}

	if cluster.Spec.NovaRouteIntegration != nil && cluster.Spec.NovaRouteIntegration.Enabled {
		socketPath := "/run/novaroute/novaroute.sock"
		if cluster.Spec.NovaRouteIntegration.SocketPath != "" {
			socketPath = cluster.Spec.NovaRouteIntegration.SocketPath
		}
		cfg.NovaRoute = novanetNovaRouteCfg{
			Socket:          socketPath,
			Token:           cluster.Spec.NovaRouteIntegration.OwnerToken,
			Protocol:        "bgp",
			ControlPlaneVIP: cluster.Spec.Networking.ControlPlaneVIP,
		}
	}

	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.componentName(cluster),
			Namespace: cluster.Namespace,
			Labels:    r.getLabels(cluster),
		},
		Data: map[string]string{
			"novanet.json": string(cfgJSON),
		},
	}

	if err := controllerutil.SetControllerReference(cluster, cm, r.Scheme); err != nil {
		return fmt.Errorf("setting owner reference: %w", err)
	}
	return r.createOrUpdate(ctx, cm)
}

// ---------------------------------------------------------------------------
// DaemonSet
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) reconcileDaemonSet(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	metricsPort := int32(9090)
	if cluster.Spec.Agent.MetricsPort != nil {
		metricsPort = *cluster.Spec.Agent.MetricsPort
	}

	// Resolve images
	agentImage := r.getImage(cluster, "novanet-agent")
	if cluster.Spec.Agent.Image != "" {
		agentImage = cluster.Spec.Agent.Image
	}

	dataplaneImage := r.getImage(cluster, "novanet-dataplane")
	if cluster.Spec.Dataplane.Image != "" {
		dataplaneImage = cluster.Spec.Dataplane.Image
	}

	cniImage := agentImage // CNI init container uses the agent image by default
	if cluster.Spec.CNI != nil && cluster.Spec.CNI.Image != "" {
		cniImage = cluster.Spec.CNI.Image
	}

	cniBinDir := "/opt/cni/bin"
	cniConfDir := "/etc/cni/net.d"
	if cluster.Spec.CNI != nil {
		if cluster.Spec.CNI.BinDir != "" {
			cniBinDir = cluster.Spec.CNI.BinDir
		}
		if cluster.Spec.CNI.ConfDir != "" {
			cniConfDir = cluster.Spec.CNI.ConfDir
		}
	}

	privileged := true
	hostPathDirectoryOrCreate := corev1.HostPathDirectoryOrCreate
	hostPathDirectory := corev1.HostPathDirectory
	bidirectional := corev1.MountPropagationBidirectional
	hostToContainer := corev1.MountPropagationHostToContainer

	// ---------------------------------------------------------------
	// Init container: install-cni
	// ---------------------------------------------------------------
	initContainer := corev1.Container{
		Name:            "install-cni",
		Image:           cniImage,
		ImagePullPolicy: cluster.Spec.ImagePullPolicy,
		Command: []string{
			"/bin/sh", "-c",
			`# Copy the CNI binary to the host.
cp /usr/bin/novanet-cni /host/opt/cni/bin/novanet-cni
chmod 755 /host/opt/cni/bin/novanet-cni
# Install the loopback plugin (required by containerd CRI).
cp /usr/lib/cni/loopback /host/opt/cni/bin/loopback
chmod 755 /host/opt/cni/bin/loopback
echo "CNI binary installed."`,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "cni-bin", MountPath: "/host/opt/cni/bin"},
			{Name: "cni-conf", MountPath: "/host/etc/cni/net.d"},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: boolPtr(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
	}

	// ---------------------------------------------------------------
	// Agent container
	// ---------------------------------------------------------------
	agentContainer := corev1.Container{
		Name:            "agent",
		Image:           agentImage,
		ImagePullPolicy: cluster.Spec.ImagePullPolicy,
		Command:         []string{"novanet-agent", "--config", "/etc/novanet/novanet.json"},
		Env: append([]corev1.EnvVar{
			{
				Name: "NOVANET_NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			},
		}, cluster.Spec.Agent.ExtraEnv...),
		Ports: []corev1.ContainerPort{
			{Name: "metrics", ContainerPort: metricsPort, Protocol: corev1.ProtocolTCP},
		},
		Resources: cluster.Spec.Agent.Resources,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"novanetctl", "status",
						"--agent-socket", "/run/novanet/novanet.sock",
					},
				},
			},
			InitialDelaySeconds: 15,
			PeriodSeconds:       15,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"novanetctl", "status",
						"--agent-socket", "/run/novanet/novanet.sock",
					},
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/novanet", ReadOnly: true},
			{Name: "run-novanet", MountPath: "/run/novanet"},
			{Name: "netns", MountPath: "/run/netns", MountPropagation: &hostToContainer},
			{Name: "bpf-maps", MountPath: "/sys/fs/bpf", MountPropagation: &bidirectional},
			{Name: "lib-modules", MountPath: "/lib/modules", ReadOnly: true},
			{Name: "cni-state", MountPath: "/var/lib/cni"},
		},
	}

	// Add NovaRoute volume mount to agent if enabled
	if cluster.Spec.NovaRouteIntegration != nil && cluster.Spec.NovaRouteIntegration.Enabled {
		agentContainer.VolumeMounts = append(agentContainer.VolumeMounts, corev1.VolumeMount{
			Name:      "run-novaroute",
			MountPath: "/run/novaroute",
			ReadOnly:  true,
		})
	}

	// ---------------------------------------------------------------
	// Dataplane container
	// ---------------------------------------------------------------
	dataplaneContainer := corev1.Container{
		Name:            "dataplane",
		Image:           dataplaneImage,
		ImagePullPolicy: cluster.Spec.ImagePullPolicy,
		Command:         []string{"novanet-dataplane", "--socket", "/run/novanet/dataplane.sock"},
		Resources:       cluster.Spec.Dataplane.Resources,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"test", "-S", "/run/novanet/dataplane.sock"},
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       15,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"test", "-S", "/run/novanet/dataplane.sock"},
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       5,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "run-novanet", MountPath: "/run/novanet"},
			{Name: "bpf-maps", MountPath: "/sys/fs/bpf", MountPropagation: &bidirectional},
			{Name: "proc", MountPath: "/proc", ReadOnly: true},
		},
	}

	// ---------------------------------------------------------------
	// Volumes
	// ---------------------------------------------------------------
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: r.componentName(cluster),
					},
				},
			},
		},
		{
			Name:         "run-novanet",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/novanet", Type: &hostPathDirectoryOrCreate}},
		},
		{
			Name:         "cni-bin",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniBinDir, Type: &hostPathDirectoryOrCreate}},
		},
		{
			Name:         "cni-conf",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniConfDir, Type: &hostPathDirectoryOrCreate}},
		},
		{
			Name:         "netns",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/netns", Type: &hostPathDirectoryOrCreate}},
		},
		{
			Name:         "bpf-maps",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &hostPathDirectoryOrCreate}},
		},
		{
			Name:         "proc",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc", Type: &hostPathDirectory}},
		},
		{
			Name:         "lib-modules",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules", Type: &hostPathDirectory}},
		},
		{
			Name:         "cni-state",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/cni", Type: &hostPathDirectoryOrCreate}},
		},
	}

	// Add NovaRoute volume if enabled
	if cluster.Spec.NovaRouteIntegration != nil && cluster.Spec.NovaRouteIntegration.Enabled {
		volumes = append(volumes, corev1.Volume{
			Name:         "run-novaroute",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/novaroute", Type: &hostPathDirectoryOrCreate}},
		})
	}

	// ---------------------------------------------------------------
	// Tolerations
	// ---------------------------------------------------------------
	tolerations := cluster.Spec.Tolerations
	if len(tolerations) == 0 {
		// Default tolerations for a CNI: tolerate everything so we run on all nodes
		tolerations = []corev1.Toleration{
			{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
		}
	}

	// ---------------------------------------------------------------
	// Node selector
	// ---------------------------------------------------------------
	nodeSelector := cluster.Spec.NodeSelector
	if nodeSelector == nil {
		nodeSelector = map[string]string{"kubernetes.io/os": "linux"}
	}

	// ---------------------------------------------------------------
	// DaemonSet spec
	// ---------------------------------------------------------------
	terminationGrace := int64(30)

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.componentName(cluster),
			Namespace: cluster.Namespace,
			Labels:    r.getLabels(cluster),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.getSelectorLabels(cluster),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.getLabels(cluster),
				},
				Spec: corev1.PodSpec{
					HostNetwork:                   true,
					DNSPolicy:                     corev1.DNSClusterFirstWithHostNet,
					ServiceAccountName:            r.serviceAccountName(cluster),
					PriorityClassName:             "system-node-critical",
					TerminationGracePeriodSeconds: &terminationGrace,
					NodeSelector:                  nodeSelector,
					Tolerations:                   tolerations,
					ImagePullSecrets:              cluster.Spec.ImagePullSecrets,
					InitContainers:                []corev1.Container{initContainer},
					Containers:                    []corev1.Container{agentContainer, dataplaneContainer},
					Volumes:                       volumes,
				},
			},
		},
	}

	// Apply update strategy
	if cluster.Spec.UpdateStrategy != nil {
		if cluster.Spec.UpdateStrategy.Type == "OnDelete" {
			ds.Spec.UpdateStrategy = appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.OnDeleteDaemonSetStrategyType,
			}
		} else {
			maxUnavailable := intstr.FromInt32(1)
			if cluster.Spec.UpdateStrategy.MaxUnavailable != nil {
				maxUnavailable = intstr.FromInt32(*cluster.Spec.UpdateStrategy.MaxUnavailable)
			}
			ds.Spec.UpdateStrategy = appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			}
		}
	}

	if err := controllerutil.SetControllerReference(cluster, ds, r.Scheme); err != nil {
		return fmt.Errorf("setting owner reference: %w", err)
	}
	return r.createOrUpdate(ctx, ds)
}

// ---------------------------------------------------------------------------
// Metrics Service
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) reconcileMetricsService(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	metricsPort := int32(9090)
	if cluster.Spec.Agent.MetricsPort != nil {
		metricsPort = *cluster.Spec.Agent.MetricsPort
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-metrics", r.componentName(cluster)),
			Namespace: cluster.Namespace,
			Labels:    r.getLabels(cluster),
		},
		Spec: corev1.ServiceSpec{
			Selector: r.getSelectorLabels(cluster),
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics",
					Port:       metricsPort,
					TargetPort: intstr.FromInt32(metricsPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, svc, r.Scheme); err != nil {
		return fmt.Errorf("setting owner reference: %w", err)
	}
	return r.createOrUpdate(ctx, svc)
}

// ---------------------------------------------------------------------------
// PodDisruptionBudget
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) reconcilePDB(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	maxUnavailable := intstr.FromInt32(1)

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.componentName(cluster),
			Namespace: cluster.Namespace,
			Labels:    r.getLabels(cluster),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.getSelectorLabels(cluster),
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, pdb, r.Scheme); err != nil {
		return fmt.Errorf("setting owner reference: %w", err)
	}
	return r.createOrUpdate(ctx, pdb)
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) updateStatus(ctx context.Context, cluster *novanetv1alpha1.NovaNetCluster) error {
	logger := log.FromContext(ctx)

	// Fetch DaemonSet status
	ds := &appsv1.DaemonSet{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      r.componentName(cluster),
		Namespace: cluster.Namespace,
	}, ds); err == nil {
		cluster.Status.Agent = &novanetv1alpha1.ComponentStatus{
			Ready:        ds.Status.NumberReady == ds.Status.DesiredNumberScheduled,
			DesiredNodes: ds.Status.DesiredNumberScheduled,
			ReadyNodes:   ds.Status.NumberReady,
			UpdatedNodes: ds.Status.UpdatedNumberScheduled,
		}
	}

	agentReady := cluster.Status.Agent != nil && cluster.Status.Agent.Ready

	// Set conditions
	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeAgentOK,
		Status:             conditionStatus(agentReady),
		ObservedGeneration: cluster.Generation,
		Reason:             conditionReason(agentReady, "AgentReady", "AgentNotReady"),
		Message:            conditionMessage(agentReady, "Agent DaemonSet is ready", "Agent DaemonSet is not ready"),
	})

	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             conditionStatus(agentReady),
		ObservedGeneration: cluster.Generation,
		Reason:             conditionReason(agentReady, "AllComponentsReady", "SomeComponentsNotReady"),
		Message:            conditionMessage(agentReady, "All components are ready", "Some components are not ready"),
	})

	// Update phase
	switch {
	case agentReady:
		cluster.Status.Phase = novanetv1alpha1.ClusterPhaseRunning
	case cluster.Status.Agent != nil && cluster.Status.Agent.ReadyNodes > 0:
		cluster.Status.Phase = novanetv1alpha1.ClusterPhaseDegraded
	default:
		cluster.Status.Phase = novanetv1alpha1.ClusterPhaseInitializing
	}

	cluster.Status.Version = cluster.Spec.Version
	cluster.Status.ObservedGeneration = cluster.Generation

	if err := r.Status().Update(ctx, cluster); err != nil {
		logger.Error(err, "Failed to update NovaNetCluster status")
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *NovaNetClusterReconciler) componentName(cluster *novanetv1alpha1.NovaNetCluster) string {
	return cluster.Name
}

func (r *NovaNetClusterReconciler) serviceAccountName(cluster *novanetv1alpha1.NovaNetCluster) string {
	return fmt.Sprintf("%s-agent", cluster.Name)
}

func (r *NovaNetClusterReconciler) clusterRoleName(cluster *novanetv1alpha1.NovaNetCluster) string {
	return fmt.Sprintf("%s-%s-agent", cluster.Namespace, cluster.Name)
}

func (r *NovaNetClusterReconciler) clusterRoleBindingName(cluster *novanetv1alpha1.NovaNetCluster) string {
	return fmt.Sprintf("%s-%s-agent", cluster.Namespace, cluster.Name)
}

func (r *NovaNetClusterReconciler) getLabels(cluster *novanetv1alpha1.NovaNetCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "novanet",
		"app.kubernetes.io/instance":   cluster.Name,
		"app.kubernetes.io/component":  "agent",
		"app.kubernetes.io/version":    cluster.Spec.Version,
		"app.kubernetes.io/managed-by": "novanet-operator",
	}
}

func (r *NovaNetClusterReconciler) getSelectorLabels(cluster *novanetv1alpha1.NovaNetCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "novanet",
		"app.kubernetes.io/instance":  cluster.Name,
		"app.kubernetes.io/component": "agent",
	}
}

func (r *NovaNetClusterReconciler) getImage(cluster *novanetv1alpha1.NovaNetCluster, component string) string {
	repo := "ghcr.io/azrtydxb/novanet"
	if cluster.Spec.ImageRepository != "" {
		repo = cluster.Spec.ImageRepository
	}
	return fmt.Sprintf("%s/%s:%s", repo, component, cluster.Spec.Version)
}

func (r *NovaNetClusterReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	logger := log.FromContext(ctx)

	key := client.ObjectKeyFromObject(obj)
	existingObj := obj.DeepCopyObject()
	existing, ok := existingObj.(client.Object)
	if !ok {
		return errNotClientObject
	}

	if err := r.Get(ctx, key, existing); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating resource",
				"kind", obj.GetObjectKind().GroupVersionKind().Kind,
				"name", key.Name,
				"namespace", key.Namespace)
			return r.Create(ctx, obj)
		}
		return fmt.Errorf("getting resource %s/%s: %w", key.Namespace, key.Name, err)
	}

	obj.SetResourceVersion(existing.GetResourceVersion())
	logger.V(1).Info("Updating resource",
		"kind", obj.GetObjectKind().GroupVersionKind().Kind,
		"name", key.Name,
		"namespace", key.Namespace)
	return r.Update(ctx, obj)
}

func conditionStatus(ready bool) metav1.ConditionStatus {
	if ready {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func conditionReason(ready bool, trueReason, falseReason string) string {
	if ready {
		return trueReason
	}
	return falseReason
}

func conditionMessage(ready bool, trueMsg, falseMsg string) string {
	if ready {
		return trueMsg
	}
	return falseMsg
}

func boolPtr(b bool) *bool {
	return &b
}

// SetupWithManager sets up the controller with the Manager.
func (r *NovaNetClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&novanetv1alpha1.NovaNetCluster{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Complete(r)
}
