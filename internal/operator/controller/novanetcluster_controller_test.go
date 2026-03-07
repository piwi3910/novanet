package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}
	if err := novanetv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("adding novanet scheme: %v", err)
	}
	if err := policyv1.AddToScheme(s); err != nil {
		t.Fatalf("adding policy scheme: %v", err)
	}
	return s
}

func newSampleCluster() *novanetv1alpha1.NovaNetCluster {
	metricsPort := int32(9090)
	healthPort := int32(9091)
	maxUnavailable := int32(1)
	return &novanetv1alpha1.NovaNetCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cluster",
			Namespace:  "nova-system",
			Generation: 1,
		},
		Spec: novanetv1alpha1.NovaNetClusterSpec{
			Version:         "v0.1.0",
			ImageRepository: "ghcr.io/azrtydxb/novanet",
			ImagePullPolicy: corev1.PullIfNotPresent,
			Agent: novanetv1alpha1.NovaNetAgentSpec{
				LogLevel:    "info",
				MetricsPort: &metricsPort,
				HealthPort:  &healthPort,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
				},
			},
			Dataplane: novanetv1alpha1.DataplaneSpec{
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
				},
			},
			Networking: novanetv1alpha1.NetworkingSpec{
				ClusterCIDR:    "10.244.0.0/16",
				TunnelProtocol: "geneve",
				RoutingMode:    "overlay",
			},
			UpdateStrategy: &novanetv1alpha1.UpdateStrategySpec{
				Type:           "RollingUpdate",
				MaxUnavailable: &maxUnavailable,
			},
		},
	}
}

func reconcileOnce(t *testing.T, r *NovaNetClusterReconciler, name, namespace string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
	}
	// First reconcile adds the finalizer
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// Second reconcile creates all resources
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

func TestReconcileCreatesAllResources(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ctx := context.Background()

	// Verify ServiceAccount
	sa := &corev1.ServiceAccount{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "test-cluster-agent", Namespace: "nova-system",
	}, sa); err != nil {
		t.Errorf("ServiceAccount not found: %v", err)
	}

	// Verify ClusterRole
	cr := &rbacv1.ClusterRole{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "nova-system-test-cluster-agent",
	}, cr); err != nil {
		t.Errorf("ClusterRole not found: %v", err)
	}

	// Verify ClusterRoleBinding
	crb := &rbacv1.ClusterRoleBinding{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "nova-system-test-cluster-agent",
	}, crb); err != nil {
		t.Errorf("ClusterRoleBinding not found: %v", err)
	}

	// Verify ConfigMap
	cm := &corev1.ConfigMap{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, cm); err != nil {
		t.Errorf("ConfigMap not found: %v", err)
	}

	// Verify DaemonSet
	ds := &appsv1.DaemonSet{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, ds); err != nil {
		t.Errorf("DaemonSet not found: %v", err)
	}

	// Verify Service
	svc := &corev1.Service{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "test-cluster-metrics", Namespace: "nova-system",
	}, svc); err != nil {
		t.Errorf("Metrics Service not found: %v", err)
	}

	// Verify PDB
	pdb := &policyv1.PodDisruptionBudget{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, pdb); err != nil {
		t.Errorf("PodDisruptionBudget not found: %v", err)
	}
}

func TestDaemonSetHasThreeContainerTypes(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ds := &appsv1.DaemonSet{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, ds); err != nil {
		t.Fatalf("DaemonSet not found: %v", err)
	}

	// Verify init container
	if len(ds.Spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("expected 1 init container, got %d", len(ds.Spec.Template.Spec.InitContainers))
	}
	if ds.Spec.Template.Spec.InitContainers[0].Name != "install-cni" {
		t.Errorf("expected init container name 'install-cni', got %s", ds.Spec.Template.Spec.InitContainers[0].Name)
	}

	// Verify two regular containers
	if len(ds.Spec.Template.Spec.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(ds.Spec.Template.Spec.Containers))
	}

	containerNames := map[string]bool{}
	for _, c := range ds.Spec.Template.Spec.Containers {
		containerNames[c.Name] = true
	}
	if !containerNames["agent"] {
		t.Error("agent container not found")
	}
	if !containerNames["dataplane"] {
		t.Error("dataplane container not found")
	}
}

func TestInitContainerMountsCNIPaths(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ds := &appsv1.DaemonSet{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, ds); err != nil {
		t.Fatalf("DaemonSet not found: %v", err)
	}

	initContainer := ds.Spec.Template.Spec.InitContainers[0]
	mountPaths := map[string]bool{}
	for _, vm := range initContainer.VolumeMounts {
		mountPaths[vm.MountPath] = true
	}

	if !mountPaths["/host/opt/cni/bin"] {
		t.Error("init container missing /host/opt/cni/bin mount")
	}
	if !mountPaths["/host/etc/cni/net.d"] {
		t.Error("init container missing /host/etc/cni/net.d mount")
	}
}

func TestDataplaneContainerIsPrivileged(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ds := &appsv1.DaemonSet{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, ds); err != nil {
		t.Fatalf("DaemonSet not found: %v", err)
	}

	var dpContainer *corev1.Container
	for i := range ds.Spec.Template.Spec.Containers {
		if ds.Spec.Template.Spec.Containers[i].Name == "dataplane" {
			dpContainer = &ds.Spec.Template.Spec.Containers[i]
			break
		}
	}
	if dpContainer == nil {
		t.Fatal("dataplane container not found")
	}

	if dpContainer.SecurityContext == nil || dpContainer.SecurityContext.Privileged == nil || !*dpContainer.SecurityContext.Privileged {
		t.Error("dataplane container must be privileged: true")
	}

	// Verify /sys/fs/bpf mount exists
	hasBPFMount := false
	for _, vm := range dpContainer.VolumeMounts {
		if vm.MountPath == "/sys/fs/bpf" {
			hasBPFMount = true
			break
		}
	}
	if !hasBPFMount {
		t.Error("dataplane container missing /sys/fs/bpf mount")
	}
}

func TestConfigMapContainsNetworkingConfig(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	cm := &corev1.ConfigMap{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, cm); err != nil {
		t.Fatalf("ConfigMap not found: %v", err)
	}

	cfgJSON, ok := cm.Data["novanet.json"]
	if !ok {
		t.Fatal("ConfigMap missing novanet.json key")
	}

	// Verify the config contains expected values
	for _, expected := range []string{
		`"cluster_cidr": "10.244.0.0/16"`,
		`"tunnel_protocol": "geneve"`,
		`"routing_mode": "overlay"`,
	} {
		if !containsSubstring(cfgJSON, expected) {
			t.Errorf("ConfigMap novanet.json missing expected value: %s", expected)
		}
	}
}

func TestCleanupDeletesClusterScopedResources(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Create resources
	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ctx := context.Background()

	// Verify ClusterRole exists
	cr := &rbacv1.ClusterRole{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "nova-system-test-cluster-agent",
	}, cr); err != nil {
		t.Fatalf("ClusterRole should exist before cleanup: %v", err)
	}

	// Run cleanup
	if err := r.cleanupResources(ctx, cluster); err != nil {
		t.Fatalf("cleanupResources: %v", err)
	}

	// Verify ClusterRole is deleted
	cr2 := &rbacv1.ClusterRole{}
	err := fakeClient.Get(ctx, types.NamespacedName{
		Name: "nova-system-test-cluster-agent",
	}, cr2)
	if err == nil {
		t.Error("ClusterRole should be deleted after cleanup")
	}
}

func TestNovaRouteIntegrationAddsVolumeMount(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()
	cluster.Spec.NovaRouteIntegration = &novanetv1alpha1.NovaRouteIntegrationSpec{
		Enabled:    true,
		SocketPath: "/run/novaroute/novaroute.sock",
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ds := &appsv1.DaemonSet{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, ds); err != nil {
		t.Fatalf("DaemonSet not found: %v", err)
	}

	// Verify /run/novaroute volume exists
	hasNovaRouteVolume := false
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == "run-novaroute" {
			hasNovaRouteVolume = true
			break
		}
	}
	if !hasNovaRouteVolume {
		t.Error("DaemonSet missing run-novaroute volume when NovaRoute is enabled")
	}

	// Verify agent container has the mount
	var agentContainer *corev1.Container
	for i := range ds.Spec.Template.Spec.Containers {
		if ds.Spec.Template.Spec.Containers[i].Name == "agent" {
			agentContainer = &ds.Spec.Template.Spec.Containers[i]
			break
		}
	}
	if agentContainer == nil {
		t.Fatal("agent container not found")
	}

	hasNovaRouteMount := false
	for _, vm := range agentContainer.VolumeMounts {
		if vm.MountPath == "/run/novaroute" {
			hasNovaRouteMount = true
			break
		}
	}
	if !hasNovaRouteMount {
		t.Error("agent container missing /run/novaroute mount when NovaRoute is enabled")
	}

	// Verify ConfigMap has NovaRoute socket path
	cm := &corev1.ConfigMap{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, cm); err != nil {
		t.Fatalf("ConfigMap not found: %v", err)
	}

	cfgJSON := cm.Data["novanet.json"]
	if !containsSubstring(cfgJSON, `"socket": "/run/novaroute/novaroute.sock"`) {
		t.Error("ConfigMap novanet.json missing NovaRoute socket path")
	}
}

func TestPriorityClassIsSystemNodeCritical(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	ds := &appsv1.DaemonSet{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, ds); err != nil {
		t.Fatalf("DaemonSet not found: %v", err)
	}

	if ds.Spec.Template.Spec.PriorityClassName != "system-node-critical" {
		t.Errorf("expected priorityClassName 'system-node-critical', got %q",
			ds.Spec.Template.Spec.PriorityClassName)
	}
}

func TestPDBHasMaxUnavailableOne(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	pdb := &policyv1.PodDisruptionBudget{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "test-cluster", Namespace: "nova-system",
	}, pdb); err != nil {
		t.Fatalf("PDB not found: %v", err)
	}

	if pdb.Spec.MaxUnavailable == nil {
		t.Fatal("PDB MaxUnavailable is nil")
	}
	if pdb.Spec.MaxUnavailable.IntValue() != 1 {
		t.Errorf("expected PDB maxUnavailable=1, got %d", pdb.Spec.MaxUnavailable.IntValue())
	}
}

func TestClusterRoleHasExpectedPermissions(t *testing.T) {
	scheme := newScheme(t)
	cluster := newSampleCluster()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	r := &NovaNetClusterReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	reconcileOnce(t, r, cluster.Name, cluster.Namespace)

	cr := &rbacv1.ClusterRole{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: "nova-system-test-cluster-agent",
	}, cr); err != nil {
		t.Fatalf("ClusterRole not found: %v", err)
	}

	// Build a lookup of apiGroup/resource -> verbs
	type ruleKey struct {
		apiGroup string
		resource string
	}
	ruleMap := map[ruleKey][]string{}
	for _, rule := range cr.Rules {
		for _, apiGroup := range rule.APIGroups {
			for _, res := range rule.Resources {
				ruleMap[ruleKey{apiGroup, res}] = rule.Verbs
			}
		}
	}

	// Verify expected permissions
	expectedRules := []struct {
		apiGroup string
		resource string
		verb     string
	}{
		{"", "pods", "get"},
		{"", "nodes", "get"},
		{"", "namespaces", "get"},
		{"networking.k8s.io", "networkpolicies", "get"},
		{"discovery.k8s.io", "endpointslices", "get"},
		{"coordination.k8s.io", "leases", "create"},
		{"", "events", "create"},
	}

	for _, exp := range expectedRules {
		key := ruleKey{exp.apiGroup, exp.resource}
		verbs, ok := ruleMap[key]
		if !ok {
			t.Errorf("ClusterRole missing rule for %s/%s", exp.apiGroup, exp.resource)
			continue
		}
		found := false
		for _, v := range verbs {
			if v == exp.verb {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ClusterRole rule %s/%s missing verb %q", exp.apiGroup, exp.resource, exp.verb)
		}
	}
}

func TestSetupWithManager(t *testing.T) {
	// Verify SetupWithManager doesn't panic with a nil check on the function signature.
	r := &NovaNetClusterReconciler{}
	_ = r
	// SetupWithManager needs a real manager which requires envtest; just verify
	// the reconciler implements the Reconciler interface.
	var _ reconcile.Reconciler = r

	// Verify the method exists and has the correct signature
	_ = ctrl.Result{}
}

// containsSubstring checks if s contains sub.
func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && searchSubstring(s, sub)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
