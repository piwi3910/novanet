package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
	"github.com/azrtydxb/novanet/internal/ipam"
)

// IPPoolReconciler reconciles IPPool objects, syncing them to the in-memory
// IPAM manager.
type IPPoolReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Manager *ipam.Manager
}

// +kubebuilder:rbac:groups=novanet.io,resources=ippools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=novanet.io,resources=ippools/status,verbs=get;update;patch

// Reconcile syncs an IPPool CRD to the in-memory IPAM manager and updates
// the CRD status with current allocation counts.
func (r *IPPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling IPPool", "name", req.Name)

	pool := &novanetv1alpha1.IPPool{}
	if err := r.Get(ctx, req.NamespacedName, pool); err != nil {
		if errors.IsNotFound(err) {
			// Pool deleted — unregister from manager.
			r.Manager.UnregisterPool(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching IPPool: %w", err)
	}

	// Build pool config from CRD spec.
	cfg := ipam.PoolConfig{
		Name:       pool.Name,
		Type:       crdPoolTypeToIPAM(pool.Spec.Type),
		CIDRs:      pool.Spec.CIDRs,
		Addresses:  pool.Spec.Addresses,
		AutoAssign: pool.Spec.AutoAssign,
		Owner:      pool.Spec.Owner,
	}

	// Register or update the pool in the manager.
	if err := r.Manager.UpdatePool(cfg); err != nil {
		logger.Error(err, "failed to update pool in manager", "pool", pool.Name)

		meta.SetStatusCondition(&pool.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: pool.Generation,
			Reason:             "InvalidConfig",
			Message:            err.Error(),
		})
		_ = r.Status().Update(ctx, pool)
		return ctrl.Result{}, err
	}

	// Get status from manager and update CRD status.
	status, err := r.Manager.GetPool(pool.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting pool status: %w", err)
	}

	pool.Status.Allocated = int32(status.Allocated) //nolint:gosec // bounded by pool size
	pool.Status.Total = int32(status.Total)         //nolint:gosec // bounded by pool size
	pool.Status.Available = int32(status.Available) //nolint:gosec // bounded by pool size

	meta.SetStatusCondition(&pool.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: pool.Generation,
		Reason:             "PoolReady",
		Message:            fmt.Sprintf("Pool has %d available addresses", status.Available),
	})

	if err := r.Status().Update(ctx, pool); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating IPPool status: %w", err)
	}

	logger.Info("IPPool reconciled",
		"pool", pool.Name,
		"total", status.Total,
		"allocated", status.Allocated,
		"available", status.Available,
	)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IPPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&novanetv1alpha1.IPPool{}).
		Complete(r)
}

// crdPoolTypeToIPAM converts a CRD pool type to an IPAM pool type.
func crdPoolTypeToIPAM(t novanetv1alpha1.IPPoolType) ipam.PoolType {
	switch t {
	case novanetv1alpha1.IPPoolTypeLoadBalancerVIP:
		return ipam.PoolTypeLoadBalancerVIP
	case novanetv1alpha1.IPPoolTypeIngressIP:
		return ipam.PoolTypeIngressIP
	case novanetv1alpha1.IPPoolTypePodCIDR:
		return ipam.PoolTypePodCIDR
	case novanetv1alpha1.IPPoolTypeServiceClusterIP:
		return ipam.PoolTypeServiceClusterIP
	case novanetv1alpha1.IPPoolTypeCustom:
		return ipam.PoolTypeCustom
	default:
		return ipam.PoolTypeCustom
	}
}
