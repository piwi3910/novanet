package controller

import (
	"context"
	"errors"
	"fmt"
	"net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
	"github.com/azrtydxb/novanet/internal/ipam"
)

const ipAllocationFinalizer = "novanet.io/ipallocation-finalizer"

// IPAllocationReconciler reconciles IPAllocation objects, tracking allocations
// in the IPAM manager and handling cleanup on deletion.
type IPAllocationReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Manager *ipam.Manager
}

// +kubebuilder:rbac:groups=novanet.io,resources=ipallocations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=novanet.io,resources=ipallocations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=novanet.io,resources=ipallocations/finalizers,verbs=update

// Reconcile ensures the IP allocation is reflected in the in-memory manager
// and releases the IP when the CRD is deleted.
func (r *IPAllocationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling IPAllocation", "name", req.Name)

	alloc := &novanetv1alpha1.IPAllocation{}
	if err := r.Get(ctx, req.NamespacedName, alloc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching IPAllocation: %w", err)
	}

	// Handle deletion.
	if !alloc.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(alloc, ipAllocationFinalizer) {
			// Release the IP from the pool.
			ip := net.ParseIP(alloc.Spec.IP)
			if ip != nil {
				if err := r.Manager.Release(alloc.Spec.Pool, ip); err != nil {
					logger.Info("failed to release IP (may already be released)",
						"ip", alloc.Spec.IP,
						"pool", alloc.Spec.Pool,
						"error", err.Error(),
					)
				} else {
					logger.Info("released IP",
						"ip", alloc.Spec.IP,
						"pool", alloc.Spec.Pool,
					)
				}
			}

			controllerutil.RemoveFinalizer(alloc, ipAllocationFinalizer)
			if err := r.Update(ctx, alloc); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer is set.
	if !controllerutil.ContainsFinalizer(alloc, ipAllocationFinalizer) {
		controllerutil.AddFinalizer(alloc, ipAllocationFinalizer)
		if err := r.Update(ctx, alloc); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	// Ensure the IP is allocated in the manager.
	ip := net.ParseIP(alloc.Spec.IP)
	if ip == nil {
		alloc.Status.State = novanetv1alpha1.IPAllocationStateConflict
		meta.SetStatusCondition(&alloc.Status.Conditions, metav1.Condition{
			Type:               "Valid",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: alloc.Generation,
			Reason:             "InvalidIP",
			Message:            fmt.Sprintf("invalid IP address: %s", alloc.Spec.IP),
		})
		_ = r.Status().Update(ctx, alloc)
		return ctrl.Result{}, nil
	}

	err := r.Manager.AllocateSpecific(alloc.Spec.Pool, ip, alloc.Spec.Owner, alloc.Spec.Resource)
	if err != nil {
		// If already allocated, check if it's by us (idempotent).
		if isAlreadyAllocatedError(err) {
			// Already allocated — mark as bound.
			alloc.Status.State = novanetv1alpha1.IPAllocationStateBound
		} else {
			logger.Error(err, "failed to allocate IP",
				"ip", alloc.Spec.IP,
				"pool", alloc.Spec.Pool,
			)
			alloc.Status.State = novanetv1alpha1.IPAllocationStateConflict
			meta.SetStatusCondition(&alloc.Status.Conditions, metav1.Condition{
				Type:               "Valid",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: alloc.Generation,
				Reason:             "AllocationFailed",
				Message:            err.Error(),
			})
			_ = r.Status().Update(ctx, alloc)
			return ctrl.Result{}, nil
		}
	} else {
		alloc.Status.State = novanetv1alpha1.IPAllocationStateBound
	}

	meta.SetStatusCondition(&alloc.Status.Conditions, metav1.Condition{
		Type:               "Valid",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: alloc.Generation,
		Reason:             "Bound",
		Message:            fmt.Sprintf("IP %s allocated from pool %s", alloc.Spec.IP, alloc.Spec.Pool),
	})

	if err := r.Status().Update(ctx, alloc); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating IPAllocation status: %w", err)
	}

	logger.Info("IPAllocation reconciled",
		"name", alloc.Name,
		"ip", alloc.Spec.IP,
		"pool", alloc.Spec.Pool,
		"state", alloc.Status.State,
	)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IPAllocationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&novanetv1alpha1.IPAllocation{}).
		Complete(r)
}

// isAlreadyAllocatedError checks if the error wraps ErrIPAlreadyAlloc.
func isAlreadyAllocatedError(err error) bool {
	return errors.Is(err, ipam.ErrIPAlreadyAlloc)
}
