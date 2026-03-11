package webhook

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

// NovanetClusterValidator validates NovaNetCluster resources.
type NovanetClusterValidator struct{}

// SetupNovanetClusterWebhookWithManager registers the validating webhook.
func SetupNovanetClusterWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &novanetv1alpha1.NovaNetCluster{}).
		WithValidator(&NovanetClusterValidator{}).
		Complete()
}

// ValidateCreate validates a new NovaNetCluster.
func (v *NovanetClusterValidator) ValidateCreate(_ context.Context, nnc *novanetv1alpha1.NovaNetCluster) (admission.Warnings, error) {
	return nil, validateNovanetClusterSpec(&nnc.Spec).ToAggregate()
}

// ValidateUpdate validates an updated NovaNetCluster.
func (v *NovanetClusterValidator) ValidateUpdate(_ context.Context, _ *novanetv1alpha1.NovaNetCluster, nnc *novanetv1alpha1.NovaNetCluster) (admission.Warnings, error) {
	return nil, validateNovanetClusterSpec(&nnc.Spec).ToAggregate()
}

// ValidateDelete is a no-op for NovaNetCluster.
func (v *NovanetClusterValidator) ValidateDelete(_ context.Context, _ *novanetv1alpha1.NovaNetCluster) (admission.Warnings, error) {
	return nil, nil
}

func validateNovanetClusterSpec(spec *novanetv1alpha1.NovaNetClusterSpec) field.ErrorList {
	allErrs := make(field.ErrorList, 0)

	netPath := field.NewPath("spec", "networking")

	// Validate ClusterCIDR (required).
	if err := validateCIDR(spec.Networking.ClusterCIDR); err != nil {
		allErrs = append(allErrs, field.Invalid(netPath.Child("clusterCIDR"),
			spec.Networking.ClusterCIDR, err.Error()))
	}

	// Validate optional IPv6 ClusterCIDR.
	if spec.Networking.ClusterCIDRv6 != "" {
		if err := validateCIDR(spec.Networking.ClusterCIDRv6); err != nil {
			allErrs = append(allErrs, field.Invalid(netPath.Child("clusterCIDRv6"),
				spec.Networking.ClusterCIDRv6, err.Error()))
		}
	}

	// Validate optional ControlPlaneVIP.
	if spec.Networking.ControlPlaneVIP != "" {
		if err := validateIP(spec.Networking.ControlPlaneVIP); err != nil {
			allErrs = append(allErrs, field.Invalid(netPath.Child("controlPlaneVIP"),
				spec.Networking.ControlPlaneVIP, err.Error()))
		}
	}

	// Validate MTU range if provided.
	if spec.Networking.MTU != nil {
		mtu := *spec.Networking.MTU
		if mtu != 0 && (mtu < 1280 || mtu > 9000) {
			allErrs = append(allErrs, field.Invalid(netPath.Child("mtu"), mtu,
				"MTU must be 0 (auto) or between 1280 and 9000"))
		}
	}

	// Validate optional WireGuard port.
	if spec.Encryption != nil && spec.Encryption.WireGuardPort != nil {
		port := *spec.Encryption.WireGuardPort
		if port < 1 || port > 65535 {
			allErrs = append(allErrs, field.Invalid(
				field.NewPath("spec", "encryption", "wireGuardPort"), port,
				"port must be in range [1, 65535]"))
		}
	}

	// Validate agent ports.
	agentPath := field.NewPath("spec", "agent")
	if spec.Agent.MetricsPort != nil {
		if err := validatePort(*spec.Agent.MetricsPort); err != nil {
			allErrs = append(allErrs, field.Invalid(agentPath.Child("metricsPort"),
				*spec.Agent.MetricsPort, err.Error()))
		}
	}
	if spec.Agent.HealthPort != nil {
		if err := validatePort(*spec.Agent.HealthPort); err != nil {
			allErrs = append(allErrs, field.Invalid(agentPath.Child("healthPort"),
				*spec.Agent.HealthPort, err.Error()))
		}
	}

	return allErrs
}
