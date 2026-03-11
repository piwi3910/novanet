package webhook

import (
	"context"
	"net"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

// EgressGatewayPolicyValidator validates EgressGatewayPolicy resources.
type EgressGatewayPolicyValidator struct{}

// SetupEgressGatewayPolicyWebhookWithManager registers the validating webhook.
func SetupEgressGatewayPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &novanetv1alpha1.EgressGatewayPolicy{}).
		WithValidator(&EgressGatewayPolicyValidator{}).
		Complete()
}

// ValidateCreate validates a new EgressGatewayPolicy.
func (v *EgressGatewayPolicyValidator) ValidateCreate(_ context.Context, egp *novanetv1alpha1.EgressGatewayPolicy) (admission.Warnings, error) {
	return nil, validateEgressGatewayPolicySpec(&egp.Spec).ToAggregate()
}

// ValidateUpdate validates an updated EgressGatewayPolicy.
func (v *EgressGatewayPolicyValidator) ValidateUpdate(_ context.Context, _ *novanetv1alpha1.EgressGatewayPolicy, egp *novanetv1alpha1.EgressGatewayPolicy) (admission.Warnings, error) {
	return nil, validateEgressGatewayPolicySpec(&egp.Spec).ToAggregate()
}

// ValidateDelete is a no-op for EgressGatewayPolicy.
func (v *EgressGatewayPolicyValidator) ValidateDelete(_ context.Context, _ *novanetv1alpha1.EgressGatewayPolicy) (admission.Warnings, error) {
	return nil, nil
}

func validateEgressGatewayPolicySpec(spec *novanetv1alpha1.EgressGatewayPolicySpec) field.ErrorList {
	allErrs := make(field.ErrorList, 0)

	destPath := field.NewPath("spec", "destinationCIDRs")
	for i, cidr := range spec.DestinationCIDRs {
		if err := validateCIDR(cidr); err != nil {
			allErrs = append(allErrs, field.Invalid(destPath.Index(i), cidr, err.Error()))
		}
	}

	exclPath := field.NewPath("spec", "excludedCIDRs")
	for i, cidr := range spec.ExcludedCIDRs {
		if err := validateCIDR(cidr); err != nil {
			allErrs = append(allErrs, field.Invalid(exclPath.Index(i), cidr, err.Error()))
		}
	}

	if spec.EgressIP != "" {
		if net.ParseIP(spec.EgressIP) == nil {
			allErrs = append(allErrs, field.Invalid(
				field.NewPath("spec", "egressIP"), spec.EgressIP, "invalid IP address"))
		}
	}

	return allErrs
}
