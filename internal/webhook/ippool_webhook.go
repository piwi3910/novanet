package webhook

import (
	"context"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

// IPPoolValidator validates IPPool resources.
type IPPoolValidator struct{}

// SetupIPPoolWebhookWithManager registers the validating webhook.
func SetupIPPoolWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &novanetv1alpha1.IPPool{}).
		WithValidator(&IPPoolValidator{}).
		Complete()
}

// ValidateCreate validates a new IPPool.
func (v *IPPoolValidator) ValidateCreate(_ context.Context, pool *novanetv1alpha1.IPPool) (admission.Warnings, error) {
	return nil, validateIPPoolSpec(&pool.Spec).ToAggregate()
}

// ValidateUpdate validates an updated IPPool.
func (v *IPPoolValidator) ValidateUpdate(_ context.Context, _ *novanetv1alpha1.IPPool, pool *novanetv1alpha1.IPPool) (admission.Warnings, error) {
	return nil, validateIPPoolSpec(&pool.Spec).ToAggregate()
}

// ValidateDelete is a no-op for IPPool.
func (v *IPPoolValidator) ValidateDelete(_ context.Context, _ *novanetv1alpha1.IPPool) (admission.Warnings, error) {
	return nil, nil
}

func validateIPPoolSpec(spec *novanetv1alpha1.IPPoolSpec) field.ErrorList {
	var allErrs field.ErrorList

	switch spec.Type {
	case novanetv1alpha1.IPPoolTypeLoadBalancerVIP,
		novanetv1alpha1.IPPoolTypeIngressIP,
		novanetv1alpha1.IPPoolTypePodCIDR,
		novanetv1alpha1.IPPoolTypeServiceClusterIP,
		novanetv1alpha1.IPPoolTypeCustom:
	default:
		allErrs = append(allErrs, field.NotSupported(
			field.NewPath("spec", "type"), spec.Type,
			[]string{
				string(novanetv1alpha1.IPPoolTypeLoadBalancerVIP),
				string(novanetv1alpha1.IPPoolTypeIngressIP),
				string(novanetv1alpha1.IPPoolTypePodCIDR),
				string(novanetv1alpha1.IPPoolTypeServiceClusterIP),
				string(novanetv1alpha1.IPPoolTypeCustom),
			}))
	}

	cidrsPath := field.NewPath("spec", "cidrs")
	var parsedNets []*net.IPNet
	for i, cidr := range spec.CIDRs {
		if err := validateCIDR(cidr); err != nil {
			allErrs = append(allErrs, field.Invalid(cidrsPath.Index(i), cidr, err.Error()))
			continue
		}
		_, ipNet, _ := net.ParseCIDR(cidr)
		for j, prev := range parsedNets {
			if cidrsOverlap(ipNet, prev) {
				allErrs = append(allErrs, field.Invalid(cidrsPath.Index(i), cidr,
					fmt.Sprintf("overlaps with cidrs[%d] %s", j, spec.CIDRs[j])))
			}
		}
		parsedNets = append(parsedNets, ipNet)
	}

	addrPath := field.NewPath("spec", "addresses")
	for i, addr := range spec.Addresses {
		if err := validateIP(addr); err != nil {
			allErrs = append(allErrs, field.Invalid(addrPath.Index(i), addr, err.Error()))
		}
	}

	if len(spec.CIDRs) == 0 && len(spec.Addresses) == 0 {
		allErrs = append(allErrs, field.Required(field.NewPath("spec"),
			"at least one of cidrs or addresses must be specified"))
	}

	return allErrs
}
