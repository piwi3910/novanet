package webhook

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	novanetv1alpha1 "github.com/azrtydxb/novanet/api/v1alpha1"
)

// HostEndpointPolicyValidator validates HostEndpointPolicy resources.
type HostEndpointPolicyValidator struct{}

// SetupHostEndpointPolicyWebhookWithManager registers the validating webhook.
func SetupHostEndpointPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &novanetv1alpha1.HostEndpointPolicy{}).
		WithValidator(&HostEndpointPolicyValidator{}).
		Complete()
}

// ValidateCreate validates a new HostEndpointPolicy.
func (v *HostEndpointPolicyValidator) ValidateCreate(_ context.Context, hep *novanetv1alpha1.HostEndpointPolicy) (admission.Warnings, error) {
	return nil, validateHostEndpointPolicySpec(&hep.Spec).ToAggregate()
}

// ValidateUpdate validates an updated HostEndpointPolicy.
func (v *HostEndpointPolicyValidator) ValidateUpdate(_ context.Context, _ *novanetv1alpha1.HostEndpointPolicy, hep *novanetv1alpha1.HostEndpointPolicy) (admission.Warnings, error) {
	return nil, validateHostEndpointPolicySpec(&hep.Spec).ToAggregate()
}

// ValidateDelete is a no-op for HostEndpointPolicy.
func (v *HostEndpointPolicyValidator) ValidateDelete(_ context.Context, _ *novanetv1alpha1.HostEndpointPolicy) (admission.Warnings, error) {
	return nil, nil
}

func validateHostEndpointPolicySpec(spec *novanetv1alpha1.HostEndpointPolicySpec) field.ErrorList {
	var allErrs field.ErrorList

	ingressPath := field.NewPath("spec", "ingress")
	for i, rule := range spec.Ingress {
		allErrs = append(allErrs, validateHostRule(rule, ingressPath.Index(i))...)
	}

	egressPath := field.NewPath("spec", "egress")
	for i, rule := range spec.Egress {
		allErrs = append(allErrs, validateHostRule(rule, egressPath.Index(i))...)
	}

	return allErrs
}

func validateHostRule(rule novanetv1alpha1.HostRule, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	switch rule.Action {
	case novanetv1alpha1.HostRuleActionAllow, novanetv1alpha1.HostRuleActionDeny:
	default:
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("action"),
			rule.Action, []string{string(novanetv1alpha1.HostRuleActionAllow), string(novanetv1alpha1.HostRuleActionDeny)}))
	}

	for i, cidr := range rule.CIDRs {
		if err := validateCIDR(cidr); err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("cidrs").Index(i), cidr, err.Error()))
		}
	}

	for i, hp := range rule.Ports {
		portPath := fldPath.Child("ports").Index(i)
		if err := validatePort(hp.Port); err != nil {
			allErrs = append(allErrs, field.Invalid(portPath.Child("port"), hp.Port, err.Error()))
		}
		if hp.EndPort != nil {
			if err := validatePortRange(hp.Port, *hp.EndPort); err != nil {
				allErrs = append(allErrs, field.Invalid(portPath.Child("endPort"), *hp.EndPort, err.Error()))
			}
		}
	}

	if rule.Protocol != nil {
		if err := validateProtocol(string(*rule.Protocol)); err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("protocol"), *rule.Protocol, err.Error()))
		}
	}

	return allErrs
}
