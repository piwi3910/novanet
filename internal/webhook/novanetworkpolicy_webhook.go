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

// NovaNetworkPolicyValidator validates NovaNetworkPolicy resources.
type NovaNetworkPolicyValidator struct{}

// SetupNovaNetworkPolicyWebhookWithManager registers the validating webhook.
func SetupNovaNetworkPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &novanetv1alpha1.NovaNetworkPolicy{}).
		WithValidator(&NovaNetworkPolicyValidator{}).
		Complete()
}

// ValidateCreate validates a new NovaNetworkPolicy.
func (v *NovaNetworkPolicyValidator) ValidateCreate(_ context.Context, nnp *novanetv1alpha1.NovaNetworkPolicy) (admission.Warnings, error) {
	return nil, validateNovaNetworkPolicySpec(&nnp.Spec).ToAggregate()
}

// ValidateUpdate validates an updated NovaNetworkPolicy.
func (v *NovaNetworkPolicyValidator) ValidateUpdate(_ context.Context, _ *novanetv1alpha1.NovaNetworkPolicy, nnp *novanetv1alpha1.NovaNetworkPolicy) (admission.Warnings, error) {
	return nil, validateNovaNetworkPolicySpec(&nnp.Spec).ToAggregate()
}

// ValidateDelete is a no-op for NovaNetworkPolicy.
func (v *NovaNetworkPolicyValidator) ValidateDelete(_ context.Context, _ *novanetv1alpha1.NovaNetworkPolicy) (admission.Warnings, error) {
	return nil, nil
}

func validateNovaNetworkPolicySpec(spec *novanetv1alpha1.NovaNetworkPolicySpec) field.ErrorList {
	allErrs := make(field.ErrorList, 0)

	for i, pt := range spec.PolicyTypes {
		switch pt {
		case novanetv1alpha1.PolicyTypeIngress, novanetv1alpha1.PolicyTypeEgress:
		default:
			allErrs = append(allErrs, field.NotSupported(
				field.NewPath("spec", "policyTypes").Index(i),
				pt, []string{string(novanetv1alpha1.PolicyTypeIngress), string(novanetv1alpha1.PolicyTypeEgress)}))
		}
	}

	ingressPath := field.NewPath("spec", "ingress")
	for i, rule := range spec.Ingress {
		rulePath := ingressPath.Index(i)
		allErrs = append(allErrs, validateNetworkPolicyPorts(rule.Ports, rulePath.Child("ports"))...)
		allErrs = append(allErrs, validateNetworkPolicyPeers(rule.From, rulePath.Child("from"))...)
	}

	egressPath := field.NewPath("spec", "egress")
	for i, rule := range spec.Egress {
		rulePath := egressPath.Index(i)
		allErrs = append(allErrs, validateNetworkPolicyPorts(rule.Ports, rulePath.Child("ports"))...)
		allErrs = append(allErrs, validateNetworkPolicyPeers(rule.To, rulePath.Child("to"))...)
	}

	return allErrs
}

func validateNetworkPolicyPorts(ports []novanetv1alpha1.NovaNetworkPolicyPort, fldPath *field.Path) field.ErrorList {
	allErrs := make(field.ErrorList, 0)

	for i, p := range ports {
		portPath := fldPath.Index(i)

		if p.Protocol != nil {
			if err := validateProtocol(*p.Protocol); err != nil {
				allErrs = append(allErrs, field.Invalid(portPath.Child("protocol"), *p.Protocol, err.Error()))
			}
		}

		if p.Port != nil {
			if err := validatePort(*p.Port); err != nil {
				allErrs = append(allErrs, field.Invalid(portPath.Child("port"), *p.Port, err.Error()))
			}
		}

		if p.EndPort != nil {
			if p.Port == nil {
				allErrs = append(allErrs, field.Required(portPath.Child("port"),
					"port must be set when endPort is specified"))
			} else {
				if err := validatePortRange(*p.Port, *p.EndPort); err != nil {
					allErrs = append(allErrs, field.Invalid(portPath.Child("endPort"), *p.EndPort, err.Error()))
				}
			}
		}
	}

	return allErrs
}

func validateNetworkPolicyPeers(peers []novanetv1alpha1.NovaNetworkPolicyPeer, fldPath *field.Path) field.ErrorList {
	allErrs := make(field.ErrorList, 0)

	for i, peer := range peers {
		peerPath := fldPath.Index(i)
		if peer.IPBlock != nil {
			allErrs = append(allErrs, validateIPBlock(peer.IPBlock, peerPath.Child("ipBlock"))...)
		}
	}

	return allErrs
}

func validateIPBlock(ipBlock *novanetv1alpha1.NovaIPBlock, fldPath *field.Path) field.ErrorList {
	allErrs := make(field.ErrorList, 0)

	if err := validateCIDR(ipBlock.CIDR); err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("cidr"), ipBlock.CIDR, err.Error()))
		// If the parent CIDR is invalid, we cannot validate containment of except entries.
		return allErrs
	}

	_, parentNet, _ := net.ParseCIDR(ipBlock.CIDR)

	for i, except := range ipBlock.Except {
		exceptPath := fldPath.Child("except").Index(i)
		if err := validateCIDR(except); err != nil {
			allErrs = append(allErrs, field.Invalid(exceptPath, except, err.Error()))
			continue
		}
		_, exceptNet, _ := net.ParseCIDR(except)
		if !cidrContains(parentNet, exceptNet) {
			allErrs = append(allErrs, field.Invalid(exceptPath, except,
				fmt.Sprintf("except CIDR %s is not contained within parent CIDR %s", except, ipBlock.CIDR)))
		}
	}

	return allErrs
}
