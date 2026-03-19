package nist.sr.sr_11

import rego.v1

# SR-11: Component Authenticity

deny_no_authenticity_policy contains msg if {
	not input.normalized_data.component_authenticity
	msg := "SR-11: No component authenticity policy established"
}

deny_no_anti_counterfeit contains msg if {
	ca := input.normalized_data.component_authenticity
	not ca.anti_counterfeit_procedures
	msg := "SR-11: No anti-counterfeit procedures implemented"
}

deny_no_verification_process contains msg if {
	ca := input.normalized_data.component_authenticity
	not ca.authenticity_verification_process
	msg := "SR-11: No process for verifying component authenticity"
}

deny_component_not_verified contains msg if {
	some component in input.normalized_data.system_components
	component.requires_authenticity_verification
	not component.authenticity_verified
	msg := sprintf("SR-11: Component '%s' has not been verified for authenticity", [component.name])
}

deny_no_sbom contains msg if {
	ca := input.normalized_data.component_authenticity
	not ca.software_bill_of_materials
	msg := "SR-11: No software bill of materials (SBOM) maintained for component authenticity tracking"
}

default compliant := false

compliant if {
	count(deny_no_authenticity_policy) == 0
	count(deny_no_anti_counterfeit) == 0
	count(deny_no_verification_process) == 0
	count(deny_component_not_verified) == 0
	count(deny_no_sbom) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_authenticity_policy],
		[f | some f in deny_no_anti_counterfeit],
	),
	array.concat(
		[f | some f in deny_no_verification_process],
		array.concat(
			[f | some f in deny_component_not_verified],
			[f | some f in deny_no_sbom],
		),
	),
)

result := {
	"control_id": "SR-11",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
