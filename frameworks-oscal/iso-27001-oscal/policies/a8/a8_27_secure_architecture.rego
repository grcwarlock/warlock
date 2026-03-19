package iso_27001.a8.a8_27

import rego.v1

# A.8.27: Secure System Architecture and Engineering Principles
# Validates secure architecture principles are applied to infrastructure

deny_no_security_standards contains msg if {
	input.normalized_data.security_hub.enabled
	count(input.normalized_data.security_hub.enabled_standards) == 0
	msg := "A.8.27: No Security Hub standards enabled for architecture best practices"
}

deny_no_security_hub contains msg if {
	not input.normalized_data.security_hub.enabled
	msg := "A.8.27: Security Hub is not enabled for security posture assessment"
}

deny_no_well_architected_review contains msg if {
	count(input.normalized_data.wellarchitected.workloads) == 0
	msg := "A.8.27: No Well-Architected Framework reviews exist for workload assessment"
}

deny_no_conformance_pack contains msg if {
	not input.normalized_data.config.conformance_packs_exist
	msg := "A.8.27: No Config conformance packs enforce architecture security baseline"
}

default compliant := false

compliant if {
	count(deny_no_security_hub) == 0
	count(deny_no_security_standards) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_standards],
		[f | some f in deny_no_security_hub],
	),
	array.concat(
		[f | some f in deny_no_well_architected_review],
		[f | some f in deny_no_conformance_pack],
	),
)

result := {
	"control_id": "A.8.27",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
