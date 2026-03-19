package iso_27001.a5.a5_04

import rego.v1

# A.5.4: Management Responsibilities
# Validates that management enforces security policy compliance

deny_no_conformance_pack contains msg if {
	not input.normalized_data.config.conformance_packs_exist
	msg := "A.5.4: No AWS Config conformance packs deployed for policy compliance enforcement"
}

deny_conformance_pack_noncompliant contains msg if {
	some pack in input.normalized_data.config.conformance_packs
	pack.compliance_status != "COMPLIANT"
	msg := sprintf("A.5.4: Conformance pack '%s' is non-compliant — management must address violations", [pack.name])
}

deny_no_security_hub contains msg if {
	not input.normalized_data.security_hub.enabled
	msg := "A.5.4: Security Hub is not enabled — management lacks visibility into compliance posture"
}

deny_no_compliance_standards contains msg if {
	input.normalized_data.security_hub.enabled
	count(input.normalized_data.security_hub.enabled_standards) == 0
	msg := "A.5.4: No Security Hub compliance standards are enabled"
}

default compliant := false

compliant if {
	count(deny_no_conformance_pack) == 0
	count(deny_no_security_hub) == 0
	count(deny_conformance_pack_noncompliant) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_conformance_pack],
		[f | some f in deny_conformance_pack_noncompliant],
	),
	array.concat(
		[f | some f in deny_no_security_hub],
		[f | some f in deny_no_compliance_standards],
	),
)

result := {
	"control_id": "A.5.4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
