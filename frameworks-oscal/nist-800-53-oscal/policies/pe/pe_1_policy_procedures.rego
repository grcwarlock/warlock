package nist.pe.pe_1

import rego.v1

# PE-1: Physical and Environmental Protection Policy and Procedures

deny_no_physical_security_policy contains msg if {
	not input.normalized_data.physical_security.policy_defined
	msg := "PE-1: Organization has not defined a physical and environmental protection policy"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.physical_security.policy_defined
	not input.normalized_data.physical_security.policy_reviewed_within_365_days
	msg := "PE-1: Physical and environmental protection policy has not been reviewed within the last 365 days"
}

deny_no_procedures contains msg if {
	not input.normalized_data.physical_security.procedures_documented
	msg := "PE-1: Physical and environmental protection procedures are not documented"
}

deny_no_designated_official contains msg if {
	not input.normalized_data.physical_security.designated_official
	msg := "PE-1: No designated official assigned for physical security policy management"
}

default compliant := false

compliant if {
	count(deny_no_physical_security_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_procedures) == 0
	count(deny_no_designated_official) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_physical_security_policy],
		[f | some f in deny_policy_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_procedures],
		[f | some f in deny_no_designated_official],
	),
)

result := {
	"control_id": "PE-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
