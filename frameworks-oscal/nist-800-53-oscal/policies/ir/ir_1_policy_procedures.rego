package nist.ir.ir_1

import rego.v1

# IR-1: Policy and Procedures
# Validates incident response policy exists and is current

deny_no_ir_policy contains msg if {
	not input.normalized_data.ir_policy
	msg := "IR-1: No incident response policy document found"
}

deny_no_ir_policy contains msg if {
	input.normalized_data.ir_policy
	not input.normalized_data.ir_policy.exists
	msg := "IR-1: Incident response policy document does not exist"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.ir_policy.exists
	input.normalized_data.ir_policy.last_review_days > 365
	msg := sprintf("IR-1: Incident response policy has not been reviewed in %d days (exceeds 365-day maximum)", [input.normalized_data.ir_policy.last_review_days])
}

deny_no_designated_official contains msg if {
	input.normalized_data.ir_policy.exists
	not input.normalized_data.ir_policy.designated_official
	msg := "IR-1: No designated official assigned for incident response policy oversight"
}

deny_no_scope_defined contains msg if {
	input.normalized_data.ir_policy.exists
	not input.normalized_data.ir_policy.scope_defined
	msg := "IR-1: Incident response policy does not define scope of applicability"
}

deny_no_dissemination contains msg if {
	input.normalized_data.ir_policy.exists
	not input.normalized_data.ir_policy.disseminated
	msg := "IR-1: Incident response policy has not been disseminated to relevant personnel"
}

deny_no_procedures contains msg if {
	input.normalized_data.ir_policy.exists
	not input.normalized_data.ir_policy.procedures_documented
	msg := "IR-1: Incident response procedures are not documented to support the policy"
}

default compliant := false

compliant if {
	count(deny_no_ir_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_designated_official) == 0
	count(deny_no_scope_defined) == 0
	count(deny_no_dissemination) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_policy],
		[f | some f in deny_policy_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_designated_official],
		array.concat(
			[f | some f in deny_no_scope_defined],
			array.concat(
				[f | some f in deny_no_dissemination],
				[f | some f in deny_no_procedures],
			),
		),
	),
)

result := {
	"control_id": "IR-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
