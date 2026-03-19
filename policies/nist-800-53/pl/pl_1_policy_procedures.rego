package nist.pl.pl_1

import rego.v1

# PL-1: Planning Policy and Procedures

deny_no_planning_policy contains msg if {
	not input.normalized_data.planning.policy_defined
	msg := "PL-1: Organization has not defined a security planning policy"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.planning.policy_defined
	not input.normalized_data.planning.policy_reviewed_within_365_days
	msg := "PL-1: Security planning policy has not been reviewed within the last 365 days"
}

deny_no_procedures contains msg if {
	not input.normalized_data.planning.procedures_documented
	msg := "PL-1: Security planning procedures are not documented"
}

deny_no_designated_official contains msg if {
	not input.normalized_data.planning.designated_official
	msg := "PL-1: No designated official assigned for security planning policy management"
}

default compliant := false

compliant if {
	count(deny_no_planning_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_procedures) == 0
	count(deny_no_designated_official) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_planning_policy],
		[f | some f in deny_policy_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_procedures],
		[f | some f in deny_no_designated_official],
	),
)

result := {
	"control_id": "PL-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
