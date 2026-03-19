package hipaa.s164_308.s164_308_a_8

import rego.v1

# 164.308(a)(8): Evaluation
# Requires periodic technical and nontechnical evaluations to determine
# the extent to which security policies and procedures meet HIPAA requirements

deny_no_evaluation_performed contains msg if {
	not input.normalized_data.policies.security_evaluation_performed
	msg := "164.308(a)(8): No security evaluation has been performed"
}

deny_evaluation_stale contains msg if {
	input.normalized_data.policies.security_evaluation_performed
	input.normalized_data.policies.last_evaluation_days > 365
	msg := sprintf("164.308(a)(8): Security evaluation is overdue — last performed %d days ago (must be within 365 days)", [input.normalized_data.policies.last_evaluation_days])
}

deny_no_evaluation_scope contains msg if {
	input.normalized_data.policies.security_evaluation_performed
	not input.normalized_data.policies.evaluation_covers_all_controls
	msg := "164.308(a)(8): Security evaluation does not cover all required HIPAA controls"
}

default compliant := false

compliant if {
	count(deny_no_evaluation_performed) == 0
	count(deny_evaluation_stale) == 0
	count(deny_no_evaluation_scope) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_evaluation_performed],
		[f | some f in deny_evaluation_stale],
	),
	[f | some f in deny_no_evaluation_scope],
)

result := {
	"control_id": "164.308(a)(8)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
