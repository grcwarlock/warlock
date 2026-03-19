package hipaa.s164_316.s164_316_b_1

import rego.v1

# 164.316(b)(1): Documentation — Retention
# Requires maintenance of policies, procedures, and written records
# of actions, activities, or assessments for at least six years

deny_no_document_retention_policy contains msg if {
	not input.normalized_data.policies.document_retention_policy
	msg := "164.316(b)(1): No document retention policy — must retain security policies, procedures, and documentation for at least six years"
}

deny_insufficient_retention_period contains msg if {
	input.normalized_data.policies.document_retention_policy
	input.normalized_data.policies.retention_period_years < 6
	msg := sprintf("164.316(b)(1): Document retention period is %d years — HIPAA requires a minimum of six years", [input.normalized_data.policies.retention_period_years])
}

deny_no_document_availability contains msg if {
	not input.normalized_data.policies.documentation_accessible_to_workforce
	msg := "164.316(b)(1): Documentation is not accessible to workforce — policies and procedures must be available to persons responsible for implementing them"
}

default compliant := false

compliant if {
	count(deny_no_document_retention_policy) == 0
	count(deny_insufficient_retention_period) == 0
	count(deny_no_document_availability) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_document_retention_policy],
		[f | some f in deny_insufficient_retention_period],
	),
	[f | some f in deny_no_document_availability],
)

result := {
	"control_id": "164.316(b)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
