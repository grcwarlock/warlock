package hipaa.s164_308.s164_308_a_1

import rego.v1

# 164.308(a)(1): Security Management Process — Risk Analysis
# Requires covered entities to conduct an accurate and thorough assessment
# of potential risks and vulnerabilities to ePHI

deny_no_risk_assessment contains msg if {
	not input.normalized_data.risk_assessment.completed
	msg := "164.308(a)(1): Risk assessment has not been completed"
}

deny_stale_risk_assessment contains msg if {
	input.normalized_data.risk_assessment.completed
	input.normalized_data.risk_assessment.last_review_days > 365
	msg := sprintf("164.308(a)(1): Risk assessment is stale — last reviewed %d days ago (must be within 365 days)", [input.normalized_data.risk_assessment.last_review_days])
}

deny_scope_not_documented contains msg if {
	input.normalized_data.risk_assessment.completed
	not input.normalized_data.risk_assessment.scope_documented
	msg := "164.308(a)(1): Risk assessment scope is not documented — must identify all systems that create, receive, maintain, or transmit ePHI"
}

deny_no_risk_remediation_plan contains msg if {
	input.normalized_data.risk_assessment.completed
	not input.normalized_data.risk_assessment.remediation_plan_exists
	msg := "164.308(a)(1): No risk remediation plan exists — identified risks must have documented mitigation measures"
}

default compliant := false

compliant if {
	count(deny_no_risk_assessment) == 0
	count(deny_stale_risk_assessment) == 0
	count(deny_scope_not_documented) == 0
	count(deny_no_risk_remediation_plan) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_assessment],
		[f | some f in deny_stale_risk_assessment],
	),
	array.concat(
		[f | some f in deny_scope_not_documented],
		[f | some f in deny_no_risk_remediation_plan],
	),
)

result := {
	"control_id": "164.308(a)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
