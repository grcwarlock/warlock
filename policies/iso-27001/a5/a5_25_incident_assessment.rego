package iso_27001.a5.a5_25

import rego.v1

# A.5.25: Assessment and Decision on Information Security Events
# Validates security event triage and classification process

deny_no_finding_aggregation contains msg if {
	input.normalized_data.security_hub.enabled
	not input.normalized_data.security_hub.finding_aggregation_enabled
	msg := "A.5.25: Security Hub finding aggregation is not enabled across regions"
}

deny_untriaged_findings contains msg if {
	input.normalized_data.security_hub.enabled
	input.normalized_data.security_hub.new_findings_count > 100
	msg := sprintf("A.5.25: %d Security Hub findings in NEW status require triage", [input.normalized_data.security_hub.new_findings_count])
}

deny_no_triage_insights contains msg if {
	input.normalized_data.security_hub.enabled
	not input.normalized_data.security_hub.triage_insights_configured
	msg := "A.5.25: No Security Hub custom insights configured for finding triage"
}

deny_no_custom_actions contains msg if {
	input.normalized_data.security_hub.enabled
	count(input.normalized_data.security_hub.custom_actions) == 0
	msg := "A.5.25: No Security Hub custom actions defined for event classification workflow"
}

default compliant := false

compliant if {
	count(deny_no_finding_aggregation) == 0
	count(deny_untriaged_findings) == 0
	count(deny_no_triage_insights) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_finding_aggregation],
		[f | some f in deny_untriaged_findings],
	),
	array.concat(
		[f | some f in deny_no_triage_insights],
		[f | some f in deny_no_custom_actions],
	),
)

result := {
	"control_id": "A.5.25",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
