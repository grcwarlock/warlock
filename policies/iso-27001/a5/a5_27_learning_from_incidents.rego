package iso_27001.a5.a5_27

import rego.v1

# A.5.27: Learning from Information Security Incidents
# Validates post-incident review process and lessons learned

deny_no_incident_trend_insights contains msg if {
	input.normalized_data.security_hub.enabled
	not input.normalized_data.security_hub.incident_trend_insights_exist
	msg := "A.5.27: No Security Hub insights configured for incident trend analysis"
}

deny_no_security_dashboard contains msg if {
	not input.normalized_data.cloudwatch.security_dashboard_exists
	msg := "A.5.27: No CloudWatch security metrics dashboard for tracking incident trends"
}

deny_no_post_incident_reports contains msg if {
	not input.normalized_data.policies.post_incident_reports_stored
	msg := "A.5.27: No post-incident reports stored in document repository"
}

deny_no_resolved_findings_analysis contains msg if {
	input.normalized_data.security_hub.enabled
	input.normalized_data.security_hub.resolved_findings_count == 0
	msg := "A.5.27: No resolved Security Hub findings — incident learning loop not established"
}

default compliant := false

compliant if {
	count(deny_no_incident_trend_insights) == 0
	count(deny_no_security_dashboard) == 0
	count(deny_no_post_incident_reports) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_trend_insights],
		[f | some f in deny_no_security_dashboard],
	),
	array.concat(
		[f | some f in deny_no_post_incident_reports],
		[f | some f in deny_no_resolved_findings_analysis],
	),
)

result := {
	"control_id": "A.5.27",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
