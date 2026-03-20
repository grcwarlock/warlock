package gdpr.art33

import rego.v1

# GDPR Article 33: Notification of a personal data breach to the supervisory authority
# Must notify within 72 hours

deny_no_siem contains msg if {
	not input.normalized_data.siem.active
	msg := "Art33: No active SIEM monitoring — breach detection capability required for 72-hour notification"
}

deny_no_incident_process contains msg if {
	not input.normalized_data.policies.breach_notification_procedure
	msg := "Art33: No documented breach notification procedure — must notify supervisory authority within 72 hours"
}

deny_stale_detection_rules contains msg if {
	input.normalized_data.siem.active
	input.normalized_data.siem.days_since_rule_review > 90
	msg := sprintf("Art33: SIEM detection rules not reviewed in %d days — review quarterly to maintain breach detection", [input.normalized_data.siem.days_since_rule_review])
}

default compliant := false

compliant if {
	count(deny_no_siem) == 0
	count(deny_no_incident_process) == 0
	count(deny_stale_detection_rules) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_siem],
		[f | some f in deny_no_incident_process],
	),
	[f | some f in deny_stale_detection_rules],
)

result := {
	"control_id": "Art33",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
