package iso_27001.a6.a6_08

import rego.v1

# A.6.8: Information Security Event Reporting
# Validates security event reporting mechanisms are in place and accessible

deny_no_guardduty contains msg if {
	not input.normalized_data.guardduty.enabled
	msg := "A.6.8: GuardDuty is not enabled for automated security event detection"
}

deny_no_reporting_topic contains msg if {
	not input.normalized_data.sns.security_reporting_topic_exists
	msg := "A.6.8: No SNS topic exists for security event reporting"
}

deny_no_event_notification_rule contains msg if {
	not input.normalized_data.eventbridge.security_event_notification_rule_exists
	msg := "A.6.8: No EventBridge rule to route security events to notification channels"
}

deny_no_security_team_subscription contains msg if {
	input.normalized_data.sns.security_reporting_topic_exists
	input.normalized_data.sns.security_topic_subscription_count == 0
	msg := "A.6.8: Security reporting SNS topic has no subscribers"
}

default compliant := false

compliant if {
	count(deny_no_guardduty) == 0
	count(deny_no_reporting_topic) == 0
	count(deny_no_event_notification_rule) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_guardduty],
		[f | some f in deny_no_reporting_topic],
	),
	array.concat(
		[f | some f in deny_no_event_notification_rule],
		[f | some f in deny_no_security_team_subscription],
	),
)

result := {
	"control_id": "A.6.8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
