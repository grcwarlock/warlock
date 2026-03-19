package iso_27001.a6.a6_04

import rego.v1

# A.6.4: Disciplinary Process
# Validates disciplinary process is documented and security violations are tracked

deny_no_disciplinary_policy contains msg if {
	not input.normalized_data.policies.disciplinary_policy_documented
	msg := "A.6.4: No disciplinary process policy is documented"
}

deny_no_user_activity_trail contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "A.6.4: CloudTrail is not enabled — user activity cannot be monitored for policy violations"
}

deny_no_violation_detection contains msg if {
	not input.normalized_data.guardduty.enabled
	msg := "A.6.4: GuardDuty is not enabled — cannot detect potential security policy violations"
}

deny_no_unauthorized_access_alarm contains msg if {
	not input.normalized_data.cloudwatch.unauthorized_access_alarm_exists
	msg := "A.6.4: No CloudWatch alarm for unauthorized access attempts"
}

deny_no_policy_violation_rule contains msg if {
	not input.normalized_data.eventbridge.policy_violation_rule_exists
	msg := "A.6.4: No EventBridge rule configured for security policy violation detection"
}

default compliant := false

compliant if {
	count(deny_no_disciplinary_policy) == 0
	count(deny_no_user_activity_trail) == 0
	count(deny_no_violation_detection) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_disciplinary_policy],
		[f | some f in deny_no_user_activity_trail],
	),
	array.concat(
		[f | some f in deny_no_violation_detection],
		array.concat(
			[f | some f in deny_no_unauthorized_access_alarm],
			[f | some f in deny_no_policy_violation_rule],
		),
	),
)

result := {
	"control_id": "A.6.4",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
