package iso_27001.a7.a7_02

import rego.v1

# A.7.2: Physical Entry
# Validates physical entry controls via CloudTrail and console access monitoring

deny_no_management_trail contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "A.7.2: CloudTrail is not enabled — console and API entry events are not audited"
}

deny_trail_not_logging contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.is_logging
	msg := "A.7.2: CloudTrail trail exists but is not actively logging"
}

deny_no_console_signin_alarm contains msg if {
	not input.normalized_data.cloudwatch.console_signin_alarm_exists
	msg := "A.7.2: No CloudWatch alarm for unusual console sign-in activity"
}

deny_no_log_file_validation contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.log_file_validation_enabled
	msg := "A.7.2: CloudTrail log file validation is not enabled — entry logs may be tampered"
}

default compliant := false

compliant if {
	count(deny_no_management_trail) == 0
	count(deny_trail_not_logging) == 0
	count(deny_no_console_signin_alarm) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_management_trail],
		[f | some f in deny_trail_not_logging],
	),
	array.concat(
		[f | some f in deny_no_console_signin_alarm],
		[f | some f in deny_no_log_file_validation],
	),
)

result := {
	"control_id": "A.7.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
