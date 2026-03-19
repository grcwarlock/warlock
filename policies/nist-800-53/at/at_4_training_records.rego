package nist.at.at_4

import rego.v1

# AT-4: Training Records
# Validates that training records are maintained and monitored

deny_no_training_records contains msg if {
	not input.normalized_data.training_records
	msg := "AT-4: No training records system configured"
}

deny_records_not_retained contains msg if {
	input.normalized_data.training_records
	input.normalized_data.training_records.retention_days < 1095
	msg := sprintf("AT-4: Training records retention period (%d days) is less than 3 years", [input.normalized_data.training_records.retention_days])
}

deny_incomplete_records contains msg if {
	some user in input.normalized_data.users
	user.security_training_completed
	not user.training_record_documented
	msg := sprintf("AT-4: User '%s' completed training but no record is documented", [user.username])
}

deny_no_completion_tracking contains msg if {
	input.normalized_data.training_records
	not input.normalized_data.training_records.completion_tracking_enabled
	msg := "AT-4: Training completion tracking is not enabled"
}

deny_no_automated_reporting contains msg if {
	input.normalized_data.training_records
	not input.normalized_data.training_records.automated_reporting
	msg := "AT-4: Automated training compliance reporting is not configured"
}

deny_records_not_reviewed contains msg if {
	input.normalized_data.training_records
	input.normalized_data.training_records.last_review_days > 90
	msg := sprintf("AT-4: Training records have not been reviewed in %d days (exceeds 90-day maximum)", [input.normalized_data.training_records.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_training_records) == 0
	count(deny_records_not_retained) == 0
	count(deny_incomplete_records) == 0
	count(deny_no_completion_tracking) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_training_records],
		[f | some f in deny_records_not_retained],
	),
	array.concat(
		[f | some f in deny_incomplete_records],
		array.concat(
			[f | some f in deny_no_completion_tracking],
			array.concat(
				[f | some f in deny_no_automated_reporting],
				[f | some f in deny_records_not_reviewed],
			),
		),
	),
)

result := {
	"control_id": "AT-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "low",
}
