package iso_27001.a8.a8_15

import rego.v1

# A.8.15: Logging
# Validates comprehensive logging is enabled across all services

deny_no_cloudtrail contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "A.8.15: CloudTrail is not enabled for API activity logging"
}

deny_cloudtrail_not_multiregion contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.is_multi_region
	msg := "A.8.15: CloudTrail is not configured as multi-region"
}

deny_no_log_file_validation contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.log_file_validation_enabled
	msg := "A.8.15: CloudTrail log file validation is not enabled"
}

deny_vpc_no_flow_logs contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.flow_logs_enabled
	msg := sprintf("A.8.15: VPC '%s' does not have flow logs enabled", [vpc.id])
}

deny_no_s3_access_logging contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.access_logging_enabled
	msg := sprintf("A.8.15: S3 bucket '%s' does not have access logging enabled", [bucket.name])
}

deny_no_log_retention contains msg if {
	some log_group in input.normalized_data.cloudwatch.log_groups
	not log_group.retention_in_days
	msg := sprintf("A.8.15: Log group '%s' has no retention policy", [log_group.name])
}

default compliant := false

compliant if {
	count(deny_no_cloudtrail) == 0
	count(deny_cloudtrail_not_multiregion) == 0
	count(deny_no_log_file_validation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_cloudtrail],
		[f | some f in deny_cloudtrail_not_multiregion],
	),
	array.concat(
		[f | some f in deny_no_log_file_validation],
		array.concat(
			[f | some f in deny_vpc_no_flow_logs],
			array.concat(
				[f | some f in deny_no_s3_access_logging],
				[f | some f in deny_no_log_retention],
			),
		),
	),
)

result := {
	"control_id": "A.8.15",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
