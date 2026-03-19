package nist.au.au_2

import rego.v1

# AU-2: Event Logging

deny_no_multi_region_trail contains msg if {
	input.provider == "aws"
	not any_multi_region_trail
	msg := "AU-2: No multi-region CloudTrail trail configured"
}

any_multi_region_trail if {
	some trail in input.normalized_data.trails
	trail.is_multi_region
}

deny_logging_inactive contains msg if {
	input.provider == "aws"
	some trail in input.normalized_data.trails
	trail.is_multi_region
	not trail.is_logging
	msg := sprintf("AU-2: CloudTrail trail '%s' is not actively logging", [trail.name])
}

deny_no_log_validation contains msg if {
	input.provider == "aws"
	some trail in input.normalized_data.trails
	trail.is_multi_region
	not trail.log_file_validation_enabled
	msg := sprintf("AU-2: Trail '%s' does not have log file validation enabled", [trail.name])
}

deny_no_activity_log contains msg if {
	input.provider == "azure"
	not input.normalized_data.activity_log_enabled
	msg := "AU-2: Azure Activity Log is not enabled"
}

deny_no_audit_log contains msg if {
	input.provider == "gcp"
	not input.normalized_data.audit_logging_enabled
	msg := "AU-2: GCP Cloud Audit Logging is not enabled"
}

default compliant := false

compliant if {
	count(deny_no_multi_region_trail) == 0
	count(deny_logging_inactive) == 0
	count(deny_no_activity_log) == 0
	count(deny_no_audit_log) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_multi_region_trail],
		[f | some f in deny_logging_inactive],
	),
	array.concat(
		[f | some f in deny_no_log_validation],
		array.concat(
			[f | some f in deny_no_activity_log],
			[f | some f in deny_no_audit_log],
		),
	),
)

result := {
	"control_id": "AU-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
