package iso_27001.a5.a5_28

import rego.v1

# A.5.28: Collection of Evidence
# Validates evidence collection and preservation procedures

deny_no_log_object_lock contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "logs"
	not bucket.object_lock_enabled
	msg := sprintf("A.5.28: Log bucket '%s' does not have Object Lock enabled for evidence preservation", [bucket.name])
}

deny_no_cloudtrail_validation contains msg if {
	input.normalized_data.cloudtrail.enabled
	not input.normalized_data.cloudtrail.log_file_validation_enabled
	msg := "A.5.28: CloudTrail log file validation is not enabled — evidence integrity at risk"
}

deny_log_bucket_not_encrypted contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "logs"
	not bucket.encryption_enabled
	msg := sprintf("A.5.28: Log bucket '%s' is not encrypted — evidence confidentiality at risk", [bucket.name])
}

deny_no_forensic_process contains msg if {
	not input.normalized_data.policies.forensic_evidence_procedure_documented
	msg := "A.5.28: No documented forensic evidence collection procedure exists"
}

default compliant := false

compliant if {
	count(deny_no_log_object_lock) == 0
	count(deny_no_cloudtrail_validation) == 0
	count(deny_log_bucket_not_encrypted) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_log_object_lock],
		[f | some f in deny_no_cloudtrail_validation],
	),
	array.concat(
		[f | some f in deny_log_bucket_not_encrypted],
		[f | some f in deny_no_forensic_process],
	),
)

result := {
	"control_id": "A.5.28",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
