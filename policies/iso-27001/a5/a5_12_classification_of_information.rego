package iso_27001.a5.a5_12

import rego.v1

# A.5.12: Classification of Information
# Validates data classification scheme is implemented through tagging

deny_no_macie contains msg if {
	not input.normalized_data.macie.enabled
	msg := "A.5.12: Macie is not enabled for automated data classification"
}

deny_no_classification_jobs contains msg if {
	input.normalized_data.macie.enabled
	count(input.normalized_data.macie.classification_jobs) == 0
	msg := "A.5.12: No Macie classification jobs are configured"
}

deny_buckets_missing_classification contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.tags.DataClassification
	msg := sprintf("A.5.12: S3 bucket '%s' is missing a DataClassification tag", [bucket.name])
}

deny_no_classification_config_rule contains msg if {
	not input.normalized_data.config.classification_tag_rule_exists
	msg := "A.5.12: No AWS Config rule enforces DataClassification tagging on resources"
}

default compliant := false

compliant if {
	count(deny_no_macie) == 0
	count(deny_no_classification_jobs) == 0
	count(deny_buckets_missing_classification) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_macie],
		[f | some f in deny_no_classification_jobs],
	),
	array.concat(
		[f | some f in deny_buckets_missing_classification],
		[f | some f in deny_no_classification_config_rule],
	),
)

result := {
	"control_id": "A.5.12",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
