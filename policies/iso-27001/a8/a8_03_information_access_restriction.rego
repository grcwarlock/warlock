package iso_27001.a8.a8_03

import rego.v1

# A.8.3: Information Access Restriction
# Validates information access restrictions through IAM and resource policies

deny_public_s3_buckets contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.public_access_blocked
	msg := sprintf("A.8.3: S3 bucket '%s' does not block public access", [bucket.name])
}

deny_no_account_public_access_block contains msg if {
	not input.normalized_data.s3.account_public_access_blocked
	msg := "A.8.3: S3 Block Public Access is not enabled at the account level"
}

deny_public_read_buckets contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.allows_public_read
	msg := sprintf("A.8.3: S3 bucket '%s' allows public read access", [bucket.name])
}

deny_no_public_access_config_rule contains msg if {
	not input.normalized_data.config.s3_public_read_prohibited_rule_exists
	msg := "A.8.3: No Config rule monitors for public S3 bucket access"
}

deny_kms_key_public contains msg if {
	some key in input.normalized_data.kms.keys
	key.is_publicly_accessible
	msg := sprintf("A.8.3: KMS key '%s' is publicly accessible — restrict key policy", [key.id])
}

default compliant := false

compliant if {
	count(deny_public_s3_buckets) == 0
	count(deny_no_account_public_access_block) == 0
	count(deny_kms_key_public) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_public_s3_buckets],
		[f | some f in deny_no_account_public_access_block],
	),
	array.concat(
		[f | some f in deny_public_read_buckets],
		array.concat(
			[f | some f in deny_no_public_access_config_rule],
			[f | some f in deny_kms_key_public],
		),
	),
)

result := {
	"control_id": "A.8.3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
