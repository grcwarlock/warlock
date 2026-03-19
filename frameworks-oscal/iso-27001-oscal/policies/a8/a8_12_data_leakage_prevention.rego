package iso_27001.a8.a8_12

import rego.v1

# A.8.12: Data Leakage Prevention
# Validates data leakage prevention controls are active

deny_no_macie contains msg if {
	not input.normalized_data.macie.enabled
	msg := "A.8.12: Macie is not enabled for data leakage detection"
}

deny_no_account_public_access_block contains msg if {
	not input.normalized_data.s3.account_public_access_blocked
	msg := "A.8.12: Account-level S3 Block Public Access is not enabled — data leakage risk"
}

deny_no_vpc_endpoints contains msg if {
	count(input.normalized_data.vpc_endpoints) == 0
	msg := "A.8.12: No VPC endpoints configured — data may traverse public internet"
}

deny_bucket_public contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.public_access_blocked
	msg := sprintf("A.8.12: Bucket '%s' does not block public access — data leakage risk", [bucket.name])
}

deny_no_data_exfiltration_scp contains msg if {
	not input.normalized_data.organization.data_exfiltration_scp_exists
	msg := "A.8.12: No SCP restricts data exfiltration actions"
}

default compliant := false

compliant if {
	count(deny_no_macie) == 0
	count(deny_no_account_public_access_block) == 0
	count(deny_bucket_public) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_macie],
		[f | some f in deny_no_account_public_access_block],
	),
	array.concat(
		[f | some f in deny_no_vpc_endpoints],
		array.concat(
			[f | some f in deny_bucket_public],
			[f | some f in deny_no_data_exfiltration_scp],
		),
	),
)

result := {
	"control_id": "A.8.12",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
