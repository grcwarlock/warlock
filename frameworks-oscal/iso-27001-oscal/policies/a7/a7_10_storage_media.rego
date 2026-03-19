package iso_27001.a7.a7_10

import rego.v1

# A.7.10: Storage Media
# Validates storage media lifecycle management and encryption

deny_no_lifecycle_policy contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.lifecycle_policy_configured
	msg := sprintf("A.7.10: S3 bucket '%s' has no lifecycle policy for media retention management", [bucket.name])
}

deny_unencrypted_volumes contains msg if {
	some volume in input.normalized_data.ec2.volumes
	not volume.encrypted
	msg := sprintf("A.7.10: EBS volume '%s' is not encrypted — storage media unprotected", [volume.id])
}

deny_no_key_rotation contains msg if {
	some key in input.normalized_data.kms.keys
	key.key_state == "Enabled"
	not key.rotation_enabled
	msg := sprintf("A.7.10: KMS key '%s' does not have automatic rotation enabled", [key.id])
}

deny_no_ebs_encryption_default contains msg if {
	not input.normalized_data.ec2.ebs_encryption_by_default
	msg := "A.7.10: EBS encryption by default is not enabled"
}

default compliant := false

compliant if {
	count(deny_unencrypted_volumes) == 0
	count(deny_no_key_rotation) == 0
	count(deny_no_ebs_encryption_default) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_lifecycle_policy],
		[f | some f in deny_unencrypted_volumes],
	),
	array.concat(
		[f | some f in deny_no_key_rotation],
		[f | some f in deny_no_ebs_encryption_default],
	),
)

result := {
	"control_id": "A.7.10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
