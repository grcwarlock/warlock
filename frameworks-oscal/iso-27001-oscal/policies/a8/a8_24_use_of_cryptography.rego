package iso_27001.a8.a8_24

import rego.v1

# A.8.24: Use of Cryptography
# Validates cryptographic controls and key management

deny_no_kms_keys contains msg if {
	count(input.normalized_data.kms.keys) == 0
	msg := "A.8.24: No KMS keys exist for cryptographic operations"
}

deny_no_key_rotation contains msg if {
	some key in input.normalized_data.kms.keys
	key.key_state == "Enabled"
	not key.rotation_enabled
	msg := sprintf("A.8.24: KMS key '%s' does not have automatic rotation enabled", [key.id])
}

deny_unencrypted_volumes contains msg if {
	some volume in input.normalized_data.ec2.volumes
	not volume.encrypted
	msg := sprintf("A.8.24: EBS volume '%s' is not encrypted", [volume.id])
}

deny_unencrypted_buckets contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.encryption_enabled
	msg := sprintf("A.8.24: S3 bucket '%s' does not have default encryption enabled", [bucket.name])
}

deny_no_encrypted_volumes_rule contains msg if {
	not input.normalized_data.config.encrypted_volumes_rule_exists
	msg := "A.8.24: No Config rule enforces EBS volume encryption"
}

default compliant := false

compliant if {
	count(deny_no_kms_keys) == 0
	count(deny_no_key_rotation) == 0
	count(deny_unencrypted_volumes) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_kms_keys],
		[f | some f in deny_no_key_rotation],
	),
	array.concat(
		[f | some f in deny_unencrypted_volumes],
		array.concat(
			[f | some f in deny_unencrypted_buckets],
			[f | some f in deny_no_encrypted_volumes_rule],
		),
	),
)

result := {
	"control_id": "A.8.24",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
