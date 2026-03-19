package iso_27001.a7.a7_09

import rego.v1

# A.7.9: Security of Assets Off-Premises
# Validates encryption and protection of data stored or transferred off-premises

deny_bucket_no_encryption contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.encryption_enabled
	msg := sprintf("A.7.9: S3 bucket '%s' does not have default encryption enabled", [bucket.name])
}

deny_ebs_encryption_not_default contains msg if {
	not input.normalized_data.ec2.ebs_encryption_by_default
	msg := "A.7.9: EBS encryption by default is not enabled — off-premises data at risk"
}

deny_unencrypted_ebs_volumes contains msg if {
	some volume in input.normalized_data.ec2.volumes
	not volume.encrypted
	msg := sprintf("A.7.9: EBS volume '%s' is not encrypted", [volume.id])
}

deny_elb_no_tls contains msg if {
	some listener in input.normalized_data.elb.listeners
	listener.protocol == "HTTP"
	msg := sprintf("A.7.9: Load balancer listener on port %d uses HTTP — TLS required for off-premises transfers", [listener.port])
}

default compliant := false

compliant if {
	count(deny_bucket_no_encryption) == 0
	count(deny_ebs_encryption_not_default) == 0
	count(deny_unencrypted_ebs_volumes) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_bucket_no_encryption],
		[f | some f in deny_ebs_encryption_not_default],
	),
	array.concat(
		[f | some f in deny_unencrypted_ebs_volumes],
		[f | some f in deny_elb_no_tls],
	),
)

result := {
	"control_id": "A.7.9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
