package iso_27001.a7.a7_14

import rego.v1

# A.7.14: Secure Disposal or Re-use of Equipment
# Validates secure data deletion and volume cleanup procedures

deny_unattached_unencrypted_volumes contains msg if {
	some volume in input.normalized_data.ec2.volumes
	volume.state == "available"
	not volume.encrypted
	msg := sprintf("A.7.14: Unattached EBS volume '%s' is not encrypted — data exposed before disposal", [volume.id])
}

deny_old_snapshots contains msg if {
	some snapshot in input.normalized_data.ec2.snapshots
	snapshot.age_days > 365
	msg := sprintf("A.7.14: EBS snapshot '%s' is %d days old — review for secure disposal", [snapshot.id, snapshot.age_days])
}

deny_no_lifecycle_expiration contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.lifecycle_expiration_configured
	msg := sprintf("A.7.14: S3 bucket '%s' has no lifecycle expiration rule for data disposal", [bucket.name])
}

deny_unattached_volumes_exist contains msg if {
	unattached := [v | some v in input.normalized_data.ec2.volumes; v.state == "available"]
	count(unattached) > 0
	msg := sprintf("A.7.14: %d unattached EBS volumes found — review and delete unused volumes", [count(unattached)])
}

default compliant := false

compliant if {
	count(deny_unattached_unencrypted_volumes) == 0
	count(deny_old_snapshots) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unattached_unencrypted_volumes],
		[f | some f in deny_old_snapshots],
	),
	array.concat(
		[f | some f in deny_no_lifecycle_expiration],
		[f | some f in deny_unattached_volumes_exist],
	),
)

result := {
	"control_id": "A.7.14",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
