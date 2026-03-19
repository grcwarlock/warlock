package iso_27001.a7.a7_05

import rego.v1

# A.7.5: Protecting Against Physical and Environmental Threats
# Validates multi-AZ and disaster recovery configurations

deny_rds_no_multi_az contains msg if {
	some db in input.normalized_data.rds.instances
	not db.multi_az
	msg := sprintf("A.7.5: RDS instance '%s' is not multi-AZ — vulnerable to AZ failure", [db.identifier])
}

deny_no_backup_plans contains msg if {
	count(input.normalized_data.backup.plans) == 0
	msg := "A.7.5: No AWS Backup plans for disaster recovery"
}

deny_no_cross_region_replication contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.is_critical
	not bucket.cross_region_replication_enabled
	msg := sprintf("A.7.5: Critical bucket '%s' does not have cross-region replication", [bucket.name])
}

deny_single_az_instances contains msg if {
	az_counts := {az: count([i | some i in input.normalized_data.ec2.instances; i.availability_zone == az]) | some az in input.normalized_data.ec2.availability_zones}
	count(az_counts) == 1
	msg := "A.7.5: All EC2 instances deployed in a single availability zone"
}

default compliant := false

compliant if {
	count(deny_rds_no_multi_az) == 0
	count(deny_no_backup_plans) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_rds_no_multi_az],
		[f | some f in deny_no_backup_plans],
	),
	array.concat(
		[f | some f in deny_no_cross_region_replication],
		[f | some f in deny_single_az_instances],
	),
)

result := {
	"control_id": "A.7.5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
