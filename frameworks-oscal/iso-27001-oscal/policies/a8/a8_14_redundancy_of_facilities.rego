package iso_27001.a8.a8_14

import rego.v1

# A.8.14: Redundancy of Information Processing Facilities
# Validates redundancy and high availability configurations

deny_rds_no_multi_az contains msg if {
	some db in input.normalized_data.rds.instances
	not db.multi_az
	msg := sprintf("A.8.14: RDS instance '%s' is not multi-AZ", [db.identifier])
}

deny_elb_single_az contains msg if {
	some lb in input.normalized_data.elb.load_balancers
	count(lb.availability_zones) < 2
	msg := sprintf("A.8.14: Load balancer '%s' is deployed in only %d AZ", [lb.name, count(lb.availability_zones)])
}

deny_asg_single_az contains msg if {
	some asg in input.normalized_data.autoscaling.groups
	count(asg.availability_zones) < 2
	msg := sprintf("A.8.14: Auto Scaling group '%s' spans only %d AZ — insufficient redundancy", [asg.name, count(asg.availability_zones)])
}

deny_elasticache_no_replication contains msg if {
	some cluster in input.normalized_data.elasticache.replication_groups
	not cluster.multi_az
	msg := sprintf("A.8.14: ElastiCache replication group '%s' is not multi-AZ", [cluster.id])
}

default compliant := false

compliant if {
	count(deny_rds_no_multi_az) == 0
	count(deny_elb_single_az) == 0
	count(deny_asg_single_az) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_rds_no_multi_az],
		[f | some f in deny_elb_single_az],
	),
	array.concat(
		[f | some f in deny_asg_single_az],
		[f | some f in deny_elasticache_no_replication],
	),
)

result := {
	"control_id": "A.8.14",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
