package iso_27001.a7.a7_11

import rego.v1

# A.7.11: Supporting Utilities
# Validates redundancy and failover configurations

deny_rds_no_multi_az contains msg if {
	some db in input.normalized_data.rds.instances
	db.is_production
	not db.multi_az
	msg := sprintf("A.7.11: Production RDS instance '%s' is not multi-AZ — no utility redundancy", [db.identifier])
}

deny_no_autoscaling contains msg if {
	count(input.normalized_data.autoscaling.groups) == 0
	input.normalized_data.ec2.instance_count > 0
	msg := "A.7.11: No Auto Scaling groups configured — workloads cannot self-heal from failures"
}

deny_single_az_autoscaling contains msg if {
	some asg in input.normalized_data.autoscaling.groups
	count(asg.availability_zones) < 2
	msg := sprintf("A.7.11: Auto Scaling group '%s' spans only %d AZ — needs multiple for redundancy", [asg.name, count(asg.availability_zones)])
}

deny_no_health_checks contains msg if {
	count(input.normalized_data.route53.health_checks) == 0
	msg := "A.7.11: No Route 53 health checks configured for service availability monitoring"
}

default compliant := false

compliant if {
	count(deny_rds_no_multi_az) == 0
	count(deny_single_az_autoscaling) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_rds_no_multi_az],
		[f | some f in deny_no_autoscaling],
	),
	array.concat(
		[f | some f in deny_single_az_autoscaling],
		[f | some f in deny_no_health_checks],
	),
)

result := {
	"control_id": "A.7.11",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
