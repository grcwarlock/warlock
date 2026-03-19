package iso_27001.a8.a8_06

import rego.v1

# A.8.6: Capacity Management
# Validates capacity monitoring and auto-scaling configurations

deny_no_autoscaling contains msg if {
	count(input.normalized_data.autoscaling.groups) == 0
	input.normalized_data.ec2.instance_count > 0
	msg := "A.8.6: No Auto Scaling groups configured for capacity management"
}

deny_no_capacity_alarms contains msg if {
	not input.normalized_data.cloudwatch.capacity_alarms_configured
	msg := "A.8.6: No CloudWatch alarms configured for capacity monitoring (CPU, memory, disk)"
}

deny_no_compute_optimizer contains msg if {
	not input.normalized_data.compute_optimizer.enabled
	msg := "A.8.6: Compute Optimizer is not enabled for rightsizing recommendations"
}

deny_asg_no_scaling_policy contains msg if {
	some asg in input.normalized_data.autoscaling.groups
	count(asg.scaling_policies) == 0
	msg := sprintf("A.8.6: Auto Scaling group '%s' has no scaling policies configured", [asg.name])
}

default compliant := false

compliant if {
	count(deny_no_autoscaling) == 0
	count(deny_no_capacity_alarms) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_autoscaling],
		[f | some f in deny_no_capacity_alarms],
	),
	array.concat(
		[f | some f in deny_no_compute_optimizer],
		[f | some f in deny_asg_no_scaling_policy],
	),
)

result := {
	"control_id": "A.8.6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
