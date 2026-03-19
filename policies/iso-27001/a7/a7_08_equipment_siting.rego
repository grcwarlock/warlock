package iso_27001.a7.a7_08

import rego.v1

# A.7.8: Equipment Siting and Protection
# Validates infrastructure deployment in compliant and protected locations

deny_instances_unapproved_region contains msg if {
	approved_regions := input.normalized_data.organization.approved_regions
	some instance in input.normalized_data.ec2.instances
	not instance.region in approved_regions
	msg := sprintf("A.7.8: Instance '%s' deployed in unapproved region '%s'", [instance.id, instance.region])
}

deny_no_dedicated_hosts contains msg if {
	input.normalized_data.compliance.requires_dedicated_hosts
	not input.normalized_data.ec2.dedicated_hosts_configured
	msg := "A.7.8: Compliance requires dedicated hosts but none are configured"
}

deny_no_nitro_instances contains msg if {
	some instance in input.normalized_data.ec2.instances
	not instance.is_nitro_based
	instance.is_production
	msg := sprintf("A.7.8: Production instance '%s' is not Nitro-based — hardware security reduced", [instance.id])
}

deny_no_placement_groups contains msg if {
	input.normalized_data.ec2.instance_count > 10
	count(input.normalized_data.ec2.placement_groups) == 0
	msg := "A.7.8: No placement groups configured for infrastructure placement control"
}

default compliant := false

compliant if {
	count(deny_instances_unapproved_region) == 0
	count(deny_no_dedicated_hosts) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_instances_unapproved_region],
		[f | some f in deny_no_dedicated_hosts],
	),
	array.concat(
		[f | some f in deny_no_nitro_instances],
		[f | some f in deny_no_placement_groups],
	),
)

result := {
	"control_id": "A.7.8",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
