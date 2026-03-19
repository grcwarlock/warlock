package iso_27001.a8.a8_19

import rego.v1

# A.8.19: Installation of Software on Operational Systems
# Validates software installation controls and approved package management

deny_no_software_inventory contains msg if {
	not input.normalized_data.ssm.software_inventory_enabled
	msg := "A.8.19: SSM software inventory is not enabled — installed software untracked"
}

deny_no_approved_amis_rule contains msg if {
	not input.normalized_data.config.approved_amis_rule_exists
	msg := "A.8.19: No Config rule enforces approved AMIs for instance launches"
}

deny_unapproved_ami contains msg if {
	some instance in input.normalized_data.ec2.instances
	not instance.ami_approved
	msg := sprintf("A.8.19: Instance '%s' launched from unapproved AMI '%s'", [instance.id, instance.ami_id])
}

deny_instances_not_managed contains msg if {
	some instance in input.normalized_data.ec2.instances
	instance.state == "running"
	not instance.ssm_managed
	msg := sprintf("A.8.19: Instance '%s' is not SSM-managed — software installation uncontrolled", [instance.id])
}

default compliant := false

compliant if {
	count(deny_no_software_inventory) == 0
	count(deny_no_approved_amis_rule) == 0
	count(deny_unapproved_ami) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_software_inventory],
		[f | some f in deny_no_approved_amis_rule],
	),
	array.concat(
		[f | some f in deny_unapproved_ami],
		[f | some f in deny_instances_not_managed],
	),
)

result := {
	"control_id": "A.8.19",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
