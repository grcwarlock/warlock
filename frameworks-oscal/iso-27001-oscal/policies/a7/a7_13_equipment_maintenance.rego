package iso_27001.a7.a7_13

import rego.v1

# A.7.13: Equipment Maintenance
# Validates patching and maintenance schedules for managed infrastructure

deny_no_maintenance_windows contains msg if {
	not input.normalized_data.ssm.maintenance_windows_configured
	msg := "A.7.13: No SSM maintenance windows configured for scheduled patching"
}

deny_instances_not_patch_compliant contains msg if {
	some instance in input.normalized_data.ssm.managed_instances
	not instance.patch_compliant
	msg := sprintf("A.7.13: Instance '%s' is not patch compliant", [instance.id])
}

deny_no_patch_baseline contains msg if {
	not input.normalized_data.ssm.patch_baseline_configured
	msg := "A.7.13: No SSM patch baseline configured for security patch management"
}

deny_instances_not_managed contains msg if {
	some instance in input.normalized_data.ec2.instances
	instance.state == "running"
	not instance.ssm_managed
	msg := sprintf("A.7.13: Running instance '%s' is not managed by SSM — cannot verify patch status", [instance.id])
}

default compliant := false

compliant if {
	count(deny_no_maintenance_windows) == 0
	count(deny_instances_not_patch_compliant) == 0
	count(deny_no_patch_baseline) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_maintenance_windows],
		[f | some f in deny_instances_not_patch_compliant],
	),
	array.concat(
		[f | some f in deny_no_patch_baseline],
		[f | some f in deny_instances_not_managed],
	),
)

result := {
	"control_id": "A.7.13",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
