package iso_27001.a8.a8_01

import rego.v1

# A.8.1: User Endpoint Devices
# Validates endpoint device security policies and access controls

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	user.console_access
	not user.mfa_enabled
	user.username != "root"
	msg := sprintf("A.8.1: User '%s' accesses endpoints without MFA", [user.username])
}

deny_no_ssm_managed contains msg if {
	some instance in input.normalized_data.ec2.instances
	instance.state == "running"
	not instance.ssm_managed
	msg := sprintf("A.8.1: Instance '%s' is not managed by SSM — endpoint compliance unknown", [instance.id])
}

deny_no_software_inventory contains msg if {
	not input.normalized_data.ssm.software_inventory_enabled
	msg := "A.8.1: SSM software inventory is not enabled for endpoint device tracking"
}

deny_endpoints_no_compliance_check contains msg if {
	some instance in input.normalized_data.ssm.managed_instances
	instance.ping_status != "Online"
	msg := sprintf("A.8.1: Managed instance '%s' is not online — endpoint health unknown", [instance.id])
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_no_ssm_managed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_no_ssm_managed],
	),
	array.concat(
		[f | some f in deny_no_software_inventory],
		[f | some f in deny_endpoints_no_compliance_check],
	),
)

result := {
	"control_id": "A.8.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
