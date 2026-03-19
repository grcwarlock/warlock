package nist.pm.pm_10

import rego.v1

# PM-10: Authorization Process

deny_no_auth_process contains msg if {
	not input.normalized_data.authorization_process
	msg := "PM-10: No security and privacy authorization process established"
}

deny_no_authorizing_official contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.authorizing_official
	msg := sprintf("PM-10: System '%s' does not have a designated authorizing official", [system.name])
}

deny_ato_expired contains msg if {
	some system in input.normalized_data.system_inventory.systems
	system.ato_expiration_days < 0
	msg := sprintf("PM-10: System '%s' has an expired authorization to operate (%d days past expiration)", [system.name, abs(system.ato_expiration_days)])
}

deny_ato_expiring_soon contains msg if {
	some system in input.normalized_data.system_inventory.systems
	system.ato_expiration_days >= 0
	system.ato_expiration_days < 90
	msg := sprintf("PM-10: System '%s' authorization to operate expires in %d days", [system.name, system.ato_expiration_days])
}

deny_no_continuous_monitoring contains msg if {
	process := input.normalized_data.authorization_process
	not process.continuous_monitoring_integrated
	msg := "PM-10: Continuous monitoring not integrated into the authorization process"
}

deny_no_common_controls contains msg if {
	process := input.normalized_data.authorization_process
	not process.common_controls_identified
	msg := "PM-10: Common controls have not been identified and documented"
}

default compliant := false

compliant if {
	count(deny_no_auth_process) == 0
	count(deny_no_authorizing_official) == 0
	count(deny_ato_expired) == 0
	count(deny_ato_expiring_soon) == 0
	count(deny_no_continuous_monitoring) == 0
	count(deny_no_common_controls) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_auth_process],
		[f | some f in deny_no_authorizing_official],
	),
	array.concat(
		array.concat(
			[f | some f in deny_ato_expired],
			[f | some f in deny_ato_expiring_soon],
		),
		array.concat(
			[f | some f in deny_no_continuous_monitoring],
			[f | some f in deny_no_common_controls],
		),
	),
)

result := {
	"control_id": "PM-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
