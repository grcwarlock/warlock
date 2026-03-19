package nist.pm.pm_5

import rego.v1

# PM-5: System Inventory

deny_no_system_inventory contains msg if {
	not input.normalized_data.system_inventory
	msg := "PM-5: No inventory of organizational systems maintained"
}

deny_inventory_outdated contains msg if {
	inv := input.normalized_data.system_inventory
	inv.last_update_days > 90
	msg := sprintf("PM-5: System inventory has not been updated in %d days (exceeds 90-day requirement)", [inv.last_update_days])
}

deny_system_no_authorization contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.authorization_status
	msg := sprintf("PM-5: System '%s' does not have an authorization status recorded", [system.name])
}

deny_system_no_owner contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.system_owner
	msg := sprintf("PM-5: System '%s' does not have a designated system owner", [system.name])
}

deny_system_no_boundary contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.boundary_defined
	msg := sprintf("PM-5: System '%s' does not have an authorization boundary defined", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_system_inventory) == 0
	count(deny_inventory_outdated) == 0
	count(deny_system_no_authorization) == 0
	count(deny_system_no_owner) == 0
	count(deny_system_no_boundary) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_system_inventory],
		[f | some f in deny_inventory_outdated],
	),
	array.concat(
		[f | some f in deny_system_no_authorization],
		array.concat(
			[f | some f in deny_system_no_owner],
			[f | some f in deny_system_no_boundary],
		),
	),
)

result := {
	"control_id": "PM-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
