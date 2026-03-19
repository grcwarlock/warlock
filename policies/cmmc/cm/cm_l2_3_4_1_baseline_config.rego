package cmmc.cm.cm_l2_3_4_1

import rego.v1

# CM.L2-3.4.1: Baseline Configuration
# Establish and maintain baseline configurations and inventories of organizational systems

deny_no_baseline contains msg if {
	some system in input.normalized_data.systems
	not system.baseline_configuration_documented
	msg := sprintf("CM.L2-3.4.1: System '%s' does not have a documented baseline configuration", [system.name])
}

deny_config_drift contains msg if {
	some system in input.normalized_data.systems
	system.baseline_configuration_documented
	system.configuration_drift_detected
	msg := sprintf("CM.L2-3.4.1: System '%s' has drifted from its approved baseline configuration", [system.name])
}

deny_no_asset_inventory contains msg if {
	some system in input.normalized_data.systems
	not system.in_asset_inventory
	msg := sprintf("CM.L2-3.4.1: System '%s' is not registered in the organizational asset inventory", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_baseline) == 0
	count(deny_config_drift) == 0
	count(deny_no_asset_inventory) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_baseline],
		[f | some f in deny_config_drift],
	),
	[f | some f in deny_no_asset_inventory],
)

result := {
	"control_id": "CM.L2-3.4.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
