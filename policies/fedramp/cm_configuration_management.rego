package warlock.fedramp.cm

import rego.v1

# FedRAMP Configuration Management Requirements

# CM-2: Baseline configuration documented
deny_no_baseline contains msg if {
	not input.normalized_data.configuration.baseline_documented
	msg := "CM-2: No baseline configuration documented for FedRAMP boundary"
}

# CM-3: Configuration change control — all changes reviewed and approved
deny_unapproved_changes contains msg if {
	some change in input.normalized_data.configuration.recent_changes
	not change.approved
	msg := sprintf("CM-3: Configuration change '%s' not approved through change control", [change.id])
}

# CM-6: Configuration settings — hardened per FedRAMP benchmarks
deny_no_hardening contains msg if {
	some system in input.normalized_data.configuration.systems
	not system.hardened
	msg := sprintf("CM-6: System '%s' not hardened per FedRAMP configuration benchmarks", [system.id])
}

# CM-7: Least functionality — unnecessary services disabled
deny_unnecessary_services contains msg if {
	some system in input.normalized_data.configuration.systems
	some service in system.unnecessary_services
	service.enabled
	msg := sprintf("CM-7: System '%s' has unnecessary service '%s' enabled", [system.id, service.name])
}

# CM-8: Information system component inventory
deny_no_component_inventory contains msg if {
	not input.normalized_data.configuration.component_inventory_maintained
	msg := "CM-8: No system component inventory maintained within FedRAMP boundary"
}

default compliant := false

compliant if {
	count(deny_no_baseline) == 0
	count(deny_unapproved_changes) == 0
	count(deny_no_hardening) == 0
	count(deny_unnecessary_services) == 0
	count(deny_no_component_inventory) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_baseline],
		[f | some f in deny_unapproved_changes],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_hardening],
			[f | some f in deny_unnecessary_services],
		),
		[f | some f in deny_no_component_inventory],
	),
)

result := {
	"control_id": "CM",
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
