package nist.pe.pe_18

import rego.v1

# PE-18: Location of Information System Components

deny_components_in_public_area contains msg if {
	some component in input.normalized_data.physical_security.system_components
	component.in_public_area
	component.processes_sensitive_data
	msg := sprintf("PE-18: System component '%s' (%s) processes sensitive data but is located in a public area", [component.component_id, component.component_type])
}

deny_no_physical_separation contains msg if {
	some component in input.normalized_data.physical_security.system_components
	component.critical
	not component.physically_separated
	msg := sprintf("PE-18: Critical system component '%s' is not physically separated from non-critical components", [component.component_id])
}

deny_visible_to_unauthorized contains msg if {
	some component in input.normalized_data.physical_security.system_components
	component.display_visible_to_unauthorized
	msg := sprintf("PE-18: Display of system component '%s' is visible to unauthorized individuals", [component.component_id])
}

deny_no_location_documentation contains msg if {
	some component in input.normalized_data.physical_security.system_components
	not component.location_documented
	msg := sprintf("PE-18: Physical location of system component '%s' is not documented", [component.component_id])
}

default compliant := false

compliant if {
	count(deny_components_in_public_area) == 0
	count(deny_no_physical_separation) == 0
	count(deny_visible_to_unauthorized) == 0
	count(deny_no_location_documentation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_components_in_public_area],
		[f | some f in deny_no_physical_separation],
	),
	array.concat(
		[f | some f in deny_visible_to_unauthorized],
		[f | some f in deny_no_location_documentation],
	),
)

result := {
	"control_id": "PE-18",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
