package pci_dss.r9

import rego.v1

# PCI DSS 4.0 Requirement 9: Restrict Physical Access to Cardholder Data

deny_unmonitored_access contains msg if {
	some area in input.normalized_data.physical_areas
	area.contains_cardholder_data
	not area.access_control_enabled
	msg := sprintf("R9.1: Area '%s' with cardholder data lacks physical access controls", [area.name])
}

deny_no_visitor_log contains msg if {
	some area in input.normalized_data.physical_areas
	area.contains_cardholder_data
	not area.visitor_log_active
	msg := sprintf("R9.3: Area '%s' does not maintain visitor logs", [area.name])
}

default compliant := false

compliant if {
	count(deny_unmonitored_access) == 0
	count(deny_no_visitor_log) == 0
}

findings := array.concat(
	[f | some f in deny_unmonitored_access],
	[f | some f in deny_no_visitor_log],
)

result := {
	"control_id": "R9",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
