package soc2.cc2

import rego.v1

# SOC 2 CC2: Communication and Information (COSO Principles 13-15)
# Internal/external communication, system boundaries documented

deny_no_internal_communication_policy contains msg if {
	not input.normalized_data.governance.internal_communication_policy_exists
	msg := "CC2.1: No internal communication policy — information quality and flow not governed"
}

deny_no_system_description contains msg if {
	not input.normalized_data.governance.system_description_documented
	msg := "CC2.1: System description not documented — internal stakeholders lack awareness of system boundaries and controls"
}

deny_no_control_communication contains msg if {
	not input.normalized_data.governance.control_responsibilities_communicated
	msg := "CC2.2: Internal control responsibilities not communicated to personnel"
}

deny_no_external_communication_policy contains msg if {
	not input.normalized_data.governance.external_communication_policy_exists
	msg := "CC2.3: No external communication policy — commitments and obligations to external parties not governed"
}

deny_no_boundary_documentation contains msg if {
	not input.normalized_data.governance.system_boundaries_defined
	msg := "CC2.3: System boundaries not documented — scope of services and infrastructure not defined for external parties"
}

deny_no_whistleblower_channel contains msg if {
	not input.normalized_data.governance.whistleblower_channel_exists
	msg := "CC2.2: No anonymous reporting channel for control deficiencies or ethical concerns"
}

default compliant := false

compliant if {
	count(deny_no_internal_communication_policy) == 0
	count(deny_no_system_description) == 0
	count(deny_no_control_communication) == 0
	count(deny_no_external_communication_policy) == 0
	count(deny_no_boundary_documentation) == 0
	count(deny_no_whistleblower_channel) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_internal_communication_policy],
			[f | some f in deny_no_system_description],
		),
		array.concat(
			[f | some f in deny_no_control_communication],
			[f | some f in deny_no_external_communication_policy],
		),
	),
	array.concat(
		[f | some f in deny_no_boundary_documentation],
		[f | some f in deny_no_whistleblower_channel],
	),
)

result := {
	"control_id": "CC2",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
