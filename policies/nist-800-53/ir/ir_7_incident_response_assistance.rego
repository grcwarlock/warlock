package nist.ir.ir_7

import rego.v1

# IR-7: Incident Response Assistance
# Validates incident response support resources are available to system users

deny_no_ir_support contains msg if {
	not input.normalized_data.ir_assistance
	msg := "IR-7: No incident response assistance capability configured"
}

deny_no_help_desk contains msg if {
	input.normalized_data.ir_assistance
	not input.normalized_data.ir_assistance.help_desk_available
	msg := "IR-7: No help desk or support channel available for incident response assistance"
}

deny_no_24x7_availability contains msg if {
	input.normalized_data.ir_assistance
	not input.normalized_data.ir_assistance.available_24x7
	msg := "IR-7: Incident response assistance is not available 24x7"
}

deny_no_knowledge_base contains msg if {
	input.normalized_data.ir_assistance
	not input.normalized_data.ir_assistance.knowledge_base_available
	msg := "IR-7: No knowledge base available for incident response guidance"
}

deny_no_contact_information contains msg if {
	input.normalized_data.ir_assistance
	not input.normalized_data.ir_assistance.contact_information_published
	msg := "IR-7: Incident response contact information is not published to system users"
}

deny_sla_not_defined contains msg if {
	input.normalized_data.ir_assistance
	not input.normalized_data.ir_assistance.response_sla_defined
	msg := "IR-7: Response SLA for incident response assistance is not defined"
}

default compliant := false

compliant if {
	count(deny_no_ir_support) == 0
	count(deny_no_help_desk) == 0
	count(deny_no_contact_information) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_support],
		[f | some f in deny_no_help_desk],
	),
	array.concat(
		[f | some f in deny_no_24x7_availability],
		array.concat(
			[f | some f in deny_no_knowledge_base],
			array.concat(
				[f | some f in deny_no_contact_information],
				[f | some f in deny_sla_not_defined],
			),
		),
	),
)

result := {
	"control_id": "IR-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
