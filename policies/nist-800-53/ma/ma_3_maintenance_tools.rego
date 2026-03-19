package nist.ma.ma_3

import rego.v1

# MA-3: Maintenance Tools

deny_unapproved_tool contains msg if {
	some tool in input.normalized_data.maintenance.tools_in_use
	not tool.approved
	msg := sprintf("MA-3: Maintenance tool '%s' (version %s) is not on the approved tools list", [tool.tool_name, tool.version])
}

deny_tool_no_inspection contains msg if {
	some tool in input.normalized_data.maintenance.tools_in_use
	tool.approved
	not tool.inspected_before_use
	msg := sprintf("MA-3: Approved maintenance tool '%s' was not inspected before use", [tool.tool_name])
}

deny_tool_no_integrity_check contains msg if {
	some tool in input.normalized_data.maintenance.tools_in_use
	tool.approved
	not tool.integrity_verified
	msg := sprintf("MA-3: Maintenance tool '%s' has not passed integrity verification", [tool.tool_name])
}

deny_no_approved_tools_list contains msg if {
	not input.normalized_data.maintenance.approved_tools_list_defined
	msg := "MA-3: No approved maintenance tools list has been defined"
}

default compliant := false

compliant if {
	count(deny_unapproved_tool) == 0
	count(deny_tool_no_inspection) == 0
	count(deny_tool_no_integrity_check) == 0
	count(deny_no_approved_tools_list) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unapproved_tool],
		[f | some f in deny_tool_no_inspection],
	),
	array.concat(
		[f | some f in deny_tool_no_integrity_check],
		[f | some f in deny_no_approved_tools_list],
	),
)

result := {
	"control_id": "MA-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
