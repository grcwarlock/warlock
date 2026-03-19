package cmmc.ir.ir_l2_3_6_1

import rego.v1

# IR.L2-3.6.1: Incident Handling
# Establish an operational incident-handling capability for organizational systems

deny_no_incident_plan contains msg if {
	some org_unit in input.normalized_data.org_units
	not org_unit.incident_response_plan_documented
	msg := sprintf("IR.L2-3.6.1: Organizational unit '%s' does not have a documented incident response plan", [org_unit.name])
}

deny_no_incident_team contains msg if {
	some org_unit in input.normalized_data.org_units
	not org_unit.incident_response_team_assigned
	msg := sprintf("IR.L2-3.6.1: Organizational unit '%s' does not have an assigned incident response team", [org_unit.name])
}

deny_no_incident_testing contains msg if {
	some org_unit in input.normalized_data.org_units
	org_unit.incident_response_plan_documented
	org_unit.ir_plan_last_tested_days > 365
	msg := sprintf("IR.L2-3.6.1: Organizational unit '%s' has not tested its incident response plan in %d days", [org_unit.name, org_unit.ir_plan_last_tested_days])
}

default compliant := false

compliant if {
	count(deny_no_incident_plan) == 0
	count(deny_no_incident_team) == 0
	count(deny_no_incident_testing) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_plan],
		[f | some f in deny_no_incident_team],
	),
	[f | some f in deny_no_incident_testing],
)

result := {
	"control_id": "IR.L2-3.6.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
