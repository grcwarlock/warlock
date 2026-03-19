package cmmc.ir.ir_l2_3_6_2

import rego.v1

# IR.L2-3.6.2: Incident Reporting
# Track, document, and report incidents to designated officials and/or authorities

deny_no_incident_tracking contains msg if {
	some org_unit in input.normalized_data.org_units
	not org_unit.incident_tracking_system
	msg := sprintf("IR.L2-3.6.2: Organizational unit '%s' does not have an incident tracking system", [org_unit.name])
}

deny_unresolved_incidents contains msg if {
	some incident in input.normalized_data.incidents
	incident.status == "open"
	incident.age_days > 30
	msg := sprintf("IR.L2-3.6.2: Incident '%s' has been open for %d days without resolution", [incident.id, incident.age_days])
}

deny_no_dibcac_reporting contains msg if {
	some incident in input.normalized_data.incidents
	incident.involves_cui
	not incident.reported_to_dibcac
	msg := sprintf("IR.L2-3.6.2: CUI incident '%s' has not been reported to DIBCAC within 72 hours as required", [incident.id])
}

default compliant := false

compliant if {
	count(deny_no_incident_tracking) == 0
	count(deny_unresolved_incidents) == 0
	count(deny_no_dibcac_reporting) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_tracking],
		[f | some f in deny_unresolved_incidents],
	),
	[f | some f in deny_no_dibcac_reporting],
)

result := {
	"control_id": "IR.L2-3.6.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
