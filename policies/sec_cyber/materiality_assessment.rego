package warlock.sec_cyber.materiality

import rego.v1

# SEC Cyber — Incident Materiality Assessment
# Item 1.05 / S-K 106: Determining materiality of cybersecurity incidents

# Materiality assessment process documented
deny_no_materiality_process contains msg if {
	not input.normalized_data.sec_cyber.materiality_assessment_process
	msg := "Item 1.05: No materiality assessment process — cannot determine 8-K filing obligations"
}

# Materiality criteria defined (financial, operational, reputational)
deny_no_materiality_criteria contains msg if {
	not input.normalized_data.sec_cyber.materiality_criteria_defined
	msg := "Item 1.05: Materiality criteria not defined — financial, operational, reputational thresholds missing"
}

# Incident assessed within required timeframe (4 business days)
deny_late_materiality_assessment contains msg if {
	some incident in input.normalized_data.sec_cyber.incidents
	not incident.materiality_assessed
	incident.business_days_since_discovery > 4
	msg := sprintf("Item 1.05: Incident '%s' — materiality not assessed within 4 business days", [incident.id])
}

# Material incidents disclosed to SEC
deny_undisclosed_material_incident contains msg if {
	some incident in input.normalized_data.sec_cyber.incidents
	incident.materiality_assessed
	incident.is_material
	not incident.sec_disclosed
	msg := sprintf("Item 1.05: Material incident '%s' not disclosed to SEC via Form 8-K", [incident.id])
}

# Aggregation of incidents considered for materiality
deny_no_aggregation_analysis contains msg if {
	not input.normalized_data.sec_cyber.incident_aggregation_analysis
	msg := "Item 1.05: No aggregation analysis — related incidents may collectively be material"
}

default compliant := false

compliant if {
	count(deny_no_materiality_process) == 0
	count(deny_no_materiality_criteria) == 0
	count(deny_late_materiality_assessment) == 0
	count(deny_undisclosed_material_incident) == 0
	count(deny_no_aggregation_analysis) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_materiality_process],
		[f | some f in deny_no_materiality_criteria],
	),
	array.concat(
		array.concat(
			[f | some f in deny_late_materiality_assessment],
			[f | some f in deny_undisclosed_material_incident],
		),
		[f | some f in deny_no_aggregation_analysis],
	),
)

result := {
	"control_id": "Item 1.05",
	"framework": "SEC Cyber",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
