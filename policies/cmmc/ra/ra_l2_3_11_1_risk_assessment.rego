package cmmc.ra.ra_l2_3_11_1

import rego.v1

# RA.L2-3.11.1: Risk Assessment
# Periodically assess the risk to organizational operations, assets, and individuals

deny_no_risk_assessment contains msg if {
	some org_unit in input.normalized_data.org_units
	not org_unit.risk_assessment_completed
	msg := sprintf("RA.L2-3.11.1: Organizational unit '%s' has not completed a risk assessment", [org_unit.name])
}

deny_stale_risk_assessment contains msg if {
	some org_unit in input.normalized_data.org_units
	org_unit.risk_assessment_completed
	org_unit.risk_assessment_age_days > 365
	msg := sprintf("RA.L2-3.11.1: Organizational unit '%s' risk assessment is %d days old — annual reassessment required", [org_unit.name, org_unit.risk_assessment_age_days])
}

deny_no_vulnerability_scanning contains msg if {
	some system in input.normalized_data.systems
	system.processes_cui
	not system.vulnerability_scanning_enabled
	msg := sprintf("RA.L2-3.11.1: CUI system '%s' does not have vulnerability scanning enabled", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_risk_assessment) == 0
	count(deny_stale_risk_assessment) == 0
	count(deny_no_vulnerability_scanning) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_assessment],
		[f | some f in deny_stale_risk_assessment],
	),
	[f | some f in deny_no_vulnerability_scanning],
)

result := {
	"control_id": "RA.L2-3.11.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
