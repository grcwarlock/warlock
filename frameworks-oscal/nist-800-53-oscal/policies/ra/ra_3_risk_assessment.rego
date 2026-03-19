package nist.ra.ra_3

import rego.v1

# RA-3: Risk Assessment

deny_no_risk_assessment contains msg if {
	not input.normalized_data.risk_assessment
	msg := "RA-3: No risk assessment conducted for the organization or system"
}

deny_assessment_outdated contains msg if {
	ra := input.normalized_data.risk_assessment
	ra.last_assessment_days > 365
	msg := sprintf("RA-3: Risk assessment has not been updated in %d days", [ra.last_assessment_days])
}

deny_no_threat_identification contains msg if {
	ra := input.normalized_data.risk_assessment
	not ra.threats_identified
	msg := "RA-3: Risk assessment does not identify threats to the system"
}

deny_no_vulnerability_identification contains msg if {
	ra := input.normalized_data.risk_assessment
	not ra.vulnerabilities_identified
	msg := "RA-3: Risk assessment does not identify vulnerabilities in the system"
}

deny_no_likelihood_determination contains msg if {
	ra := input.normalized_data.risk_assessment
	not ra.likelihood_determined
	msg := "RA-3: Likelihood of threat exploitation has not been determined"
}

deny_no_impact_analysis contains msg if {
	ra := input.normalized_data.risk_assessment
	not ra.impact_analyzed
	msg := "RA-3: Impact of threat exploitation has not been analyzed"
}

deny_results_not_shared contains msg if {
	ra := input.normalized_data.risk_assessment
	not ra.results_shared_with_stakeholders
	msg := "RA-3: Risk assessment results have not been shared with relevant stakeholders"
}

default compliant := false

compliant if {
	count(deny_no_risk_assessment) == 0
	count(deny_assessment_outdated) == 0
	count(deny_no_threat_identification) == 0
	count(deny_no_vulnerability_identification) == 0
	count(deny_no_likelihood_determination) == 0
	count(deny_no_impact_analysis) == 0
	count(deny_results_not_shared) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_assessment],
		[f | some f in deny_assessment_outdated],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_threat_identification],
			[f | some f in deny_no_vulnerability_identification],
		),
		array.concat(
			[f | some f in deny_no_likelihood_determination],
			array.concat(
				[f | some f in deny_no_impact_analysis],
				[f | some f in deny_results_not_shared],
			),
		),
	),
)

result := {
	"control_id": "RA-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
