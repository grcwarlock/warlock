package nist.pm.pm_12

import rego.v1

# PM-12: Insider Threat Program

deny_no_insider_threat_program contains msg if {
	not input.normalized_data.insider_threat_program
	msg := "PM-12: No insider threat program established"
}

deny_no_threat_indicators contains msg if {
	itp := input.normalized_data.insider_threat_program
	not itp.threat_indicators_defined
	msg := "PM-12: Insider threat indicators have not been defined"
}

deny_no_awareness_training contains msg if {
	itp := input.normalized_data.insider_threat_program
	not itp.awareness_training_provided
	msg := "PM-12: Insider threat awareness training not provided to personnel"
}

deny_no_cross_discipline_team contains msg if {
	itp := input.normalized_data.insider_threat_program
	not itp.cross_discipline_team
	msg := "PM-12: No cross-discipline insider threat incident handling team established"
}

deny_no_reporting_mechanism contains msg if {
	itp := input.normalized_data.insider_threat_program
	not itp.reporting_mechanism
	msg := "PM-12: No mechanism for reporting insider threat indicators"
}

deny_program_not_reviewed contains msg if {
	itp := input.normalized_data.insider_threat_program
	itp.last_review_days > 365
	msg := sprintf("PM-12: Insider threat program has not been reviewed in %d days", [itp.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_insider_threat_program) == 0
	count(deny_no_threat_indicators) == 0
	count(deny_no_awareness_training) == 0
	count(deny_no_cross_discipline_team) == 0
	count(deny_no_reporting_mechanism) == 0
	count(deny_program_not_reviewed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_insider_threat_program],
		[f | some f in deny_no_threat_indicators],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_awareness_training],
			[f | some f in deny_no_cross_discipline_team],
		),
		array.concat(
			[f | some f in deny_no_reporting_mechanism],
			[f | some f in deny_program_not_reviewed],
		),
	),
)

result := {
	"control_id": "PM-12",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
