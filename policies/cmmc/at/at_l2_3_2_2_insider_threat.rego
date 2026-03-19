package cmmc.at.at_l2_3_2_2

import rego.v1

# AT.L2-3.2.2: Insider Threat Awareness
# Provide security awareness training on recognizing and reporting potential indicators of insider threat

deny_no_insider_threat_training contains msg if {
	some user in input.normalized_data.users
	user.enabled
	not user.insider_threat_training_completed
	msg := sprintf("AT.L2-3.2.2: User '%s' has not completed insider threat awareness training", [user.username])
}

deny_insider_training_expired contains msg if {
	some user in input.normalized_data.users
	user.enabled
	user.insider_threat_training_completed
	user.insider_threat_training_age_days > 365
	msg := sprintf("AT.L2-3.2.2: User '%s' insider threat training expired %d days ago — annual renewal required", [user.username, user.insider_threat_training_age_days])
}

deny_no_reporting_mechanism contains msg if {
	some org_unit in input.normalized_data.org_units
	not org_unit.insider_threat_reporting_mechanism
	msg := sprintf("AT.L2-3.2.2: Organizational unit '%s' lacks a documented insider threat reporting mechanism", [org_unit.name])
}

default compliant := false

compliant if {
	count(deny_no_insider_threat_training) == 0
	count(deny_insider_training_expired) == 0
	count(deny_no_reporting_mechanism) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_insider_threat_training],
		[f | some f in deny_insider_training_expired],
	),
	[f | some f in deny_no_reporting_mechanism],
)

result := {
	"control_id": "AT.L2-3.2.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
