package gdpr.art6

import rego.v1

# GDPR Article 6: Lawfulness of processing
# At least one legal basis must apply for each processing activity

deny_no_legal_basis contains msg if {
	some activity in input.normalized_data.processing_activities
	not activity.legal_basis
	msg := sprintf("Art6: Processing activity '%s' has no documented legal basis", [activity.name])
}

deny_invalid_legal_basis contains msg if {
	valid_bases := {"consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"}
	some activity in input.normalized_data.processing_activities
	activity.legal_basis
	not activity.legal_basis in valid_bases
	msg := sprintf("Art6: Processing activity '%s' has invalid legal basis '%s'", [activity.name, activity.legal_basis])
}

deny_consent_not_recorded contains msg if {
	some activity in input.normalized_data.processing_activities
	activity.legal_basis == "consent"
	not activity.consent_recorded
	msg := sprintf("Art6: Processing activity '%s' relies on consent but no consent record exists", [activity.name])
}

default compliant := false

compliant if {
	count(deny_no_legal_basis) == 0
	count(deny_invalid_legal_basis) == 0
	count(deny_consent_not_recorded) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_legal_basis],
		[f | some f in deny_invalid_legal_basis],
	),
	[f | some f in deny_consent_not_recorded],
)

result := {
	"control_id": "Art6",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
