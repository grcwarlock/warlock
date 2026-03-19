package nist.sa.sa_21

import rego.v1

# SA-21: Developer Screening

deny_no_developer_screening contains msg if {
	not input.normalized_data.developer_screening
	msg := "SA-21: No developer screening requirements established"
}

deny_developer_not_screened contains msg if {
	some dev in input.normalized_data.developers
	dev.has_privileged_access
	not dev.background_check_completed
	msg := sprintf("SA-21: Developer '%s' with privileged access has not completed background screening", [dev.name])
}

deny_screening_criteria_missing contains msg if {
	ds := input.normalized_data.developer_screening
	not ds.screening_criteria_defined
	msg := "SA-21: Developer screening criteria not defined based on system criticality"
}

deny_contractor_developers_not_screened contains msg if {
	some dev in input.normalized_data.developers
	dev.is_contractor
	not dev.screening_verified
	msg := sprintf("SA-21: Contractor developer '%s' screening has not been verified", [dev.name])
}

deny_screening_not_reviewed contains msg if {
	ds := input.normalized_data.developer_screening
	ds.last_review_days > 365
	msg := sprintf("SA-21: Developer screening requirements have not been reviewed in %d days", [ds.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_developer_screening) == 0
	count(deny_developer_not_screened) == 0
	count(deny_screening_criteria_missing) == 0
	count(deny_contractor_developers_not_screened) == 0
	count(deny_screening_not_reviewed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_developer_screening],
		[f | some f in deny_developer_not_screened],
	),
	array.concat(
		[f | some f in deny_screening_criteria_missing],
		array.concat(
			[f | some f in deny_contractor_developers_not_screened],
			[f | some f in deny_screening_not_reviewed],
		),
	),
)

result := {
	"control_id": "SA-21",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
