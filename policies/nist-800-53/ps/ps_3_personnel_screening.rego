package nist.ps.ps_3

import rego.v1

# PS-3: Personnel Screening

deny_no_screening_process contains msg if {
	not input.normalized_data.personnel_screening
	msg := "PS-3: No personnel screening process established"
}

deny_personnel_not_screened contains msg if {
	some person in input.normalized_data.personnel
	person.requires_screening
	not person.screening_completed
	msg := sprintf("PS-3: Personnel '%s' has not completed required screening", [person.name])
}

deny_screening_expired contains msg if {
	some person in input.normalized_data.personnel
	person.screening_completed
	person.screening_expiration_days < 0
	msg := sprintf("PS-3: Personnel '%s' screening has expired (%d days past expiration)", [person.name, abs(person.screening_expiration_days)])
}

deny_rescreening_overdue contains msg if {
	some person in input.normalized_data.personnel
	person.screening_completed
	person.days_since_last_screening > input.normalized_data.personnel_screening.rescreening_interval_days
	msg := sprintf("PS-3: Personnel '%s' rescreening is overdue (last screened %d days ago)", [person.name, person.days_since_last_screening])
}

deny_screening_not_commensurate contains msg if {
	some person in input.normalized_data.personnel
	person.screening_completed
	not person.screening_commensurate_with_risk
	msg := sprintf("PS-3: Personnel '%s' screening level is not commensurate with position risk designation", [person.name])
}

default compliant := false

compliant if {
	count(deny_no_screening_process) == 0
	count(deny_personnel_not_screened) == 0
	count(deny_screening_expired) == 0
	count(deny_rescreening_overdue) == 0
	count(deny_screening_not_commensurate) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_screening_process],
		[f | some f in deny_personnel_not_screened],
	),
	array.concat(
		[f | some f in deny_screening_expired],
		array.concat(
			[f | some f in deny_rescreening_overdue],
			[f | some f in deny_screening_not_commensurate],
		),
	),
)

result := {
	"control_id": "PS-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
