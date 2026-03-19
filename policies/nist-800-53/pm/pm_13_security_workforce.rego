package nist.pm.pm_13

import rego.v1

# PM-13: Security and Privacy Workforce

deny_no_workforce_program contains msg if {
	not input.normalized_data.security_workforce
	msg := "PM-13: No security and privacy workforce development and improvement program established"
}

deny_no_training_requirements contains msg if {
	wf := input.normalized_data.security_workforce
	not wf.training_requirements_defined
	msg := "PM-13: Security workforce training requirements have not been defined"
}

deny_staff_not_certified contains msg if {
	some staff in input.normalized_data.security_workforce.personnel
	staff.role == "security"
	not staff.certifications_current
	msg := sprintf("PM-13: Security staff member '%s' does not have current certifications", [staff.name])
}

deny_no_skills_assessment contains msg if {
	wf := input.normalized_data.security_workforce
	not wf.skills_assessment_completed
	msg := "PM-13: No security workforce skills assessment has been completed"
}

deny_workforce_plan_outdated contains msg if {
	wf := input.normalized_data.security_workforce
	wf.last_review_days > 365
	msg := sprintf("PM-13: Security workforce development plan has not been reviewed in %d days", [wf.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_workforce_program) == 0
	count(deny_no_training_requirements) == 0
	count(deny_staff_not_certified) == 0
	count(deny_no_skills_assessment) == 0
	count(deny_workforce_plan_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_workforce_program],
		[f | some f in deny_no_training_requirements],
	),
	array.concat(
		[f | some f in deny_staff_not_certified],
		array.concat(
			[f | some f in deny_no_skills_assessment],
			[f | some f in deny_workforce_plan_outdated],
		),
	),
)

result := {
	"control_id": "PM-13",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
