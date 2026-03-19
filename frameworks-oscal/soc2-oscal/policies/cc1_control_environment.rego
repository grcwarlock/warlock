package soc2.cc1

import rego.v1

# SOC 2 CC1: Control Environment (COSO Principles 1-5)
# Board oversight, management philosophy, org structure, competence, accountability

deny_no_code_of_conduct contains msg if {
	not input.normalized_data.governance.code_of_conduct_exists
	msg := "CC1.1: No code of conduct or ethics policy found — integrity and ethical values not documented"
}

deny_ethics_training_gap contains msg if {
	some employee in input.normalized_data.governance.employees
	not employee.ethics_training_current
	msg := sprintf("CC1.1: Employee '%s' has not completed annual ethics training", [employee.name])
}

deny_no_board_oversight contains msg if {
	not input.normalized_data.governance.audit_committee_charter_exists
	msg := "CC1.2: No audit committee charter found — board oversight responsibility not documented"
}

deny_insufficient_board_meetings contains msg if {
	input.normalized_data.governance.board_meetings_per_year < 4
	msg := sprintf("CC1.2: Only %d board/audit committee meetings per year — minimum 4 quarterly meetings required", [input.normalized_data.governance.board_meetings_per_year])
}

deny_no_org_structure contains msg if {
	not input.normalized_data.governance.org_chart_documented
	msg := "CC1.3: Organizational structure and reporting lines not documented"
}

deny_no_authority_definitions contains msg if {
	not input.normalized_data.governance.roles_and_responsibilities_defined
	msg := "CC1.3: Roles and responsibilities for internal controls not formally defined"
}

deny_no_competency_program contains msg if {
	not input.normalized_data.governance.competency_requirements_defined
	msg := "CC1.4: Competency requirements and professional development program not established"
}

deny_no_accountability contains msg if {
	not input.normalized_data.governance.accountability_policy_exists
	msg := "CC1.5: No accountability policy — internal control responsibilities not enforced"
}

default compliant := false

compliant if {
	count(deny_no_code_of_conduct) == 0
	count(deny_ethics_training_gap) == 0
	count(deny_no_board_oversight) == 0
	count(deny_insufficient_board_meetings) == 0
	count(deny_no_org_structure) == 0
	count(deny_no_authority_definitions) == 0
	count(deny_no_competency_program) == 0
	count(deny_no_accountability) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_code_of_conduct],
			[f | some f in deny_ethics_training_gap],
		),
		array.concat(
			[f | some f in deny_no_board_oversight],
			[f | some f in deny_insufficient_board_meetings],
		),
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_org_structure],
			[f | some f in deny_no_authority_definitions],
		),
		array.concat(
			[f | some f in deny_no_competency_program],
			[f | some f in deny_no_accountability],
		),
	),
)

result := {
	"control_id": "CC1",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
