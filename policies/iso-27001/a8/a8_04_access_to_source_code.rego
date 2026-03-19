package iso_27001.a8.a8_04

import rego.v1

# A.8.4: Access to Source Code
# Validates source code access controls and repository security

deny_repo_no_access_controls contains msg if {
	some repo in input.normalized_data.codecommit.repositories
	not repo.has_access_controls
	msg := sprintf("A.8.4: Repository '%s' has no access controls configured", [repo.name])
}

deny_no_approval_rules contains msg if {
	not input.normalized_data.codecommit.approval_rules_configured
	msg := "A.8.4: No approval rule templates configured for code review enforcement"
}

deny_repo_public contains msg if {
	some repo in input.normalized_data.codecommit.repositories
	repo.is_public
	msg := sprintf("A.8.4: Repository '%s' is publicly accessible — source code exposed", [repo.name])
}

deny_no_branch_protection contains msg if {
	some repo in input.normalized_data.codecommit.repositories
	not repo.main_branch_protected
	msg := sprintf("A.8.4: Repository '%s' main branch has no protection rules", [repo.name])
}

default compliant := false

compliant if {
	count(deny_repo_no_access_controls) == 0
	count(deny_no_approval_rules) == 0
	count(deny_repo_public) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_repo_no_access_controls],
		[f | some f in deny_no_approval_rules],
	),
	array.concat(
		[f | some f in deny_repo_public],
		[f | some f in deny_no_branch_protection],
	),
)

result := {
	"control_id": "A.8.4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
