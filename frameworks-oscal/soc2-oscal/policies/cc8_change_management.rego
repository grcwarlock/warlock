package soc2.cc8

import rego.v1

# SOC 2 CC8: Change Management
# Change management process, approval workflows, testing, rollback

deny_no_change_management_policy contains msg if {
	not input.normalized_data.governance.change_management_policy_exists
	msg := "CC8.1: No change management policy — infrastructure and software changes not governed"
}

deny_no_change_approval_workflow contains msg if {
	input.provider == "aws"
	not input.normalized_data.change_management.approval_workflow_enabled
	msg := "CC8.1: No change approval workflow — changes can be deployed without authorization"
}

deny_unapproved_changes contains msg if {
	some change in input.normalized_data.change_management.recent_changes
	not change.approved
	msg := sprintf("CC8.1: Change '%s' deployed without approval on %s", [change.id, change.date])
}

deny_no_testing_requirements contains msg if {
	not input.normalized_data.change_management.testing_required_before_deploy
	msg := "CC8.1: No testing requirements before deployment — changes not validated prior to production"
}

deny_no_rollback_procedures contains msg if {
	not input.normalized_data.change_management.rollback_procedures_defined
	msg := "CC8.1: No rollback procedures defined — failed changes cannot be systematically reverted"
}

deny_no_cicd_gates contains msg if {
	input.normalized_data.change_management.cicd_pipeline_exists
	not input.normalized_data.change_management.cicd_security_gates_enabled
	msg := "CC8.1: CI/CD pipeline exists but security gates not enabled — automated quality and security checks missing"
}

deny_no_change_log contains msg if {
	not input.normalized_data.change_management.change_log_maintained
	msg := "CC8.1: No change log maintained — historical record of changes not available for audit"
}

deny_no_emergency_change_process contains msg if {
	not input.normalized_data.change_management.emergency_change_process_defined
	msg := "CC8.1: No emergency change process — expedited changes lack documented authorization and post-implementation review"
}

default compliant := false

compliant if {
	count(deny_no_change_management_policy) == 0
	count(deny_no_change_approval_workflow) == 0
	count(deny_unapproved_changes) == 0
	count(deny_no_testing_requirements) == 0
	count(deny_no_rollback_procedures) == 0
	count(deny_no_cicd_gates) == 0
	count(deny_no_change_log) == 0
	count(deny_no_emergency_change_process) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_change_management_policy],
			[f | some f in deny_no_change_approval_workflow],
		),
		array.concat(
			[f | some f in deny_unapproved_changes],
			[f | some f in deny_no_testing_requirements],
		),
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_rollback_procedures],
			[f | some f in deny_no_cicd_gates],
		),
		array.concat(
			[f | some f in deny_no_change_log],
			[f | some f in deny_no_emergency_change_process],
		),
	),
)

result := {
	"control_id": "CC8",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
