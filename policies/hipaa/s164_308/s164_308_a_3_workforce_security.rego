package hipaa.s164_308.s164_308_a_3

import rego.v1

# 164.308(a)(3): Workforce Security
# Requires policies and procedures to ensure workforce members have
# appropriate access to ePHI and to prevent unauthorized access

deny_no_access_authorization_policy contains msg if {
	not input.normalized_data.policies.workforce_access_authorization
	msg := "164.308(a)(3): No workforce access authorization policy exists — must define procedures for granting access to ePHI"
}

deny_no_termination_procedure contains msg if {
	not input.normalized_data.policies.termination_procedures
	msg := "164.308(a)(3): No workforce termination procedures — must revoke access to ePHI upon termination"
}

deny_terminated_user_active contains msg if {
	some user in input.normalized_data.users
	user.employment_status == "terminated"
	user.account_enabled
	msg := sprintf("164.308(a)(3): Terminated employee '%s' still has active account access", [user.username])
}

deny_no_background_checks contains msg if {
	not input.normalized_data.policies.background_check_required
	msg := "164.308(a)(3): No background check requirement for workforce members with ePHI access"
}

default compliant := false

compliant if {
	count(deny_no_access_authorization_policy) == 0
	count(deny_no_termination_procedure) == 0
	count(deny_terminated_user_active) == 0
	count(deny_no_background_checks) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_access_authorization_policy],
		[f | some f in deny_no_termination_procedure],
	),
	array.concat(
		[f | some f in deny_terminated_user_active],
		[f | some f in deny_no_background_checks],
	),
)

result := {
	"control_id": "164.308(a)(3)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
