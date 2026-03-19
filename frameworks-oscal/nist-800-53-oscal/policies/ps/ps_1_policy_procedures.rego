package nist.ps.ps_1

import rego.v1

# PS-1: Policy and Procedures

deny_no_personnel_security_policy contains msg if {
	not input.normalized_data.personnel_security_policy
	msg := "PS-1: No personnel security policy established"
}

deny_policy_not_approved contains msg if {
	policy := input.normalized_data.personnel_security_policy
	not policy.approved
	msg := "PS-1: Personnel security policy has not been approved by designated official"
}

deny_policy_outdated contains msg if {
	policy := input.normalized_data.personnel_security_policy
	policy.last_review_days > 365
	msg := sprintf("PS-1: Personnel security policy has not been reviewed in %d days", [policy.last_review_days])
}

deny_no_procedures contains msg if {
	policy := input.normalized_data.personnel_security_policy
	not policy.procedures_documented
	msg := "PS-1: Personnel security procedures have not been documented"
}

deny_procedures_outdated contains msg if {
	policy := input.normalized_data.personnel_security_policy
	policy.procedures_last_review_days > 365
	msg := sprintf("PS-1: Personnel security procedures have not been reviewed in %d days", [policy.procedures_last_review_days])
}

deny_policy_not_disseminated contains msg if {
	policy := input.normalized_data.personnel_security_policy
	not policy.disseminated_to_personnel
	msg := "PS-1: Personnel security policy has not been disseminated to relevant personnel"
}

default compliant := false

compliant if {
	count(deny_no_personnel_security_policy) == 0
	count(deny_policy_not_approved) == 0
	count(deny_policy_outdated) == 0
	count(deny_no_procedures) == 0
	count(deny_procedures_outdated) == 0
	count(deny_policy_not_disseminated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_personnel_security_policy],
		[f | some f in deny_policy_not_approved],
	),
	array.concat(
		array.concat(
			[f | some f in deny_policy_outdated],
			[f | some f in deny_no_procedures],
		),
		array.concat(
			[f | some f in deny_procedures_outdated],
			[f | some f in deny_policy_not_disseminated],
		),
	),
)

result := {
	"control_id": "PS-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
