package hipaa.s164_308.s164_308_a_4

import rego.v1

# 164.308(a)(4): Information Access Management
# Requires policies and procedures for authorizing access to ePHI
# consistent with the minimum necessary standard

deny_no_role_based_access contains msg if {
	not input.normalized_data.config.role_based_access_enabled
	msg := "164.308(a)(4): Role-based access control is not enabled — access to ePHI must be granted based on job function"
}

deny_overprivileged_user contains msg if {
	some user in input.normalized_data.users
	user.admin_access
	not user.admin_justified
	msg := sprintf("164.308(a)(4): User '%s' has admin privileges without documented justification — violates minimum necessary standard", [user.username])
}

deny_no_access_review contains msg if {
	not input.normalized_data.policies.periodic_access_review
	msg := "164.308(a)(4): No periodic access review process — must regularly review workforce access rights to ePHI"
}

deny_stale_access_review contains msg if {
	input.normalized_data.policies.periodic_access_review
	input.normalized_data.policies.last_access_review_days > 180
	msg := sprintf("164.308(a)(4): Access review is overdue — last performed %d days ago (must be within 180 days)", [input.normalized_data.policies.last_access_review_days])
}

default compliant := false

compliant if {
	count(deny_no_role_based_access) == 0
	count(deny_overprivileged_user) == 0
	count(deny_no_access_review) == 0
	count(deny_stale_access_review) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_role_based_access],
		[f | some f in deny_overprivileged_user],
	),
	array.concat(
		[f | some f in deny_no_access_review],
		[f | some f in deny_stale_access_review],
	),
)

result := {
	"control_id": "164.308(a)(4)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
