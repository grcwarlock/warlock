package cmmc.ac.ac_l2_3_1_5

import rego.v1

# AC.L2-3.1.5: Least Privilege
# Employ the principle of least privilege, including for specific security functions and privileged accounts

deny_excessive_admin contains msg if {
	some user in input.normalized_data.users
	user.admin_access
	not user.admin_justified
	msg := sprintf("AC.L2-3.1.5: User '%s' has admin privileges without documented justification", [user.username])
}

deny_no_privilege_review contains msg if {
	some user in input.normalized_data.users
	user.privileged
	user.last_privilege_review_days > 90
	msg := sprintf("AC.L2-3.1.5: Privileged user '%s' has not had a privilege review in %d days", [user.username, user.last_privilege_review_days])
}

deny_shared_admin_account contains msg if {
	some user in input.normalized_data.users
	user.admin_access
	user.shared_account
	msg := sprintf("AC.L2-3.1.5: Shared admin account '%s' detected — privileged accounts must be individually assigned", [user.username])
}

deny_root_direct_usage contains msg if {
	input.normalized_data.root_account.last_login_days < 7
	msg := "AC.L2-3.1.5: Root account was used directly within the last 7 days — use individual privileged accounts instead"
}

default compliant := false

compliant if {
	count(deny_excessive_admin) == 0
	count(deny_no_privilege_review) == 0
	count(deny_shared_admin_account) == 0
	count(deny_root_direct_usage) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_excessive_admin],
		[f | some f in deny_no_privilege_review],
	),
	array.concat(
		[f | some f in deny_shared_admin_account],
		[f | some f in deny_root_direct_usage],
	),
)

result := {
	"control_id": "AC.L2-3.1.5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
