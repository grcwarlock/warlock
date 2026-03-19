package cmmc.ac.ac_l2_3_1_2

import rego.v1

# AC.L2-3.1.2: Transaction & Function Control
# Limit system access to the types of transactions and functions that authorized users are permitted to execute

deny_no_rbac contains msg if {
	some system in input.normalized_data.systems
	not system.rbac_enabled
	msg := sprintf("AC.L2-3.1.2: System '%s' does not enforce role-based access control", [system.name])
}

deny_overly_permissive_policy contains msg if {
	some policy in input.normalized_data.iam_policies
	policy.effect == "Allow"
	policy.action == "*"
	policy.resource == "*"
	msg := sprintf("AC.L2-3.1.2: IAM policy '%s' grants unrestricted access to all actions and resources", [policy.name])
}

deny_no_function_separation contains msg if {
	some user in input.normalized_data.users
	user.admin_access
	user.data_access
	not user.separation_of_duties
	msg := sprintf("AC.L2-3.1.2: User '%s' has both admin and data access without separation of duties controls", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_rbac) == 0
	count(deny_overly_permissive_policy) == 0
	count(deny_no_function_separation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_rbac],
		[f | some f in deny_overly_permissive_policy],
	),
	[f | some f in deny_no_function_separation],
)

result := {
	"control_id": "AC.L2-3.1.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
