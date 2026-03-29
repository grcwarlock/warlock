package warlock.fedramp.ac

import rego.v1

# FedRAMP Access Control Requirements
# Enhanced access control requirements for federal authorization boundary

# AC-2(1): Automated system account management
deny_no_automated_account_mgmt contains msg if {
	some user in input.normalized_data.users
	not user.provisioning_approved
	user.is_active
	msg := sprintf("AC-2(1): User '%s' active without automated provisioning approval", [user.username])
}

# AC-2(3): Disable inactive accounts after 90 days
deny_inactive_not_disabled contains msg if {
	some user in input.normalized_data.users
	user.is_active
	user.days_since_last_login > 90
	msg := sprintf("AC-2(3): User '%s' inactive for %d days — exceeds FedRAMP 90-day limit", [user.username, user.days_since_last_login])
}

# AC-6: Least privilege
deny_excessive_privilege contains msg if {
	some user in input.normalized_data.users
	some policy in user.policies
	policy.effect == "Allow"
	policy.action == "*"
	policy.resource == "*"
	msg := sprintf("AC-6: User '%s' has wildcard admin access via '%s'", [user.username, policy.name])
}

# AC-17: Remote access — must use encrypted channel
deny_unencrypted_remote_access contains msg if {
	some connection in input.normalized_data.remote_access.connections
	not connection.encrypted
	msg := sprintf("AC-17: Remote access connection '%s' is not encrypted", [connection.id])
}

# AC-22: Publicly accessible content — must be authorized
deny_unauthorized_public_content contains msg if {
	some resource in input.normalized_data.public_resources
	not resource.authorized
	msg := sprintf("AC-22: Public resource '%s' not authorized for public release", [resource.id])
}

default compliant := false

compliant if {
	count(deny_no_automated_account_mgmt) == 0
	count(deny_inactive_not_disabled) == 0
	count(deny_excessive_privilege) == 0
	count(deny_unencrypted_remote_access) == 0
	count(deny_unauthorized_public_content) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_automated_account_mgmt],
		[f | some f in deny_inactive_not_disabled],
	),
	array.concat(
		array.concat(
			[f | some f in deny_excessive_privilege],
			[f | some f in deny_unencrypted_remote_access],
		),
		[f | some f in deny_unauthorized_public_content],
	),
)

result := {
	"control_id": "AC",
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
