package hipaa.s164_310.s164_310_c

import rego.v1

# 164.310(c): Workstation Use
# Requires policies and procedures specifying the proper functions,
# manner of use, and physical attributes of workstations accessing ePHI

deny_no_workstation_use_policy contains msg if {
	not input.normalized_data.policies.workstation_use_policy
	msg := "164.310(c): No workstation use policy — must specify proper functions and manner of use for workstations accessing ePHI"
}

deny_no_acceptable_use_agreement contains msg if {
	some user in input.normalized_data.users
	user.account_enabled
	user.ephi_access
	not user.acceptable_use_signed
	msg := sprintf("164.310(c): User '%s' with ePHI access has not signed acceptable use agreement", [user.username])
}

deny_no_remote_access_policy contains msg if {
	input.normalized_data.config.remote_access_enabled
	not input.normalized_data.policies.remote_workstation_policy
	msg := "164.310(c): Remote access is enabled but no remote workstation use policy exists"
}

default compliant := false

compliant if {
	count(deny_no_workstation_use_policy) == 0
	count(deny_no_acceptable_use_agreement) == 0
	count(deny_no_remote_access_policy) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_workstation_use_policy],
		[f | some f in deny_no_acceptable_use_agreement],
	),
	[f | some f in deny_no_remote_access_policy],
)

result := {
	"control_id": "164.310(c)",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
