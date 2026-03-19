package hipaa.s164_310.s164_310_b

import rego.v1

# 164.310(b): Workstation Security
# Requires physical safeguards for all workstations that access ePHI
# to restrict access to authorized users

deny_no_workstation_security_policy contains msg if {
	not input.normalized_data.policies.workstation_security_policy
	msg := "164.310(b): No workstation security policy — must implement physical safeguards restricting access to workstations with ePHI"
}

deny_unencrypted_workstation contains msg if {
	some workstation in input.normalized_data.resources.workstations
	not workstation.disk_encryption_enabled
	msg := sprintf("164.310(b): Workstation '%s' does not have disk encryption enabled", [workstation.name])
}

deny_no_screen_lock contains msg if {
	some workstation in input.normalized_data.resources.workstations
	not workstation.screen_lock_enabled
	msg := sprintf("164.310(b): Workstation '%s' does not have automatic screen lock configured", [workstation.name])
}

default compliant := false

compliant if {
	count(deny_no_workstation_security_policy) == 0
	count(deny_unencrypted_workstation) == 0
	count(deny_no_screen_lock) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_workstation_security_policy],
		[f | some f in deny_unencrypted_workstation],
	),
	[f | some f in deny_no_screen_lock],
)

result := {
	"control_id": "164.310(b)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
