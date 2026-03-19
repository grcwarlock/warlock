package cmmc.cm.cm_l2_3_4_2

import rego.v1

# CM.L2-3.4.2: Security Configuration Enforcement
# Establish and enforce security configuration settings for IT products deployed in organizational systems

deny_no_hardening contains msg if {
	some system in input.normalized_data.systems
	not system.security_hardening_applied
	msg := sprintf("CM.L2-3.4.2: System '%s' does not have security hardening applied per approved configuration", [system.name])
}

deny_default_credentials contains msg if {
	some system in input.normalized_data.systems
	system.default_credentials_present
	msg := sprintf("CM.L2-3.4.2: System '%s' still has default or vendor-supplied credentials in use", [system.name])
}

deny_unapproved_changes contains msg if {
	some change in input.normalized_data.configuration_changes
	not change.approved
	msg := sprintf("CM.L2-3.4.2: Configuration change '%s' on system '%s' was not approved through change control", [change.description, change.system_name])
}

default compliant := false

compliant if {
	count(deny_no_hardening) == 0
	count(deny_default_credentials) == 0
	count(deny_unapproved_changes) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_hardening],
		[f | some f in deny_default_credentials],
	),
	[f | some f in deny_unapproved_changes],
)

result := {
	"control_id": "CM.L2-3.4.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
