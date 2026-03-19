package nist.sa.sa_8

import rego.v1

# SA-8: Security and Privacy Engineering Principles

deny_no_engineering_principles contains msg if {
	not input.normalized_data.security_engineering
	msg := "SA-8: No security and privacy engineering principles applied to system design"
}

deny_no_defense_in_depth contains msg if {
	eng := input.normalized_data.security_engineering
	not eng.defense_in_depth
	msg := "SA-8: Defense-in-depth principle not applied in system design"
}

deny_no_least_privilege_design contains msg if {
	eng := input.normalized_data.security_engineering
	not eng.least_privilege_design
	msg := "SA-8: Least privilege principle not applied in system design"
}

deny_no_secure_defaults contains msg if {
	eng := input.normalized_data.security_engineering
	not eng.secure_defaults
	msg := "SA-8: Secure-by-default principle not applied in system design"
}

deny_no_fail_secure contains msg if {
	eng := input.normalized_data.security_engineering
	not eng.fail_secure
	msg := "SA-8: Fail-secure principle not applied in system design"
}

deny_principles_not_documented contains msg if {
	eng := input.normalized_data.security_engineering
	not eng.principles_documented
	msg := "SA-8: Applied security engineering principles are not documented"
}

default compliant := false

compliant if {
	count(deny_no_engineering_principles) == 0
	count(deny_no_defense_in_depth) == 0
	count(deny_no_least_privilege_design) == 0
	count(deny_no_secure_defaults) == 0
	count(deny_no_fail_secure) == 0
	count(deny_principles_not_documented) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_engineering_principles],
		[f | some f in deny_no_defense_in_depth],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_least_privilege_design],
			[f | some f in deny_no_secure_defaults],
		),
		array.concat(
			[f | some f in deny_no_fail_secure],
			[f | some f in deny_principles_not_documented],
		),
	),
)

result := {
	"control_id": "SA-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
