package nist.pl.pl_8

import rego.v1

# PL-8: Security and Privacy Architecture

deny_no_security_architecture contains msg if {
	some system in input.normalized_data.planning.systems
	not system.security_architecture_documented
	msg := sprintf("PL-8: System '%s' does not have a documented security architecture", [system.system_id])
}

deny_architecture_not_current contains msg if {
	some system in input.normalized_data.planning.systems
	system.security_architecture_documented
	not system.architecture_reviewed_within_365_days
	msg := sprintf("PL-8: Security architecture for system '%s' has not been reviewed within the last 365 days", [system.system_id])
}

deny_no_threat_model contains msg if {
	some system in input.normalized_data.planning.systems
	not system.threat_model_documented
	msg := sprintf("PL-8: System '%s' does not have a documented threat model as part of its security architecture", [system.system_id])
}

deny_architecture_not_aligned contains msg if {
	some system in input.normalized_data.planning.systems
	system.security_architecture_documented
	not system.architecture_aligned_with_enterprise
	msg := sprintf("PL-8: Security architecture for system '%s' is not aligned with the enterprise architecture", [system.system_id])
}

default compliant := false

compliant if {
	count(deny_no_security_architecture) == 0
	count(deny_architecture_not_current) == 0
	count(deny_no_threat_model) == 0
	count(deny_architecture_not_aligned) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_architecture],
		[f | some f in deny_architecture_not_current],
	),
	array.concat(
		[f | some f in deny_no_threat_model],
		[f | some f in deny_architecture_not_aligned],
	),
)

result := {
	"control_id": "PL-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
