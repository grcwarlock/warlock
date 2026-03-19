package nist.sa.sa_17

import rego.v1

# SA-17: Developer Security and Privacy Architecture and Design

deny_no_security_architecture contains msg if {
	not input.normalized_data.developer_security_architecture
	msg := "SA-17: No developer security architecture and design specification produced"
}

deny_architecture_not_consistent contains msg if {
	dsa := input.normalized_data.developer_security_architecture
	not dsa.consistent_with_enterprise_architecture
	msg := "SA-17: Developer security architecture is not consistent with organization's enterprise architecture"
}

deny_no_threat_model contains msg if {
	dsa := input.normalized_data.developer_security_architecture
	not dsa.threat_model_completed
	msg := "SA-17: No threat model completed for the system design"
}

deny_architecture_not_reviewed contains msg if {
	dsa := input.normalized_data.developer_security_architecture
	dsa.last_review_days > 365
	msg := sprintf("SA-17: Developer security architecture has not been reviewed in %d days", [dsa.last_review_days])
}

deny_no_security_mechanisms contains msg if {
	dsa := input.normalized_data.developer_security_architecture
	not dsa.security_mechanisms_documented
	msg := "SA-17: Security mechanisms are not documented in the architecture design"
}

default compliant := false

compliant if {
	count(deny_no_security_architecture) == 0
	count(deny_architecture_not_consistent) == 0
	count(deny_no_threat_model) == 0
	count(deny_architecture_not_reviewed) == 0
	count(deny_no_security_mechanisms) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_architecture],
		[f | some f in deny_architecture_not_consistent],
	),
	array.concat(
		[f | some f in deny_no_threat_model],
		array.concat(
			[f | some f in deny_architecture_not_reviewed],
			[f | some f in deny_no_security_mechanisms],
		),
	),
)

result := {
	"control_id": "SA-17",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
