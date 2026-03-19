package nist.sa.sa_4

import rego.v1

# SA-4: Acquisition Process

deny_no_security_requirements contains msg if {
	not input.normalized_data.acquisition_security_requirements
	msg := "SA-4: No security and privacy functional requirements included in acquisitions"
}

deny_contract_missing_security contains msg if {
	some contract in input.normalized_data.acquisition_contracts
	not contract.security_requirements_included
	msg := sprintf("SA-4: Acquisition contract '%s' does not include security requirements", [contract.id])
}

deny_no_strength_requirements contains msg if {
	some contract in input.normalized_data.acquisition_contracts
	not contract.strength_of_mechanism_specified
	msg := sprintf("SA-4: Contract '%s' does not specify strength of security mechanism requirements", [contract.id])
}

deny_no_assurance_requirements contains msg if {
	some contract in input.normalized_data.acquisition_contracts
	not contract.assurance_requirements_specified
	msg := sprintf("SA-4: Contract '%s' does not specify security assurance requirements", [contract.id])
}

deny_no_documentation_requirements contains msg if {
	some contract in input.normalized_data.acquisition_contracts
	not contract.documentation_requirements_specified
	msg := sprintf("SA-4: Contract '%s' does not specify security documentation requirements", [contract.id])
}

default compliant := false

compliant if {
	count(deny_no_security_requirements) == 0
	count(deny_contract_missing_security) == 0
	count(deny_no_strength_requirements) == 0
	count(deny_no_assurance_requirements) == 0
	count(deny_no_documentation_requirements) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_requirements],
		[f | some f in deny_contract_missing_security],
	),
	array.concat(
		[f | some f in deny_no_strength_requirements],
		array.concat(
			[f | some f in deny_no_assurance_requirements],
			[f | some f in deny_no_documentation_requirements],
		),
	),
)

result := {
	"control_id": "SA-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
