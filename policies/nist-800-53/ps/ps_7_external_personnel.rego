package nist.ps.ps_7

import rego.v1

# PS-7: External Personnel Security

deny_no_external_policy contains msg if {
	not input.normalized_data.external_personnel_policy
	msg := "PS-7: No external personnel security policy established"
}

deny_contractor_no_agreement contains msg if {
	some person in input.normalized_data.external_personnel
	not person.security_agreement_signed
	msg := sprintf("PS-7: External personnel '%s' from '%s' has not signed security agreement", [person.name, person.organization])
}

deny_contractor_not_screened contains msg if {
	some person in input.normalized_data.external_personnel
	person.requires_screening
	not person.screening_completed
	msg := sprintf("PS-7: External personnel '%s' has not completed required screening", [person.name])
}

deny_contractor_access_not_monitored contains msg if {
	some person in input.normalized_data.external_personnel
	person.has_system_access
	not person.access_monitored
	msg := sprintf("PS-7: Access by external personnel '%s' is not being monitored", [person.name])
}

deny_no_compliance_monitoring contains msg if {
	policy := input.normalized_data.external_personnel_policy
	not policy.compliance_monitoring
	msg := "PS-7: No compliance monitoring established for external personnel security requirements"
}

deny_contracts_missing_security contains msg if {
	some contract in input.normalized_data.external_contracts
	not contract.security_requirements_included
	msg := sprintf("PS-7: Contract '%s' does not include personnel security requirements", [contract.id])
}

default compliant := false

compliant if {
	count(deny_no_external_policy) == 0
	count(deny_contractor_no_agreement) == 0
	count(deny_contractor_not_screened) == 0
	count(deny_contractor_access_not_monitored) == 0
	count(deny_no_compliance_monitoring) == 0
	count(deny_contracts_missing_security) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_external_policy],
		[f | some f in deny_contractor_no_agreement],
	),
	array.concat(
		array.concat(
			[f | some f in deny_contractor_not_screened],
			[f | some f in deny_contractor_access_not_monitored],
		),
		array.concat(
			[f | some f in deny_no_compliance_monitoring],
			[f | some f in deny_contracts_missing_security],
		),
	),
)

result := {
	"control_id": "PS-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
