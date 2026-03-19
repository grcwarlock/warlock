package nist.cp.cp_10

import rego.v1

# CP-10: System Recovery and Reconstitution
# Validates recovery procedures are documented and system can be restored

deny_no_recovery_procedures contains msg if {
	not input.normalized_data.recovery_procedures
	msg := "CP-10: No system recovery and reconstitution procedures documented"
}

deny_no_recovery_runbooks contains msg if {
	input.normalized_data.recovery_procedures
	not input.normalized_data.recovery_procedures.runbooks_exist
	msg := "CP-10: Recovery runbooks do not exist for critical system components"
}

deny_recovery_not_tested contains msg if {
	input.normalized_data.recovery_procedures
	input.normalized_data.recovery_procedures.last_recovery_test_days > 365
	msg := sprintf("CP-10: System recovery has not been tested in %d days (exceeds annual requirement)", [input.normalized_data.recovery_procedures.last_recovery_test_days])
}

deny_no_known_state_baseline contains msg if {
	input.normalized_data.recovery_procedures
	not input.normalized_data.recovery_procedures.known_state_baseline
	msg := "CP-10: No known-state baseline defined for system reconstitution"
}

deny_no_transaction_recovery contains msg if {
	input.normalized_data.recovery_procedures
	input.normalized_data.recovery_procedures.transaction_based_system
	not input.normalized_data.recovery_procedures.transaction_recovery_enabled
	msg := "CP-10: Transaction-based system does not have transaction recovery capability"
}

deny_no_recovery_automation contains msg if {
	input.provider == "aws"
	input.normalized_data.recovery_procedures
	not input.normalized_data.recovery_procedures.infrastructure_as_code
	msg := "CP-10: Infrastructure as Code is not used for automated system reconstitution"
}

default compliant := false

compliant if {
	count(deny_no_recovery_procedures) == 0
	count(deny_no_recovery_runbooks) == 0
	count(deny_recovery_not_tested) == 0
	count(deny_no_known_state_baseline) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_recovery_procedures],
		[f | some f in deny_no_recovery_runbooks],
	),
	array.concat(
		[f | some f in deny_recovery_not_tested],
		array.concat(
			[f | some f in deny_no_known_state_baseline],
			array.concat(
				[f | some f in deny_no_transaction_recovery],
				[f | some f in deny_no_recovery_automation],
			),
		),
	),
)

result := {
	"control_id": "CP-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
