package soc2.pi1

import rego.v1

# SOC 2 PI1: Processing Integrity
# Processing accuracy, completeness, timeliness, authorization

deny_no_input_validation contains msg if {
	not input.normalized_data.processing_integrity.input_validation_enabled
	msg := "PI1.1: No input validation controls — data accuracy at point of entry not enforced"
}

deny_no_processing_monitoring contains msg if {
	not input.normalized_data.processing_integrity.processing_monitoring_enabled
	msg := "PI1.2: No processing monitoring — completeness and accuracy of system processing not verified"
}

deny_no_data_quality_checks contains msg if {
	not input.normalized_data.processing_integrity.data_quality_checks_configured
	msg := "PI1.3: No data quality checks — output accuracy and completeness not validated"
}

deny_no_error_handling contains msg if {
	not input.normalized_data.processing_integrity.error_handling_procedures_exist
	msg := "PI1.4: No error handling procedures — processing errors not detected, reported, and corrected in a timely manner"
}

deny_no_audit_trails contains msg if {
	not input.normalized_data.processing_integrity.audit_trail_enabled
	msg := "PI1.5: No audit trails for data processing — system inputs, processing, and outputs not traceable"
}

deny_no_reconciliation contains msg if {
	not input.normalized_data.processing_integrity.reconciliation_procedures_exist
	msg := "PI1.3: No reconciliation procedures — data consistency across systems not verified"
}

deny_no_processing_authorization contains msg if {
	not input.normalized_data.processing_integrity.processing_authorization_required
	msg := "PI1.2: No processing authorization controls — system transactions can be initiated without proper authorization"
}

deny_no_timeliness_monitoring contains msg if {
	not input.normalized_data.processing_integrity.timeliness_sla_defined
	msg := "PI1.4: No timeliness SLA defined — processing completion deadlines not established or monitored"
}

default compliant := false

compliant if {
	count(deny_no_input_validation) == 0
	count(deny_no_processing_monitoring) == 0
	count(deny_no_data_quality_checks) == 0
	count(deny_no_error_handling) == 0
	count(deny_no_audit_trails) == 0
	count(deny_no_reconciliation) == 0
	count(deny_no_processing_authorization) == 0
	count(deny_no_timeliness_monitoring) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_input_validation],
			[f | some f in deny_no_processing_monitoring],
		),
		array.concat(
			[f | some f in deny_no_data_quality_checks],
			[f | some f in deny_no_error_handling],
		),
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_audit_trails],
			[f | some f in deny_no_reconciliation],
		),
		array.concat(
			[f | some f in deny_no_processing_authorization],
			[f | some f in deny_no_timeliness_monitoring],
		),
	),
)

result := {
	"control_id": "PI1",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
