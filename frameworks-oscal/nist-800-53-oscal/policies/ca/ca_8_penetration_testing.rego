package nist.ca.ca_8

import rego.v1

# CA-8: Penetration Testing
# Validates regular penetration testing is conducted

deny_no_pentest_program contains msg if {
	not input.normalized_data.penetration_testing
	msg := "CA-8: No penetration testing program configured"
}

deny_pentest_overdue contains msg if {
	input.normalized_data.penetration_testing
	input.normalized_data.penetration_testing.last_test_days > 365
	msg := sprintf("CA-8: Penetration testing is overdue (%d days since last test, exceeds annual requirement)", [input.normalized_data.penetration_testing.last_test_days])
}

deny_no_pentest_report contains msg if {
	input.normalized_data.penetration_testing
	not input.normalized_data.penetration_testing.report_available
	msg := "CA-8: No penetration testing report available from most recent test"
}

deny_critical_findings_open contains msg if {
	input.normalized_data.penetration_testing
	input.normalized_data.penetration_testing.critical_findings_open > 0
	msg := sprintf("CA-8: %d critical penetration testing findings remain unresolved", [input.normalized_data.penetration_testing.critical_findings_open])
}

deny_no_scope_defined contains msg if {
	input.normalized_data.penetration_testing
	not input.normalized_data.penetration_testing.scope_defined
	msg := "CA-8: Penetration testing scope and rules of engagement are not defined"
}

deny_no_remediation_tracking contains msg if {
	input.normalized_data.penetration_testing
	input.normalized_data.penetration_testing.findings_total > 0
	not input.normalized_data.penetration_testing.remediation_tracked
	msg := "CA-8: Penetration testing findings are not tracked for remediation"
}

default compliant := false

compliant if {
	count(deny_no_pentest_program) == 0
	count(deny_pentest_overdue) == 0
	count(deny_no_pentest_report) == 0
	count(deny_critical_findings_open) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_pentest_program],
		[f | some f in deny_pentest_overdue],
	),
	array.concat(
		[f | some f in deny_no_pentest_report],
		array.concat(
			[f | some f in deny_critical_findings_open],
			array.concat(
				[f | some f in deny_no_scope_defined],
				[f | some f in deny_no_remediation_tracking],
			),
		),
	),
)

result := {
	"control_id": "CA-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
