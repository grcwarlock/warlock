package nist.ir.ir_6

import rego.v1

# IR-6: Incident Reporting
# Validates incident reporting procedures and mechanisms

deny_no_reporting_procedures contains msg if {
	not input.normalized_data.incident_reporting
	msg := "IR-6: No incident reporting procedures configured"
}

deny_no_reporting_mechanism contains msg if {
	input.normalized_data.incident_reporting
	not input.normalized_data.incident_reporting.reporting_mechanism_exists
	msg := "IR-6: No mechanism exists for personnel to report suspected incidents"
}

deny_no_reporting_timeframe contains msg if {
	input.normalized_data.incident_reporting
	not input.normalized_data.incident_reporting.timeframe_defined
	msg := "IR-6: Incident reporting timeframes are not defined"
}

deny_no_external_reporting contains msg if {
	input.normalized_data.incident_reporting
	not input.normalized_data.incident_reporting.external_reporting_configured
	msg := "IR-6: External incident reporting to authorities (e.g., US-CERT) is not configured"
}

deny_no_escalation_procedures contains msg if {
	input.normalized_data.incident_reporting
	not input.normalized_data.incident_reporting.escalation_procedures_defined
	msg := "IR-6: Incident escalation procedures are not defined"
}

deny_no_automated_reporting contains msg if {
	input.normalized_data.incident_reporting
	not input.normalized_data.incident_reporting.automated_reporting_enabled
	msg := "IR-6: Automated incident reporting and notification is not configured"
}

deny_reporting_contacts_outdated contains msg if {
	input.normalized_data.incident_reporting
	input.normalized_data.incident_reporting.contact_list_last_updated_days > 90
	msg := sprintf("IR-6: Incident reporting contact list has not been updated in %d days", [input.normalized_data.incident_reporting.contact_list_last_updated_days])
}

default compliant := false

compliant if {
	count(deny_no_reporting_procedures) == 0
	count(deny_no_reporting_mechanism) == 0
	count(deny_no_reporting_timeframe) == 0
	count(deny_no_escalation_procedures) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_reporting_procedures],
		[f | some f in deny_no_reporting_mechanism],
	),
	array.concat(
		[f | some f in deny_no_reporting_timeframe],
		array.concat(
			[f | some f in deny_no_external_reporting],
			array.concat(
				[f | some f in deny_no_escalation_procedures],
				array.concat(
					[f | some f in deny_no_automated_reporting],
					[f | some f in deny_reporting_contacts_outdated],
				),
			),
		),
	),
)

result := {
	"control_id": "IR-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
