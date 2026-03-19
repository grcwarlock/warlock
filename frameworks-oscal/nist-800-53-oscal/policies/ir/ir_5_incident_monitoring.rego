package nist.ir.ir_5

import rego.v1

# IR-5: Incident Monitoring
# Validates incident tracking and documentation on an ongoing basis

deny_no_incident_tracking contains msg if {
	not input.normalized_data.incident_monitoring
	msg := "IR-5: No incident tracking and monitoring system configured"
}

deny_no_ticketing_system contains msg if {
	input.normalized_data.incident_monitoring
	not input.normalized_data.incident_monitoring.ticketing_system_configured
	msg := "IR-5: No incident ticketing system configured for tracking incidents"
}

deny_no_severity_classification contains msg if {
	input.normalized_data.incident_monitoring
	not input.normalized_data.incident_monitoring.severity_classification_defined
	msg := "IR-5: Incident severity classification scheme is not defined"
}

deny_open_incidents_not_tracked contains msg if {
	input.normalized_data.incident_monitoring
	input.normalized_data.incident_monitoring.untracked_incidents > 0
	msg := sprintf("IR-5: %d incidents are not being tracked in the monitoring system", [input.normalized_data.incident_monitoring.untracked_incidents])
}

deny_no_trend_analysis contains msg if {
	input.normalized_data.incident_monitoring
	not input.normalized_data.incident_monitoring.trend_analysis_enabled
	msg := "IR-5: Incident trend analysis is not configured"
}

deny_no_automated_alerting contains msg if {
	input.normalized_data.incident_monitoring
	not input.normalized_data.incident_monitoring.automated_alerting
	msg := "IR-5: Automated alerting for security incidents is not configured"
}

default compliant := false

compliant if {
	count(deny_no_incident_tracking) == 0
	count(deny_no_ticketing_system) == 0
	count(deny_no_severity_classification) == 0
	count(deny_open_incidents_not_tracked) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_tracking],
		[f | some f in deny_no_ticketing_system],
	),
	array.concat(
		[f | some f in deny_no_severity_classification],
		array.concat(
			[f | some f in deny_open_incidents_not_tracked],
			array.concat(
				[f | some f in deny_no_trend_analysis],
				[f | some f in deny_no_automated_alerting],
			),
		),
	),
)

result := {
	"control_id": "IR-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
