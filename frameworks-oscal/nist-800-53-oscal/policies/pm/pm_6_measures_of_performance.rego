package nist.pm.pm_6

import rego.v1

# PM-6: Measures of Performance

deny_no_metrics_program contains msg if {
	not input.normalized_data.security_metrics
	msg := "PM-6: No information security measures of performance established"
}

deny_no_kpis_defined contains msg if {
	metrics := input.normalized_data.security_metrics
	count(metrics.key_performance_indicators) == 0
	msg := "PM-6: No key performance indicators (KPIs) defined for information security program"
}

deny_metrics_not_reported contains msg if {
	metrics := input.normalized_data.security_metrics
	not metrics.reported_to_leadership
	msg := "PM-6: Security performance metrics are not reported to senior leadership"
}

deny_metrics_outdated contains msg if {
	metrics := input.normalized_data.security_metrics
	metrics.last_report_days > 90
	msg := sprintf("PM-6: Security performance metrics have not been reported in %d days", [metrics.last_report_days])
}

deny_metrics_no_baseline contains msg if {
	metrics := input.normalized_data.security_metrics
	not metrics.baseline_established
	msg := "PM-6: No baseline established for security performance metrics"
}

default compliant := false

compliant if {
	count(deny_no_metrics_program) == 0
	count(deny_no_kpis_defined) == 0
	count(deny_metrics_not_reported) == 0
	count(deny_metrics_outdated) == 0
	count(deny_metrics_no_baseline) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_metrics_program],
		[f | some f in deny_no_kpis_defined],
	),
	array.concat(
		[f | some f in deny_metrics_not_reported],
		array.concat(
			[f | some f in deny_metrics_outdated],
			[f | some f in deny_metrics_no_baseline],
		),
	),
)

result := {
	"control_id": "PM-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
