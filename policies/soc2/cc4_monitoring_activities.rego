package soc2.cc4

import rego.v1

# SOC 2 CC4: Monitoring Activities (COSO Principles 16-17)
# Ongoing monitoring, deficiency evaluation

deny_no_monitoring_program contains msg if {
	not input.normalized_data.governance.continuous_monitoring_enabled
	msg := "CC4.1: No continuous monitoring program — ongoing evaluations of internal controls not established"
}

deny_no_monitoring_dashboards contains msg if {
	input.normalized_data.governance.continuous_monitoring_enabled
	not input.normalized_data.governance.monitoring_dashboards_configured
	msg := "CC4.1: Continuous monitoring enabled but no dashboards configured for control visibility"
}

deny_no_independent_evaluations contains msg if {
	not input.normalized_data.governance.independent_evaluations_performed
	msg := "CC4.1: No independent evaluations performed — internal audit or third-party assessments not conducted"
}

deny_no_deficiency_tracking contains msg if {
	not input.normalized_data.governance.deficiency_tracking_enabled
	msg := "CC4.2: No deficiency tracking system — control gaps not systematically recorded and managed"
}

deny_unresolved_deficiencies contains msg if {
	some deficiency in input.normalized_data.governance.deficiencies
	deficiency.age_days > 90
	deficiency.status == "open"
	msg := sprintf("CC4.2: Control deficiency '%s' open for %d days — exceeds 90-day remediation threshold", [deficiency.name, deficiency.age_days])
}

deny_no_deficiency_reporting contains msg if {
	not input.normalized_data.governance.deficiency_reporting_to_management
	msg := "CC4.2: Control deficiencies not reported to management and board — escalation process not defined"
}

default compliant := false

compliant if {
	count(deny_no_monitoring_program) == 0
	count(deny_no_monitoring_dashboards) == 0
	count(deny_no_independent_evaluations) == 0
	count(deny_no_deficiency_tracking) == 0
	count(deny_unresolved_deficiencies) == 0
	count(deny_no_deficiency_reporting) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_monitoring_program],
			[f | some f in deny_no_monitoring_dashboards],
		),
		array.concat(
			[f | some f in deny_no_independent_evaluations],
			[f | some f in deny_no_deficiency_tracking],
		),
	),
	array.concat(
		[f | some f in deny_unresolved_deficiencies],
		[f | some f in deny_no_deficiency_reporting],
	),
)

result := {
	"control_id": "CC4",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
