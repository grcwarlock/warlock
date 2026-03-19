package nist.sa.sa_15

import rego.v1

# SA-15: Development Process, Standards, and Tools

deny_no_development_process contains msg if {
	not input.normalized_data.development_process
	msg := "SA-15: No development process, standards, and tools requirements established"
}

deny_no_coding_standards contains msg if {
	dp := input.normalized_data.development_process
	not dp.coding_standards_defined
	msg := "SA-15: No secure coding standards defined"
}

deny_no_approved_tools contains msg if {
	dp := input.normalized_data.development_process
	not dp.approved_tools_list
	msg := "SA-15: No approved development tools list maintained"
}

deny_process_not_reviewed contains msg if {
	dp := input.normalized_data.development_process
	dp.last_review_days > 365
	msg := sprintf("SA-15: Development process and standards have not been reviewed in %d days", [dp.last_review_days])
}

deny_no_quality_metrics contains msg if {
	dp := input.normalized_data.development_process
	not dp.quality_metrics_defined
	msg := "SA-15: No quality metrics defined for the development process"
}

default compliant := false

compliant if {
	count(deny_no_development_process) == 0
	count(deny_no_coding_standards) == 0
	count(deny_no_approved_tools) == 0
	count(deny_process_not_reviewed) == 0
	count(deny_no_quality_metrics) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_development_process],
		[f | some f in deny_no_coding_standards],
	),
	array.concat(
		[f | some f in deny_no_approved_tools],
		array.concat(
			[f | some f in deny_process_not_reviewed],
			[f | some f in deny_no_quality_metrics],
		),
	),
)

result := {
	"control_id": "SA-15",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
