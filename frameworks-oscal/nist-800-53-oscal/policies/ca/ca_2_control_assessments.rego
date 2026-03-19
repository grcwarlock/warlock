package nist.ca.ca_2

import rego.v1

# CA-2: Control Assessments
# Validates that security control assessments are conducted regularly

deny_no_assessment_plan contains msg if {
	not input.normalized_data.control_assessments
	msg := "CA-2: No security control assessment program configured"
}

deny_assessment_overdue contains msg if {
	input.normalized_data.control_assessments
	input.normalized_data.control_assessments.last_assessment_days > 365
	msg := sprintf("CA-2: Control assessment is overdue (%d days since last assessment, exceeds annual requirement)", [input.normalized_data.control_assessments.last_assessment_days])
}

deny_no_assessment_plan_doc contains msg if {
	input.normalized_data.control_assessments
	not input.normalized_data.control_assessments.assessment_plan_exists
	msg := "CA-2: Security assessment plan document does not exist"
}

deny_no_assessor_defined contains msg if {
	input.normalized_data.control_assessments
	not input.normalized_data.control_assessments.assessor_assigned
	msg := "CA-2: No independent assessor assigned for control assessments"
}

deny_no_assessment_report contains msg if {
	input.normalized_data.control_assessments
	not input.normalized_data.control_assessments.report_generated
	msg := "CA-2: No assessment report generated from most recent assessment"
}

deny_findings_not_remediated contains msg if {
	input.normalized_data.control_assessments
	input.normalized_data.control_assessments.open_findings > 0
	input.normalized_data.control_assessments.findings_remediation_overdue
	msg := sprintf("CA-2: %d assessment findings have overdue remediation actions", [input.normalized_data.control_assessments.open_findings])
}

default compliant := false

compliant if {
	count(deny_no_assessment_plan) == 0
	count(deny_assessment_overdue) == 0
	count(deny_no_assessment_plan_doc) == 0
	count(deny_no_assessor_defined) == 0
	count(deny_no_assessment_report) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_assessment_plan],
		[f | some f in deny_assessment_overdue],
	),
	array.concat(
		[f | some f in deny_no_assessment_plan_doc],
		array.concat(
			[f | some f in deny_no_assessor_defined],
			array.concat(
				[f | some f in deny_no_assessment_report],
				[f | some f in deny_findings_not_remediated],
			),
		),
	),
)

result := {
	"control_id": "CA-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
