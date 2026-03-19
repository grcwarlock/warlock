package iso_27001.a8.a8_29

import rego.v1

# A.8.29: Security Testing in Development and Acceptance
# Validates security testing is integrated into development lifecycle

deny_no_inspector contains msg if {
	not input.normalized_data.inspector.enabled
	msg := "A.8.29: Inspector is not enabled for continuous security testing"
}

deny_no_test_reports contains msg if {
	count(input.normalized_data.codebuild.report_groups) == 0
	msg := "A.8.29: No CodeBuild test report groups — security test results not tracked"
}

deny_pipeline_no_test_stage contains msg if {
	some pipeline in input.normalized_data.pipelines
	not pipeline.has_test_stage
	msg := sprintf("A.8.29: Pipeline '%s' has no test/acceptance stage", [pipeline.name])
}

deny_inspector_not_scanning contains msg if {
	input.normalized_data.inspector.enabled
	not input.normalized_data.inspector.ec2_scanning_enabled
	not input.normalized_data.inspector.ecr_scanning_enabled
	msg := "A.8.29: Inspector is enabled but no resource types are being scanned"
}

default compliant := false

compliant if {
	count(deny_no_inspector) == 0
	count(deny_no_test_reports) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_inspector],
		[f | some f in deny_no_test_reports],
	),
	array.concat(
		[f | some f in deny_pipeline_no_test_stage],
		[f | some f in deny_inspector_not_scanning],
	),
)

result := {
	"control_id": "A.8.29",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
