package iso_27001.a8.a8_25

import rego.v1

# A.8.25: Secure Development Life Cycle
# Validates secure SDLC practices are implemented in CI/CD pipelines

deny_no_pipelines contains msg if {
	count(input.normalized_data.pipelines) == 0
	msg := "A.8.25: No CI/CD pipelines found for secure development lifecycle"
}

deny_pipeline_no_security_stage contains msg if {
	some pipeline in input.normalized_data.pipelines
	not pipeline.has_security_stage
	msg := sprintf("A.8.25: Pipeline '%s' has no security scanning stage", [pipeline.name])
}

deny_no_ecr_scanning contains msg if {
	not input.normalized_data.inspector.ecr_scanning_enabled
	msg := "A.8.25: Inspector ECR scanning is not enabled for container security in SDLC"
}

deny_no_codeguru contains msg if {
	not input.normalized_data.codeguru.reviewer_associated
	msg := "A.8.25: CodeGuru Reviewer is not associated with any repository"
}

default compliant := false

compliant if {
	count(deny_no_pipelines) == 0
	count(deny_pipeline_no_security_stage) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_pipelines],
		[f | some f in deny_pipeline_no_security_stage],
	),
	array.concat(
		[f | some f in deny_no_ecr_scanning],
		[f | some f in deny_no_codeguru],
	),
)

result := {
	"control_id": "A.8.25",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
