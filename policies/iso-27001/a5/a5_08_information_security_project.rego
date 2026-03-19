package iso_27001.a5.a5_08

import rego.v1

# A.5.8: Information Security in Project Management
# Validates security gates exist in project lifecycle

deny_no_security_pipeline_stages contains msg if {
	some pipeline in input.normalized_data.pipelines
	not has_security_stage(pipeline)
	msg := sprintf("A.5.8: Pipeline '%s' has no security scanning stage", [pipeline.name])
}

deny_no_inspector_ecr contains msg if {
	not input.normalized_data.inspector.ecr_scanning_enabled
	msg := "A.5.8: Inspector ECR container scanning is not enabled for project artifacts"
}

deny_no_codebuild_security contains msg if {
	count(input.normalized_data.pipelines) > 0
	not input.normalized_data.codebuild.security_scan_projects_exist
	msg := "A.5.8: No CodeBuild projects configured for security scanning in project pipelines"
}

deny_no_pipelines contains msg if {
	count(input.normalized_data.pipelines) == 0
	msg := "A.5.8: No CI/CD pipelines found — security cannot be integrated into project management"
}

has_security_stage(pipeline) if {
	some stage in pipeline.stages
	contains(lower(stage.name), "security")
}

has_security_stage(pipeline) if {
	some stage in pipeline.stages
	contains(lower(stage.name), "scan")
}

default compliant := false

compliant if {
	count(deny_no_security_pipeline_stages) == 0
	count(deny_no_inspector_ecr) == 0
	count(deny_no_pipelines) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_pipeline_stages],
		[f | some f in deny_no_inspector_ecr],
	),
	array.concat(
		[f | some f in deny_no_codebuild_security],
		[f | some f in deny_no_pipelines],
	),
)

result := {
	"control_id": "A.5.8",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
