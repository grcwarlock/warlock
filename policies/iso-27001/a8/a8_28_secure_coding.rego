package iso_27001.a8.a8_28

import rego.v1

# A.8.28: Secure Coding
# Validates secure coding practices and automated code analysis

deny_no_codeguru contains msg if {
	not input.normalized_data.codeguru.reviewer_associated
	msg := "A.8.28: CodeGuru Reviewer is not associated with any repository for code analysis"
}

deny_critical_code_findings contains msg if {
	input.normalized_data.codeguru.reviewer_associated
	input.normalized_data.codeguru.critical_recommendation_count > 0
	msg := sprintf("A.8.28: %d critical CodeGuru Reviewer recommendations need attention", [input.normalized_data.codeguru.critical_recommendation_count])
}

deny_ecr_critical_findings contains msg if {
	some repo in input.normalized_data.ecr.repositories
	repo.critical_findings > 0
	msg := sprintf("A.8.28: ECR repository '%s' has %d critical image scan findings", [repo.name, repo.critical_findings])
}

deny_no_security_scan_project contains msg if {
	not input.normalized_data.codebuild.security_scan_projects_exist
	msg := "A.8.28: No CodeBuild projects configured for security scanning"
}

default compliant := false

compliant if {
	count(deny_no_codeguru) == 0
	count(deny_critical_code_findings) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_codeguru],
		[f | some f in deny_critical_code_findings],
	),
	array.concat(
		[f | some f in deny_ecr_critical_findings],
		[f | some f in deny_no_security_scan_project],
	),
)

result := {
	"control_id": "A.8.28",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
