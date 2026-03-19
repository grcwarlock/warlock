package iso_27001.a5.a5_21

import rego.v1

# A.5.21: Managing Information Security in the ICT Supply Chain
# Validates ICT supply chain security controls

deny_no_ecr_scanning contains msg if {
	some repo in input.normalized_data.ecr.repositories
	not repo.scan_on_push
	msg := sprintf("A.5.21: ECR repository '%s' does not have scan-on-push enabled", [repo.name])
}

deny_no_inspector_ecr contains msg if {
	not input.normalized_data.inspector.ecr_scanning_enabled
	msg := "A.5.21: Inspector ECR scanning is not active for container supply chain security"
}

deny_critical_ecr_findings contains msg if {
	some repo in input.normalized_data.ecr.repositories
	repo.critical_findings > 0
	msg := sprintf("A.5.21: ECR repository '%s' has %d critical vulnerability findings", [repo.name, repo.critical_findings])
}

deny_no_codeartifact contains msg if {
	not input.normalized_data.codeartifact.repositories_exist
	msg := "A.5.21: No CodeArtifact repositories for managed dependency supply chain"
}

default compliant := false

compliant if {
	count(deny_no_ecr_scanning) == 0
	count(deny_no_inspector_ecr) == 0
	count(deny_critical_ecr_findings) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ecr_scanning],
		[f | some f in deny_no_inspector_ecr],
	),
	array.concat(
		[f | some f in deny_critical_ecr_findings],
		[f | some f in deny_no_codeartifact],
	),
)

result := {
	"control_id": "A.5.21",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
