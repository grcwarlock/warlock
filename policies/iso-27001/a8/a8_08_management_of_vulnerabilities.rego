package iso_27001.a8.a8_08

import rego.v1

# A.8.8: Management of Technical Vulnerabilities
# Validates vulnerability scanning and remediation processes

deny_no_inspector contains msg if {
	not input.normalized_data.inspector.enabled
	msg := "A.8.8: Inspector is not enabled for vulnerability scanning"
}

deny_inspector_not_all_types contains msg if {
	input.normalized_data.inspector.enabled
	not input.normalized_data.inspector.ec2_scanning_enabled
	msg := "A.8.8: Inspector EC2 scanning is not enabled"
}

deny_critical_findings contains msg if {
	input.normalized_data.inspector.enabled
	input.normalized_data.inspector.critical_finding_count > 0
	msg := sprintf("A.8.8: %d critical Inspector findings require immediate remediation", [input.normalized_data.inspector.critical_finding_count])
}

deny_no_patch_baseline contains msg if {
	not input.normalized_data.ssm.patch_baseline_configured
	msg := "A.8.8: No SSM patch baseline configured for vulnerability remediation"
}

deny_instances_not_compliant contains msg if {
	some instance in input.normalized_data.ssm.managed_instances
	not instance.patch_compliant
	msg := sprintf("A.8.8: Instance '%s' is not patch compliant — vulnerabilities unpatched", [instance.id])
}

default compliant := false

compliant if {
	count(deny_no_inspector) == 0
	count(deny_critical_findings) == 0
	count(deny_no_patch_baseline) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_inspector],
		[f | some f in deny_inspector_not_all_types],
	),
	array.concat(
		[f | some f in deny_critical_findings],
		array.concat(
			[f | some f in deny_no_patch_baseline],
			[f | some f in deny_instances_not_compliant],
		),
	),
)

result := {
	"control_id": "A.8.8",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
