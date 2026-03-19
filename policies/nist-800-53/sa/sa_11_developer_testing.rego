package nist.sa.sa_11

import rego.v1

# SA-11: Developer Testing and Evaluation

deny_no_sast contains msg if {
	not input.normalized_data.sast_configured
	msg := "SA-11: No Static Application Security Testing (SAST) configured"
}

deny_no_dast contains msg if {
	not input.normalized_data.dast_configured
	msg := "SA-11: No Dynamic Application Security Testing (DAST) configured"
}

deny_no_cicd_security_gates contains msg if {
	not input.normalized_data.cicd_security_gates
	msg := "SA-11: No security gates configured in CI/CD pipeline"
}

deny_sast_not_in_pipeline contains msg if {
	input.normalized_data.sast_configured
	not input.normalized_data.sast_in_pipeline
	msg := "SA-11: SAST is configured but not integrated into CI/CD pipeline"
}

deny_security_gate_bypass contains msg if {
	gates := input.normalized_data.cicd_security_gates
	gates.bypass_allowed
	msg := "SA-11: CI/CD security gates can be bypassed without approval"
}

deny_no_dependency_scanning contains msg if {
	not input.normalized_data.dependency_scanning_configured
	msg := "SA-11: No software composition analysis (SCA) or dependency scanning configured"
}

deny_no_test_plan contains msg if {
	not input.normalized_data.security_test_plan
	msg := "SA-11: No security test and evaluation plan documented"
}

deny_critical_findings_in_pipeline contains msg if {
	some finding in input.normalized_data.pipeline_security_findings
	finding.severity == "critical"
	finding.status == "open"
	msg := sprintf("SA-11: Critical security finding '%s' detected in CI/CD pipeline for '%s'", [finding.id, finding.repository])
}

default compliant := false

compliant if {
	count(deny_no_sast) == 0
	count(deny_no_dast) == 0
	count(deny_no_cicd_security_gates) == 0
	count(deny_sast_not_in_pipeline) == 0
	count(deny_security_gate_bypass) == 0
	count(deny_no_dependency_scanning) == 0
	count(deny_no_test_plan) == 0
	count(deny_critical_findings_in_pipeline) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_sast],
			[f | some f in deny_no_dast],
		),
		array.concat(
			[f | some f in deny_no_cicd_security_gates],
			[f | some f in deny_sast_not_in_pipeline],
		),
	),
	array.concat(
		array.concat(
			[f | some f in deny_security_gate_bypass],
			[f | some f in deny_no_dependency_scanning],
		),
		array.concat(
			[f | some f in deny_no_test_plan],
			[f | some f in deny_critical_findings_in_pipeline],
		),
	),
)

result := {
	"control_id": "SA-11",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
