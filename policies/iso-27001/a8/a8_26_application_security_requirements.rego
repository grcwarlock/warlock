package iso_27001.a8.a8_26

import rego.v1

# A.8.26: Application Security Requirements
# Validates application security requirements are defined and enforced

deny_no_waf contains msg if {
	count(input.normalized_data.waf.web_acls) == 0
	msg := "A.8.26: No WAF web ACLs configured for application security"
}

deny_no_lambda_scanning contains msg if {
	not input.normalized_data.inspector.lambda_scanning_enabled
	msg := "A.8.26: Inspector Lambda scanning is not enabled for serverless application security"
}

deny_critical_app_findings contains msg if {
	input.normalized_data.inspector.enabled
	input.normalized_data.inspector.critical_app_finding_count > 0
	msg := sprintf("A.8.26: %d critical application security findings from Inspector", [input.normalized_data.inspector.critical_app_finding_count])
}

deny_no_security_requirements_doc contains msg if {
	not input.normalized_data.policies.application_security_requirements_documented
	msg := "A.8.26: No application security requirements document exists"
}

default compliant := false

compliant if {
	count(deny_no_waf) == 0
	count(deny_no_lambda_scanning) == 0
	count(deny_critical_app_findings) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_waf],
		[f | some f in deny_no_lambda_scanning],
	),
	array.concat(
		[f | some f in deny_critical_app_findings],
		[f | some f in deny_no_security_requirements_doc],
	),
)

result := {
	"control_id": "A.8.26",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
