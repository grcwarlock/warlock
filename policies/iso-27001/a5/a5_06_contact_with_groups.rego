package iso_27001.a5.a5_06

import rego.v1

# A.5.6: Contact with Special Interest Groups
# Validates memberships in security information sharing groups

deny_no_threat_intel_feeds contains msg if {
	not input.normalized_data.security_hub.threat_intel_feeds_enabled
	msg := "A.5.6: No threat intelligence feed integrations enabled in Security Hub"
}

deny_no_security_hub_integrations contains msg if {
	input.normalized_data.security_hub.enabled
	count(input.normalized_data.security_hub.enabled_products) == 0
	msg := "A.5.6: No Security Hub partner product integrations enabled"
}

deny_no_trusted_advisor contains msg if {
	not input.normalized_data.support.trusted_advisor_enabled
	msg := "A.5.6: AWS Trusted Advisor is not enabled for security best practice checks"
}

deny_no_security_bulletins contains msg if {
	not input.normalized_data.sns.security_bulletin_subscription
	msg := "A.5.6: Not subscribed to AWS security bulletins or advisories"
}

default compliant := false

compliant if {
	count(deny_no_threat_intel_feeds) == 0
	count(deny_no_security_hub_integrations) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_threat_intel_feeds],
		[f | some f in deny_no_security_hub_integrations],
	),
	array.concat(
		[f | some f in deny_no_trusted_advisor],
		[f | some f in deny_no_security_bulletins],
	),
)

result := {
	"control_id": "A.5.6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
