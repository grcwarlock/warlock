package warlock.sec_cyber.risk_strategy

import rego.v1

# SEC Cyber — Risk Management and Strategy
# S-K Item 106(b): Annual 10-K cybersecurity risk disclosure

# 106(b)(1): Process for assessing, identifying, managing cyber risks
deny_no_risk_process contains msg if {
	not input.normalized_data.sec_cyber.risk_assessment_process_documented
	msg := "S-K 106(b)(1): No documented process for assessing and managing cybersecurity risks"
}

# 106(b)(2): Whether and how processes integrated into overall risk management
deny_no_risk_integration contains msg if {
	not input.normalized_data.sec_cyber.cyber_risk_integrated_with_erm
	msg := "S-K 106(b)(2): Cybersecurity risk not integrated with enterprise risk management"
}

# 106(b)(3): Whether engage assessors, consultants, auditors, or third parties
deny_no_external_assessment contains msg if {
	not input.normalized_data.sec_cyber.external_assessment_conducted
	msg := "S-K 106(b)(3): No external cybersecurity assessment conducted"
}

# 106(b)(4): Whether have processes to oversee and identify risks from third-party service providers
deny_no_vendor_risk_oversight contains msg if {
	not input.normalized_data.sec_cyber.vendor_risk_oversight
	msg := "S-K 106(b)(4): No third-party service provider cybersecurity risk oversight"
}

# 106(b)(5): Prior incidents materially affected or reasonably likely to affect
deny_no_prior_incident_analysis contains msg if {
	not input.normalized_data.sec_cyber.prior_incident_analysis
	msg := "S-K 106(b)(5): No analysis of whether prior incidents materially affected the registrant"
}

default compliant := false

compliant if {
	count(deny_no_risk_process) == 0
	count(deny_no_risk_integration) == 0
	count(deny_no_external_assessment) == 0
	count(deny_no_vendor_risk_oversight) == 0
	count(deny_no_prior_incident_analysis) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_process],
		[f | some f in deny_no_risk_integration],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_external_assessment],
			[f | some f in deny_no_vendor_risk_oversight],
		),
		[f | some f in deny_no_prior_incident_analysis],
	),
)

result := {
	"control_id": "S-K 106(b)",
	"framework": "SEC Cyber",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
