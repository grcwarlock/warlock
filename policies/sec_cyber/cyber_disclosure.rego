package warlock.sec_cyber

import rego.v1

# SEC Cyber Disclosure Rules
# SEC cybersecurity risk management, strategy, governance, and incident disclosure

# Item 1.05: Material cybersecurity incident disclosure (Form 8-K)
deny_no_incident_disclosure_process contains msg if {
	not input.normalized_data.sec_cyber.incident_disclosure_process
	msg := "Item 1.05: No material cybersecurity incident disclosure process — 4-day 8-K filing at risk"
}

# S-K Item 106(b): Cybersecurity risk management and strategy
deny_no_risk_management_program contains msg if {
	not input.normalized_data.sec_cyber.risk_management_program_documented
	msg := "S-K 106(b): No documented cybersecurity risk management program for annual disclosure"
}

# S-K Item 106(c)(1): Board oversight of cybersecurity risk
deny_no_board_oversight contains msg if {
	not input.normalized_data.sec_cyber.board_oversight_documented
	msg := "S-K 106(c)(1): Board oversight of cybersecurity risk not documented"
}

# S-K Item 106(c)(2): Management role in cybersecurity
deny_no_management_role contains msg if {
	not input.normalized_data.sec_cyber.management_cybersecurity_role_defined
	msg := "S-K 106(c)(2): Management role in assessing and managing cybersecurity risk not defined"
}

# Third-party risk assessment for SEC disclosure
deny_no_third_party_assessment contains msg if {
	not input.normalized_data.sec_cyber.third_party_risk_assessment
	msg := "S-K 106(b): No third-party cybersecurity risk assessment — required for annual risk disclosure"
}

default compliant := false

compliant if {
	count(deny_no_incident_disclosure_process) == 0
	count(deny_no_risk_management_program) == 0
	count(deny_no_board_oversight) == 0
	count(deny_no_management_role) == 0
	count(deny_no_third_party_assessment) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_disclosure_process],
		[f | some f in deny_no_risk_management_program],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_board_oversight],
			[f | some f in deny_no_management_role],
		),
		[f | some f in deny_no_third_party_assessment],
	),
)

result := {
	"framework": "SEC Cyber",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
