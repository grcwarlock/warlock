package warlock.sec_cyber.governance

import rego.v1

# SEC Cyber — Board Governance and Management Role
# S-K Item 106(c): Governance disclosure requirements

# 106(c)(1): Board oversight — committee or full board reviews cyber risk
deny_no_board_committee contains msg if {
	not input.normalized_data.sec_cyber.board_cyber_committee
	not input.normalized_data.sec_cyber.board_full_oversight
	msg := "S-K 106(c)(1): No board committee or full board oversight of cybersecurity risk"
}

# 106(c)(1): Board informed of incidents — regular briefing cadence
deny_no_board_briefing contains msg if {
	not input.normalized_data.sec_cyber.board_briefing_cadence
	msg := "S-K 106(c)(1): No regular board briefing cadence for cybersecurity risk"
}

# 106(c)(2): Management role — CISO or equivalent designated
deny_no_ciso contains msg if {
	not input.normalized_data.sec_cyber.ciso_designated
	msg := "S-K 106(c)(2): No CISO or equivalent designated for cybersecurity management"
}

# 106(c)(2): Management expertise — relevant qualifications documented
deny_no_expertise_documentation contains msg if {
	not input.normalized_data.sec_cyber.management_expertise_documented
	msg := "S-K 106(c)(2): Cybersecurity management expertise not documented for disclosure"
}

# 106(c)(2): Reporting line — management reports to board on cyber matters
deny_no_reporting_line contains msg if {
	not input.normalized_data.sec_cyber.cyber_reporting_to_board
	msg := "S-K 106(c)(2): No reporting line from cybersecurity management to board"
}

default compliant := false

compliant if {
	count(deny_no_board_committee) == 0
	count(deny_no_board_briefing) == 0
	count(deny_no_ciso) == 0
	count(deny_no_expertise_documentation) == 0
	count(deny_no_reporting_line) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_board_committee],
		[f | some f in deny_no_board_briefing],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_ciso],
			[f | some f in deny_no_expertise_documentation],
		),
		[f | some f in deny_no_reporting_line],
	),
)

result := {
	"control_id": "S-K 106(c)",
	"framework": "SEC Cyber",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
