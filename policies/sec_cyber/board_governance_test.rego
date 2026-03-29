package warlock.sec_cyber.governance_test

import rego.v1

import data.warlock.sec_cyber.governance

test_compliant_governance if {
	result := governance.result with input as {"normalized_data": {
		"sec_cyber": {
			"board_cyber_committee": true,
			"board_briefing_cadence": true,
			"ciso_designated": true,
			"management_expertise_documented": true,
			"cyber_reporting_to_board": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_full_board_oversight_also_compliant if {
	result := governance.result with input as {"normalized_data": {
		"sec_cyber": {
			"board_full_oversight": true,
			"board_briefing_cadence": true,
			"ciso_designated": true,
			"management_expertise_documented": true,
			"cyber_reporting_to_board": true,
		},
	}}
	result.compliant == true
}

test_no_board_oversight if {
	result := governance.result with input as {"normalized_data": {
		"sec_cyber": {
			"board_cyber_committee": false,
			"board_full_oversight": false,
			"board_briefing_cadence": true,
			"ciso_designated": true,
			"management_expertise_documented": true,
			"cyber_reporting_to_board": true,
		},
	}}
	result.compliant == false
}

test_no_ciso if {
	result := governance.result with input as {"normalized_data": {
		"sec_cyber": {
			"board_cyber_committee": true,
			"board_briefing_cadence": true,
			"ciso_designated": false,
			"management_expertise_documented": true,
			"cyber_reporting_to_board": true,
		},
	}}
	result.compliant == false
}

test_no_reporting_line if {
	result := governance.result with input as {"normalized_data": {
		"sec_cyber": {
			"board_cyber_committee": true,
			"board_briefing_cadence": true,
			"ciso_designated": true,
			"management_expertise_documented": true,
			"cyber_reporting_to_board": false,
		},
	}}
	result.compliant == false
}
