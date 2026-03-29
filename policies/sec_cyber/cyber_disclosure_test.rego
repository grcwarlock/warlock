package warlock.sec_cyber_test

import rego.v1

import data.warlock.sec_cyber

test_compliant_disclosure if {
	result := sec_cyber.result with input as {"normalized_data": {
		"sec_cyber": {
			"incident_disclosure_process": true,
			"risk_management_program_documented": true,
			"board_oversight_documented": true,
			"management_cybersecurity_role_defined": true,
			"third_party_risk_assessment": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_incident_disclosure if {
	result := sec_cyber.result with input as {"normalized_data": {
		"sec_cyber": {
			"incident_disclosure_process": false,
			"risk_management_program_documented": true,
			"board_oversight_documented": true,
			"management_cybersecurity_role_defined": true,
			"third_party_risk_assessment": true,
		},
	}}
	result.compliant == false
}

test_no_board_oversight if {
	result := sec_cyber.result with input as {"normalized_data": {
		"sec_cyber": {
			"incident_disclosure_process": true,
			"risk_management_program_documented": true,
			"board_oversight_documented": false,
			"management_cybersecurity_role_defined": true,
			"third_party_risk_assessment": true,
		},
	}}
	result.compliant == false
}

test_no_risk_management_program if {
	result := sec_cyber.result with input as {"normalized_data": {
		"sec_cyber": {
			"incident_disclosure_process": true,
			"risk_management_program_documented": false,
			"board_oversight_documented": true,
			"management_cybersecurity_role_defined": true,
			"third_party_risk_assessment": true,
		},
	}}
	result.compliant == false
}
