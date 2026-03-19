package nist.ma.ma_3_test

import rego.v1

import data.nist.ma.ma_3

test_compliant_maintenance_tools if {
	result := ma_3.result with input as {"normalized_data": {
		"maintenance": {
			"approved_tools_list_defined": true,
			"tools_in_use": [
				{"tool_name": "Ansible", "version": "2.14", "approved": true, "inspected_before_use": true, "integrity_verified": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unapproved_tool if {
	result := ma_3.result with input as {"normalized_data": {
		"maintenance": {
			"approved_tools_list_defined": true,
			"tools_in_use": [
				{"tool_name": "UnknownTool", "version": "1.0", "approved": false, "inspected_before_use": false, "integrity_verified": false},
			],
		},
	}}
	result.compliant == false
}
