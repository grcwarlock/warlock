package ucf.cfg.ucf_cfg_2_test

import rego.v1

import data.ucf.cfg.ucf_cfg_2

test_high_approval_rate if {
	result := ucf_cfg_2.result with input as {"normalized_data": {
		"change_management": {"total_changes": 100, "approved": 98, "approval_rate": 0.98},
	}}
	result.compliant == true
}

test_low_approval_rate if {
	result := ucf_cfg_2.result with input as {"normalized_data": {
		"change_management": {"total_changes": 100, "approved": 80, "approval_rate": 0.80},
	}}
	result.compliant == false
}

test_no_changes if {
	result := ucf_cfg_2.result with input as {"normalized_data": {
		"change_management": {"total_changes": 0, "approved": 0, "approval_rate": 0},
	}}
	result.compliant == false
}
