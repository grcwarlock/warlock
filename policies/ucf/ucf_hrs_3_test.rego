package ucf.hrs.ucf_hrs_3_test

import rego.v1

import data.ucf.hrs.ucf_hrs_3

test_good_training_and_phishing if {
	result := ucf_hrs_3.result with input as {"normalized_data": {
		"training": {"completion_rate": 0.95, "total_enrollments": 100, "completed": 95},
		"phishing": {"click_rate": 0.02, "total_tests": 50, "clicked": 1},
	}}
	result.compliant == true
}

test_low_completion if {
	result := ucf_hrs_3.result with input as {"normalized_data": {
		"training": {"completion_rate": 0.70, "total_enrollments": 100, "completed": 70},
		"phishing": {"click_rate": 0.02, "total_tests": 50, "clicked": 1},
	}}
	result.compliant == false
}

test_high_phish_rate if {
	result := ucf_hrs_3.result with input as {"normalized_data": {
		"training": {"completion_rate": 0.95, "total_enrollments": 100, "completed": 95},
		"phishing": {"click_rate": 0.15, "total_tests": 50, "clicked": 8},
	}}
	result.compliant == false
}
