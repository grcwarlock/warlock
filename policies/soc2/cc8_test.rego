package soc2.cc8_test

import rego.v1

import data.soc2.cc8

test_compliant_change_management if {
	result := cc8.result with input as {
		"provider": "aws",
		"normalized_data": {
			"governance": {"change_management_policy_exists": true},
			"change_management": {
				"approval_workflow_enabled": true,
				"recent_changes": [{"id": "CH1", "approved": true, "date": "2025-01-01"}],
				"testing_required_before_deploy": true,
				"rollback_procedures_defined": true,
				"cicd_pipeline_exists": true,
				"cicd_security_gates_enabled": true,
				"change_log_maintained": true,
				"emergency_change_process_defined": true,
			},
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_policy if {
	result := cc8.result with input as {
		"provider": "aws",
		"normalized_data": {
			"governance": {},
			"change_management": {"recent_changes": []},
		},
	}
	result.compliant == false
}
