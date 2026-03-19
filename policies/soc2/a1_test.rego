package soc2.a1_test

import rego.v1

import data.soc2.a1

test_compliant_availability if {
	result := a1.result with input as {
		"provider": "aws",
		"normalized_data": {"availability": {
			"sla_defined": true,
			"disaster_recovery_plan_exists": true,
			"dr_plan_last_tested_days": 100,
			"backup_enabled": true,
			"rto_defined": true,
			"rpo_defined": true,
			"multi_region_deployed": true,
			"capacity_planning_enabled": true,
			"incident_response_plan_exists": true,
		}},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_sla if {
	result := a1.result with input as {
		"provider": "aws",
		"normalized_data": {"availability": {
			"multi_region_deployed": true,
		}},
	}
	result.compliant == false
}
