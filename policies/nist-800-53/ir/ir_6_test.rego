package nist.ir.ir_6_test

import rego.v1

import data.nist.ir.ir_6

test_compliant_incident_reporting if {
	result := ir_6.result with input as {"normalized_data": {
		"incident_reporting": {
			"reporting_mechanism_exists": true,
			"timeframe_defined": true,
			"external_reporting_configured": true,
			"escalation_procedures_defined": true,
			"automated_reporting_enabled": true,
			"contact_list_last_updated_days": 30,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_reporting if {
	result := ir_6.result with input as {"normalized_data": {}}
	result.compliant == false
}
