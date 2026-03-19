package nist.pm.pm_5_test

import rego.v1

import data.nist.pm.pm_5

test_compliant_inventory if {
	result := pm_5.result with input as {"normalized_data": {"system_inventory": {
		"last_update_days": 30,
		"systems": [{"name": "sys1", "authorization_status": "authorized", "system_owner": "owner1", "boundary_defined": true}],
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_inventory if {
	result := pm_5.result with input as {"normalized_data": {}}
	result.compliant == false
}
