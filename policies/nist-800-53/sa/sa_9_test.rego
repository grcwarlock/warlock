package nist.sa.sa_9_test

import rego.v1

import data.nist.sa.sa_9

test_compliant_external_services if {
	result := sa_9.result with input as {"normalized_data": {
		"external_services_policy": true,
		"external_services": [{
			"name": "svc1",
			"service_level_agreement": true,
			"security_controls_documented": true,
			"compliance_monitored": true,
			"requires_interconnection": true,
			"interconnection_agreement": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_policy if {
	result := sa_9.result with input as {"normalized_data": {}}
	result.compliant == false
}
