package nist.sr.sr_9_test

import rego.v1

import data.nist.sr.sr_9

test_compliant_tamper if {
	result := sr_9.result with input as {"normalized_data": {"tamper_protection": {
		"tamper_evident_packaging": true,
		"tamper_detection_mechanisms": true,
		"inspection_procedures_defined": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_tamper if {
	result := sr_9.result with input as {"normalized_data": {}}
	result.compliant == false
}
