package nist.pl.pl_1_test

import rego.v1

import data.nist.pl.pl_1

test_compliant if {
	result := pl_1.result with input as {"normalized_data": {"planning": {"policy_defined": true, "policy_reviewed_within_365_days": true, "procedures_documented": true, "designated_official": "Jane Doe"}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_1.result with input as {"normalized_data": {"planning": {"policy_defined": false, "procedures_documented": false, "designated_official": false}}}
	result.compliant == false
}
