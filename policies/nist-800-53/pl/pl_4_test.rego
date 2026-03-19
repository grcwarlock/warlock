package nist.pl.pl_4_test

import rego.v1

import data.nist.pl.pl_4

test_compliant if {
	result := pl_4.result with input as {"normalized_data": {"planning": {"rules_of_behavior_defined": true, "rules_of_behavior_reviewed_within_365_days": true, "rules_of_behavior_defines_consequences": true, "rules_of_behavior_covers_social_media": true, "users": [{"user_id": "alice", "rules_of_behavior_signed": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_4.result with input as {"normalized_data": {"planning": {"users": [{"user_id": "bob", "rules_of_behavior_signed": false}]}}}
	result.compliant == false
}
