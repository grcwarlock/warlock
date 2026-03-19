package iso_27001.a8.a8_33

import rego.v1

# A.8.33: Test Information
# Validates test data is sanitized and protected

deny_no_test_data_scanning contains msg if {
	input.normalized_data.macie.enabled
	not input.normalized_data.macie.test_data_scanned
	msg := "A.8.33: Macie has not scanned test environment data for sensitive information"
}

deny_test_resources_not_tagged contains msg if {
	some resource in input.normalized_data.resources
	resource.tags.Environment == "Test"
	not resource.tags.DataClassification
	msg := sprintf("A.8.33: Test resource '%s' missing DataClassification tag — data sanitization status unknown", [resource.id])
}

deny_test_rds_not_tagged contains msg if {
	some db in input.normalized_data.rds.instances
	db.tags.Environment == "Test"
	not db.tags.DataSanitized
	msg := sprintf("A.8.33: Test RDS instance '%s' not tagged as DataSanitized", [db.identifier])
}

deny_no_test_environment_tags_rule contains msg if {
	not input.normalized_data.config.test_environment_tags_rule_exists
	msg := "A.8.33: No Config rule enforces proper tagging of test environment resources"
}

default compliant := false

compliant if {
	count(deny_test_resources_not_tagged) == 0
	count(deny_test_rds_not_tagged) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_test_data_scanning],
		[f | some f in deny_test_resources_not_tagged],
	),
	array.concat(
		[f | some f in deny_test_rds_not_tagged],
		[f | some f in deny_no_test_environment_tags_rule],
	),
)

result := {
	"control_id": "A.8.33",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
