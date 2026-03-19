package iso_27001.a8.a8_10

import rego.v1

# A.8.10: Information Deletion
# Validates data retention and deletion policies are configured

deny_no_s3_lifecycle contains msg if {
	some bucket in input.normalized_data.s3.buckets
	not bucket.lifecycle_policy_configured
	msg := sprintf("A.8.10: S3 bucket '%s' has no lifecycle policy for data retention/deletion", [bucket.name])
}

deny_no_log_retention contains msg if {
	some log_group in input.normalized_data.cloudwatch.log_groups
	not log_group.retention_in_days
	msg := sprintf("A.8.10: Log group '%s' has no retention policy — logs retained indefinitely", [log_group.name])
}

deny_no_dynamodb_ttl contains msg if {
	some table in input.normalized_data.dynamodb.tables
	not table.ttl_enabled
	msg := sprintf("A.8.10: DynamoDB table '%s' has no TTL configured for automatic data deletion", [table.name])
}

deny_log_groups_no_retention contains msg if {
	no_retention := [g | some g in input.normalized_data.cloudwatch.log_groups; not g.retention_in_days]
	count(no_retention) > 0
	msg := sprintf("A.8.10: %d CloudWatch log groups have no retention policy", [count(no_retention)])
}

default compliant := false

compliant if {
	count(deny_no_s3_lifecycle) == 0
	count(deny_no_log_retention) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_s3_lifecycle],
		[f | some f in deny_no_log_retention],
	),
	array.concat(
		[f | some f in deny_no_dynamodb_ttl],
		[f | some f in deny_log_groups_no_retention],
	),
)

result := {
	"control_id": "A.8.10",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
