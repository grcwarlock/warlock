package iso_27001.a5.a5_33

import rego.v1

# A.5.33: Protection of Records
# Validates records are protected with versioning, encryption, and access controls

deny_records_no_versioning contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "records"
	not bucket.versioning_enabled
	msg := sprintf("A.5.33: Records bucket '%s' does not have versioning enabled", [bucket.name])
}

deny_records_no_encryption contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "records"
	not bucket.encryption_enabled
	msg := sprintf("A.5.33: Records bucket '%s' does not have encryption enabled", [bucket.name])
}

deny_records_no_object_lock contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "records"
	not bucket.object_lock_enabled
	msg := sprintf("A.5.33: Records bucket '%s' does not have Object Lock for immutability", [bucket.name])
}

deny_records_no_access_logging contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "records"
	not bucket.access_logging_enabled
	msg := sprintf("A.5.33: Records bucket '%s' does not have access logging enabled", [bucket.name])
}

default compliant := false

compliant if {
	count(deny_records_no_versioning) == 0
	count(deny_records_no_encryption) == 0
	count(deny_records_no_object_lock) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_records_no_versioning],
		[f | some f in deny_records_no_encryption],
	),
	array.concat(
		[f | some f in deny_records_no_object_lock],
		[f | some f in deny_records_no_access_logging],
	),
)

result := {
	"control_id": "A.5.33",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
