package ucf.dat.ucf_dat_1

import rego.v1

# UCF-DAT-1: Encryption at Rest
# Validates that storage resources have encryption enabled

deny_unencrypted_bucket contains msg if {
	some bucket in input.normalized_data.storage_buckets
	not bucket.encryption
	msg := sprintf("UCF-DAT-1: Storage bucket '%s' has no encryption at rest", [bucket.name])
}

deny_unencrypted_bucket contains msg if {
	some bucket in input.normalized_data.storage_buckets
	bucket.encryption
	count(bucket.encryption) == 0
	msg := sprintf("UCF-DAT-1: Storage bucket '%s' has empty encryption configuration", [bucket.name])
}

default compliant := false

compliant if {
	count(deny_unencrypted_bucket) == 0
	count(input.normalized_data.storage_buckets) > 0
}

findings := [f | some f in deny_unencrypted_bucket]

result := {
	"control_id": "UCF-DAT-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
