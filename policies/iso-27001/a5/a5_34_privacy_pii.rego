package iso_27001.a5.a5_34

import rego.v1

# A.5.34: Privacy and Protection of Personal Identifiable Information (PII)
# Validates PII is discovered, classified, and protected

deny_no_macie contains msg if {
	not input.normalized_data.macie.enabled
	msg := "A.5.34: Macie is not enabled for PII discovery"
}

deny_no_pii_discovery_jobs contains msg if {
	input.normalized_data.macie.enabled
	not input.normalized_data.macie.pii_discovery_jobs_running
	msg := "A.5.34: No Macie PII discovery jobs are configured"
}

deny_pii_bucket_public contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.contains_pii
	not bucket.public_access_blocked
	msg := sprintf("A.5.34: Bucket '%s' contains PII but does not block public access", [bucket.name])
}

deny_pii_bucket_not_encrypted contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.contains_pii
	not bucket.encryption_enabled
	msg := sprintf("A.5.34: Bucket '%s' contains PII but is not encrypted", [bucket.name])
}

deny_no_privacy_policy contains msg if {
	not input.normalized_data.policies.privacy_policy_documented
	msg := "A.5.34: No privacy policy documented for PII handling"
}

default compliant := false

compliant if {
	count(deny_no_macie) == 0
	count(deny_no_pii_discovery_jobs) == 0
	count(deny_pii_bucket_public) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_macie],
		[f | some f in deny_no_pii_discovery_jobs],
	),
	array.concat(
		[f | some f in deny_pii_bucket_public],
		array.concat(
			[f | some f in deny_pii_bucket_not_encrypted],
			[f | some f in deny_no_privacy_policy],
		),
	),
)

result := {
	"control_id": "A.5.34",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
