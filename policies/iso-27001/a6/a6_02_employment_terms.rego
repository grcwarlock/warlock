package iso_27001.a6.a6_02

import rego.v1

# A.6.2: Terms and Conditions of Employment
# Validates employment agreements include security responsibilities

deny_no_agreements_stored contains msg if {
	not input.normalized_data.policies.employment_agreements_stored
	msg := "A.6.2: No signed employment agreements stored in document repository"
}

deny_agreements_bucket_no_versioning contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "hr-agreements"
	not bucket.versioning_enabled
	msg := sprintf("A.6.2: HR agreements bucket '%s' does not have versioning enabled", [bucket.name])
}

deny_agreements_bucket_not_encrypted contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "hr-agreements"
	not bucket.encryption_enabled
	msg := sprintf("A.6.2: HR agreements bucket '%s' is not encrypted", [bucket.name])
}

deny_users_no_acknowledgment contains msg if {
	some user in input.normalized_data.users
	not user.tags.SecurityAcknowledged
	user.username != "root"
	msg := sprintf("A.6.2: User '%s' has not acknowledged security responsibilities", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_agreements_stored) == 0
	count(deny_agreements_bucket_not_encrypted) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_agreements_stored],
		[f | some f in deny_agreements_bucket_no_versioning],
	),
	array.concat(
		[f | some f in deny_agreements_bucket_not_encrypted],
		[f | some f in deny_users_no_acknowledgment],
	),
)

result := {
	"control_id": "A.6.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
