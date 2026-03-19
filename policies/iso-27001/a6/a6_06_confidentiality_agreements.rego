package iso_27001.a6.a6_06

import rego.v1

# A.6.6: Confidentiality or Non-Disclosure Agreements
# Validates NDAs are signed and stored securely with review tracking

deny_no_nda_documents contains msg if {
	not input.normalized_data.policies.nda_documents_stored
	msg := "A.6.6: No signed NDA documents stored in document repository"
}

deny_nda_bucket_not_encrypted contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "hr-ndas"
	not bucket.encryption_enabled
	msg := sprintf("A.6.6: NDA storage bucket '%s' is not encrypted", [bucket.name])
}

deny_nda_bucket_public contains msg if {
	some bucket in input.normalized_data.s3.buckets
	bucket.purpose == "hr-ndas"
	not bucket.public_access_blocked
	msg := sprintf("A.6.6: NDA storage bucket '%s' does not block public access", [bucket.name])
}

deny_nda_review_overdue contains msg if {
	some nda in input.normalized_data.policies.ndas
	nda.review_overdue
	msg := sprintf("A.6.6: NDA for '%s' is overdue for review (due: %s)", [nda.party, nda.review_due_date])
}

default compliant := false

compliant if {
	count(deny_no_nda_documents) == 0
	count(deny_nda_bucket_not_encrypted) == 0
	count(deny_nda_bucket_public) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_nda_documents],
		[f | some f in deny_nda_bucket_not_encrypted],
	),
	array.concat(
		[f | some f in deny_nda_bucket_public],
		[f | some f in deny_nda_review_overdue],
	),
)

result := {
	"control_id": "A.6.6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
