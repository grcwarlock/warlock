package gdpr.art5

import rego.v1

# GDPR Article 5: Principles relating to processing of personal data
# Art 5(1)(a) — Lawfulness, fairness, transparency
# Art 5(1)(b) — Purpose limitation
# Art 5(1)(f) — Integrity and confidentiality

deny_no_lawful_basis contains msg if {
	not input.normalized_data.privacy.lawful_basis_documented
	msg := "Art5-1a: No documented lawful basis for processing personal data"
}

deny_no_purpose_limitation contains msg if {
	not input.normalized_data.privacy.purpose_documented
	msg := "Art5-1b: Purpose of data collection is not documented"
}

deny_no_encryption contains msg if {
	some resource in input.normalized_data.storage_resources
	not resource.encryption_enabled
	msg := sprintf("Art5-1f: Resource '%s' stores personal data without encryption at rest", [resource.name])
}

deny_no_dlp contains msg if {
	not input.normalized_data.dlp.policies_active
	msg := "Art5-1f: No active DLP policies to protect personal data integrity and confidentiality"
}

deny_policy_stale contains msg if {
	some doc in input.normalized_data.policy_documents
	doc.days_since_review > 365
	msg := sprintf("Art5-1a: Privacy policy '%s' not reviewed within 365 days (%d days ago)", [doc.name, doc.days_since_review])
}

default compliant := false

compliant if {
	count(deny_no_lawful_basis) == 0
	count(deny_no_purpose_limitation) == 0
	count(deny_no_encryption) == 0
	count(deny_no_dlp) == 0
	count(deny_policy_stale) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_lawful_basis],
		[f | some f in deny_no_purpose_limitation],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_encryption],
			[f | some f in deny_no_dlp],
		),
		[f | some f in deny_policy_stale],
	),
)

result := {
	"control_id": "Art5",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
