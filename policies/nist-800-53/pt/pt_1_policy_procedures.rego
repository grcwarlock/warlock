package nist.pt.pt_1

import rego.v1

# PT-1: Policy and Procedures

deny_no_pii_policy contains msg if {
	not input.normalized_data.pii_processing_policy
	msg := "PT-1: No PII processing and transparency policy established"
}

deny_policy_not_approved contains msg if {
	policy := input.normalized_data.pii_processing_policy
	not policy.approved
	msg := "PT-1: PII processing and transparency policy has not been approved"
}

deny_policy_outdated contains msg if {
	policy := input.normalized_data.pii_processing_policy
	policy.last_review_days > 365
	msg := sprintf("PT-1: PII processing policy has not been reviewed in %d days", [policy.last_review_days])
}

deny_no_procedures contains msg if {
	policy := input.normalized_data.pii_processing_policy
	not policy.procedures_documented
	msg := "PT-1: PII processing procedures have not been documented"
}

deny_procedures_outdated contains msg if {
	policy := input.normalized_data.pii_processing_policy
	policy.procedures_last_review_days > 365
	msg := sprintf("PT-1: PII processing procedures have not been reviewed in %d days", [policy.procedures_last_review_days])
}

deny_policy_not_disseminated contains msg if {
	policy := input.normalized_data.pii_processing_policy
	not policy.disseminated_to_personnel
	msg := "PT-1: PII processing policy has not been disseminated to relevant personnel"
}

default compliant := false

compliant if {
	count(deny_no_pii_policy) == 0
	count(deny_policy_not_approved) == 0
	count(deny_policy_outdated) == 0
	count(deny_no_procedures) == 0
	count(deny_procedures_outdated) == 0
	count(deny_policy_not_disseminated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_pii_policy],
		[f | some f in deny_policy_not_approved],
	),
	array.concat(
		array.concat(
			[f | some f in deny_policy_outdated],
			[f | some f in deny_no_procedures],
		),
		array.concat(
			[f | some f in deny_procedures_outdated],
			[f | some f in deny_policy_not_disseminated],
		),
	),
)

result := {
	"control_id": "PT-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
