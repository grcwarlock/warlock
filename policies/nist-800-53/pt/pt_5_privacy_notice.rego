package nist.pt.pt_5

import rego.v1

# PT-5: Privacy Notice

deny_no_privacy_notice contains msg if {
	not input.normalized_data.privacy_notice
	msg := "PT-5: No privacy notice provided to individuals"
}

deny_notice_not_current contains msg if {
	notice := input.normalized_data.privacy_notice
	notice.last_update_days > 365
	msg := sprintf("PT-5: Privacy notice has not been updated in %d days", [notice.last_update_days])
}

deny_notice_missing_purpose contains msg if {
	notice := input.normalized_data.privacy_notice
	not notice.includes_purpose_of_processing
	msg := "PT-5: Privacy notice does not include the purpose of PII processing"
}

deny_notice_missing_categories contains msg if {
	notice := input.normalized_data.privacy_notice
	not notice.includes_pii_categories
	msg := "PT-5: Privacy notice does not describe categories of PII being processed"
}

deny_notice_missing_rights contains msg if {
	notice := input.normalized_data.privacy_notice
	not notice.includes_individual_rights
	msg := "PT-5: Privacy notice does not describe individual rights regarding their PII"
}

deny_notice_not_accessible contains msg if {
	notice := input.normalized_data.privacy_notice
	not notice.publicly_accessible
	msg := "PT-5: Privacy notice is not publicly accessible"
}

default compliant := false

compliant if {
	count(deny_no_privacy_notice) == 0
	count(deny_notice_not_current) == 0
	count(deny_notice_missing_purpose) == 0
	count(deny_notice_missing_categories) == 0
	count(deny_notice_missing_rights) == 0
	count(deny_notice_not_accessible) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_privacy_notice],
		[f | some f in deny_notice_not_current],
	),
	array.concat(
		array.concat(
			[f | some f in deny_notice_missing_purpose],
			[f | some f in deny_notice_missing_categories],
		),
		array.concat(
			[f | some f in deny_notice_missing_rights],
			[f | some f in deny_notice_not_accessible],
		),
	),
)

result := {
	"control_id": "PT-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
