package nist.pt.pt_7

import rego.v1

# PT-7: Specific Categories of Personally Identifiable Information

deny_no_pii_categorization contains msg if {
	not input.normalized_data.pii_categories
	msg := "PT-7: No specific categories of PII identified and documented"
}

deny_sensitive_pii_no_protections contains msg if {
	some category in input.normalized_data.pii_categories.categories
	category.sensitivity == "high"
	not category.additional_protections_applied
	msg := sprintf("PT-7: Sensitive PII category '%s' does not have additional protections applied", [category.name])
}

deny_no_data_classification contains msg if {
	pc := input.normalized_data.pii_categories
	not pc.data_classification_applied
	msg := "PT-7: Data classification not applied to PII categories"
}

deny_categories_not_reviewed contains msg if {
	pc := input.normalized_data.pii_categories
	pc.last_review_days > 365
	msg := sprintf("PT-7: PII categories have not been reviewed in %d days", [pc.last_review_days])
}

deny_social_security_not_minimized contains msg if {
	some category in input.normalized_data.pii_categories.categories
	category.type == "social_security_number"
	not category.use_minimized
	msg := "PT-7: Social Security Number usage has not been minimized"
}

default compliant := false

compliant if {
	count(deny_no_pii_categorization) == 0
	count(deny_sensitive_pii_no_protections) == 0
	count(deny_no_data_classification) == 0
	count(deny_categories_not_reviewed) == 0
	count(deny_social_security_not_minimized) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_pii_categorization],
		[f | some f in deny_sensitive_pii_no_protections],
	),
	array.concat(
		[f | some f in deny_no_data_classification],
		array.concat(
			[f | some f in deny_categories_not_reviewed],
			[f | some f in deny_social_security_not_minimized],
		),
	),
)

result := {
	"control_id": "PT-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
