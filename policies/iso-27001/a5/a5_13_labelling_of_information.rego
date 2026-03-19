package iso_27001.a5.a5_13

import rego.v1

# A.5.13: Labelling of Information
# Validates information labelling is consistently applied

deny_no_tag_policy contains msg if {
	not input.normalized_data.organization.tag_policies_enforced
	msg := "A.5.13: No organizational tag policies enforce information labelling"
}

deny_untagged_resources contains msg if {
	some resource in input.normalized_data.resources
	not resource.tags.DataClassification
	msg := sprintf("A.5.13: Resource '%s' (%s) lacks DataClassification label", [resource.id, resource.type])
}

deny_no_required_tags_config_rule contains msg if {
	not input.normalized_data.config.required_tags_rule_exists
	msg := "A.5.13: No Config rule enforces required classification tags on resources"
}

deny_invalid_classification_label contains msg if {
	valid_labels := {"Public", "Internal", "Confidential", "Restricted"}
	some resource in input.normalized_data.resources
	resource.tags.DataClassification
	not resource.tags.DataClassification in valid_labels
	msg := sprintf("A.5.13: Resource '%s' has invalid DataClassification label '%s'", [resource.id, resource.tags.DataClassification])
}

default compliant := false

compliant if {
	count(deny_no_tag_policy) == 0
	count(deny_untagged_resources) == 0
	count(deny_invalid_classification_label) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_tag_policy],
		[f | some f in deny_untagged_resources],
	),
	array.concat(
		[f | some f in deny_no_required_tags_config_rule],
		[f | some f in deny_invalid_classification_label],
	),
)

result := {
	"control_id": "A.5.13",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
