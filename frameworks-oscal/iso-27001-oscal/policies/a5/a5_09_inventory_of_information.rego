package iso_27001.a5.a5_09

import rego.v1

# A.5.9: Inventory of Information and Other Associated Assets
# Validates a complete asset inventory is maintained with ownership

deny_no_config_recorder contains msg if {
	not input.normalized_data.config.recorder_enabled
	msg := "A.5.9: AWS Config recorder is not enabled — asset inventory cannot be maintained"
}

deny_resources_missing_owner_tag contains msg if {
	some resource in input.normalized_data.resources
	not resource.tags.Owner
	msg := sprintf("A.5.9: Resource '%s' (%s) is missing an Owner tag", [resource.id, resource.type])
}

deny_no_required_tags_rule contains msg if {
	not input.normalized_data.config.required_tags_rule_exists
	msg := "A.5.9: No AWS Config rule enforces required tags (Owner, Classification) on resources"
}

deny_resources_missing_classification contains msg if {
	some resource in input.normalized_data.resources
	not resource.tags.Classification
	not resource.tags.DataClassification
	msg := sprintf("A.5.9: Resource '%s' (%s) is missing a Classification tag", [resource.id, resource.type])
}

default compliant := false

compliant if {
	count(deny_no_config_recorder) == 0
	count(deny_resources_missing_owner_tag) == 0
	count(deny_no_required_tags_rule) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_config_recorder],
		[f | some f in deny_resources_missing_owner_tag],
	),
	array.concat(
		[f | some f in deny_no_required_tags_rule],
		[f | some f in deny_resources_missing_classification],
	),
)

result := {
	"control_id": "A.5.9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
