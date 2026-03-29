package warlock.eu_ai_act.art13

import rego.v1

# Art. 13: Transparency and Provision of Information to Deployers
# High-risk AI systems designed for transparency to deployers

# 13.1: Designed to allow deployers to interpret output
deny_no_interpretability contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.output_interpretable
	msg := sprintf("Art.13.1: High-risk AI system '%s' — output not interpretable by deployers", [system.name])
}

# 13.2: Instructions for use provided
deny_no_usage_instructions contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.usage_instructions_provided
	msg := sprintf("Art.13.2: High-risk AI system '%s' — no instructions for use provided", [system.name])
}

# 13.3(b)(i): Intended purpose clearly described
deny_no_purpose_description contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.intended_purpose_documented
	msg := sprintf("Art.13.3bi: AI system '%s' — intended purpose not described to deployers", [system.name])
}

# 13.3(b)(ii): Level of accuracy, robustness, and cybersecurity disclosed
deny_no_accuracy_disclosure contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.accuracy_metrics_disclosed
	msg := sprintf("Art.13.3bii: AI system '%s' — accuracy/robustness metrics not disclosed", [system.name])
}

# 13.3(d): Expected lifetime and maintenance requirements
deny_no_lifecycle_info contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.lifecycle_documented
	msg := sprintf("Art.13.3d: AI system '%s' — expected lifetime and maintenance not documented", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_interpretability) == 0
	count(deny_no_usage_instructions) == 0
	count(deny_no_purpose_description) == 0
	count(deny_no_accuracy_disclosure) == 0
	count(deny_no_lifecycle_info) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_interpretability],
		[f | some f in deny_no_usage_instructions],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_purpose_description],
			[f | some f in deny_no_accuracy_disclosure],
		),
		[f | some f in deny_no_lifecycle_info],
	),
)

result := {
	"control_id": "Art.13",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
