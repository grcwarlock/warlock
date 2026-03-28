package warlock.eu_ai_act

import rego.v1

# EU AI Act Risk Classification and Compliance
# Regulation on Artificial Intelligence risk-based requirements

# Art. 6: High-risk AI system classification and registration
deny_unclassified_ai_system contains msg if {
	some system in input.normalized_data.ai_systems
	not system.risk_classification
	msg := sprintf("Art.6: AI system '%s' not classified by risk level", [system.name])
}

# Art. 9: Risk management system for high-risk AI
deny_no_risk_management contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.risk_management_system
	msg := sprintf("Art.9: High-risk AI system '%s' lacks risk management system", [system.name])
}

# Art. 13: Transparency — users informed of AI interaction
deny_no_transparency contains msg if {
	some system in input.normalized_data.ai_systems
	system.interacts_with_humans
	not system.transparency_disclosure
	msg := sprintf("Art.13: AI system '%s' interacts with humans without transparency disclosure", [system.name])
}

# Art. 14: Human oversight — high-risk AI must allow human intervention
deny_no_human_oversight contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.human_oversight_mechanism
	msg := sprintf("Art.14: High-risk AI system '%s' lacks human oversight mechanism", [system.name])
}

# Art. 10: Data governance — training data quality requirements
deny_no_data_governance contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.data_governance_measures
	msg := sprintf("Art.10: High-risk AI system '%s' lacks data governance measures for training data", [system.name])
}

default compliant := false

compliant if {
	count(deny_unclassified_ai_system) == 0
	count(deny_no_risk_management) == 0
	count(deny_no_transparency) == 0
	count(deny_no_human_oversight) == 0
	count(deny_no_data_governance) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unclassified_ai_system],
		[f | some f in deny_no_risk_management],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_transparency],
			[f | some f in deny_no_human_oversight],
		),
		[f | some f in deny_no_data_governance],
	),
)

result := {
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
