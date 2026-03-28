package warlock.iso_42001

import rego.v1

# ISO 42001 AI Management System
# Controls for AI governance, risk management, and responsible AI

# 5.2: AI policy — documented AI management policy
deny_no_ai_policy contains msg if {
	not input.normalized_data.ai_governance.ai_policy_documented
	msg := "5.2: No documented AI management policy"
}

# 6.1.2: AI risk assessment — risks from AI systems identified and assessed
deny_no_ai_risk_assessment contains msg if {
	not input.normalized_data.ai_governance.risk_assessment_conducted
	msg := "6.1.2: No AI risk assessment conducted — AI system risks not identified"
}

# 8.4: AI system impact assessment — societal and individual impacts evaluated
deny_no_impact_assessment contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	not system.impact_assessment_completed
	msg := sprintf("8.4: AI system '%s' lacks impact assessment", [system.name])
}

# 9.3: AI data quality — training data quality and bias controls
deny_no_data_quality_controls contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.uses_training_data
	not system.data_quality_controls
	msg := sprintf("9.3: AI system '%s' lacks data quality controls for training data", [system.name])
}

# 6.2.2: AI transparency — explainability for high-risk AI decisions
deny_no_explainability contains msg if {
	some system in input.normalized_data.ai_governance.ai_systems
	system.risk_level == "high"
	not system.explainability_mechanism
	msg := sprintf("6.2.2: High-risk AI system '%s' lacks explainability mechanism", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_ai_policy) == 0
	count(deny_no_ai_risk_assessment) == 0
	count(deny_no_impact_assessment) == 0
	count(deny_no_data_quality_controls) == 0
	count(deny_no_explainability) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ai_policy],
		[f | some f in deny_no_ai_risk_assessment],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_impact_assessment],
			[f | some f in deny_no_data_quality_controls],
		),
		[f | some f in deny_no_explainability],
	),
)

result := {
	"framework": "ISO 42001",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
