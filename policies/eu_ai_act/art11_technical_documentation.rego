package warlock.eu_ai_act.art11

import rego.v1

# Art. 11: Technical Documentation
# High-risk AI systems must have complete technical documentation

# 11.1: Technical documentation drawn up before placing on market
deny_no_technical_docs contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.technical_documentation
	msg := sprintf("Art.11.1: High-risk AI system '%s' lacks technical documentation", [system.name])
}

# Documentation must include general description (Annex IV.1)
deny_no_general_description contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.technical_documentation
	not system.general_description_documented
	msg := sprintf("Art.11/AnnexIV.1: AI system '%s' — general description not documented", [system.name])
}

# Documentation must include intended purpose (Annex IV.1(b))
deny_no_intended_purpose contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.intended_purpose_documented
	msg := sprintf("Art.11/AnnexIV.1b: AI system '%s' — intended purpose not documented", [system.name])
}

# Documentation must include performance metrics (Annex IV.2(e))
deny_no_performance_metrics contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.performance_metrics_documented
	msg := sprintf("Art.11/AnnexIV.2e: AI system '%s' — performance metrics not documented", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_technical_docs) == 0
	count(deny_no_general_description) == 0
	count(deny_no_intended_purpose) == 0
	count(deny_no_performance_metrics) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_technical_docs],
		[f | some f in deny_no_general_description],
	),
	array.concat(
		[f | some f in deny_no_intended_purpose],
		[f | some f in deny_no_performance_metrics],
	),
)

result := {
	"control_id": "Art.11",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
