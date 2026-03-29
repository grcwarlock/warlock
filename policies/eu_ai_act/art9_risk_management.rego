package warlock.eu_ai_act.art9

import rego.v1

# Art. 9: Risk Management System for High-Risk AI
# Continuous, iterative risk identification, analysis, and mitigation

# 9.1: Risk management system established and maintained
deny_no_risk_management_system contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.risk_management_system
	msg := sprintf("Art.9.1: High-risk AI system '%s' has no risk management system", [system.name])
}

# 9.2(a): Identification and analysis of known and foreseeable risks
deny_no_risk_identification contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.risks_identified
	msg := sprintf("Art.9.2a: High-risk AI system '%s' — risks not identified and analyzed", [system.name])
}

# 9.2(b): Estimation and evaluation of risks during intended use and misuse
deny_no_misuse_evaluation contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.misuse_risks_evaluated
	msg := sprintf("Art.9.2b: High-risk AI system '%s' — misuse risks not evaluated", [system.name])
}

# 9.4: Risk mitigation and residual risk assessment
deny_no_residual_risk_assessment contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.risk_management_system
	not system.residual_risk_assessed
	msg := sprintf("Art.9.4: High-risk AI system '%s' — residual risks not assessed after mitigation", [system.name])
}

# 9.5: Testing to identify most appropriate risk management measures
deny_no_risk_testing contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.risk_testing_performed
	msg := sprintf("Art.9.5: High-risk AI system '%s' — risk management measures not tested", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_risk_management_system) == 0
	count(deny_no_risk_identification) == 0
	count(deny_no_misuse_evaluation) == 0
	count(deny_no_residual_risk_assessment) == 0
	count(deny_no_risk_testing) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_management_system],
		[f | some f in deny_no_risk_identification],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_misuse_evaluation],
			[f | some f in deny_no_residual_risk_assessment],
		),
		[f | some f in deny_no_risk_testing],
	),
)

result := {
	"control_id": "Art.9",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
