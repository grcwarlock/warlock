package warlock.eu_ai_act.art17

import rego.v1

# Art. 17: Quality Management System
# Providers of high-risk AI systems shall put a quality management system in place

# 17.1: Quality management system documented
deny_no_qms contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.quality_management_system
	msg := sprintf("Art.17.1: High-risk AI system '%s' — no quality management system", [system.name])
}

# 17.1(a): Strategy for regulatory compliance
deny_no_compliance_strategy contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.compliance_strategy_documented
	msg := sprintf("Art.17.1a: AI system '%s' — no regulatory compliance strategy", [system.name])
}

# 17.1(e): Systems and procedures for data management
deny_no_data_management contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	system.uses_training_data
	not system.data_management_procedures
	msg := sprintf("Art.17.1e: AI system '%s' — no data management procedures", [system.name])
}

# 17.1(h): Post-market monitoring system
deny_no_post_market_monitoring contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.post_market_monitoring
	msg := sprintf("Art.17.1h: AI system '%s' — no post-market monitoring system", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_qms) == 0
	count(deny_no_compliance_strategy) == 0
	count(deny_no_data_management) == 0
	count(deny_no_post_market_monitoring) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_qms],
		[f | some f in deny_no_compliance_strategy],
	),
	array.concat(
		[f | some f in deny_no_data_management],
		[f | some f in deny_no_post_market_monitoring],
	),
)

result := {
	"control_id": "Art.17",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
