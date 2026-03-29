package warlock.eu_ai_act.art15

import rego.v1

# Art. 15: Accuracy, Robustness, and Cybersecurity
# High-risk AI systems designed for appropriate levels of accuracy, robustness, cybersecurity

# 15.1: Accuracy levels declared and documented
deny_no_accuracy_declaration contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.accuracy_metrics_documented
	msg := sprintf("Art.15.1: High-risk AI system '%s' — accuracy levels not declared", [system.name])
}

# 15.3: Resilient to errors, faults, or inconsistencies
deny_no_robustness contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.robustness_tested
	msg := sprintf("Art.15.3: AI system '%s' — robustness against errors not tested", [system.name])
}

# 15.4: Resilient to adversarial manipulation (cybersecurity)
deny_no_adversarial_protection contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.adversarial_testing_performed
	msg := sprintf("Art.15.4: AI system '%s' — no adversarial testing performed", [system.name])
}

# 15.4: Technical redundancy solutions including backup/failsafe plans
deny_no_failsafe contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.failsafe_mechanism
	msg := sprintf("Art.15.4: AI system '%s' — no failsafe or fallback mechanism", [system.name])
}

# 15.5: Cybersecurity measures for AI-specific vulnerabilities
deny_no_ai_security contains msg if {
	some system in input.normalized_data.ai_systems
	system.risk_classification == "high"
	not system.ai_specific_security_measures
	msg := sprintf("Art.15.5: AI system '%s' — no AI-specific cybersecurity measures", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_accuracy_declaration) == 0
	count(deny_no_robustness) == 0
	count(deny_no_adversarial_protection) == 0
	count(deny_no_failsafe) == 0
	count(deny_no_ai_security) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_accuracy_declaration],
		[f | some f in deny_no_robustness],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_adversarial_protection],
			[f | some f in deny_no_failsafe],
		),
		[f | some f in deny_no_ai_security],
	),
)

result := {
	"control_id": "Art.15",
	"framework": "EU AI Act",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
